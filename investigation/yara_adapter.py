"""
YARA adapter — indicator-of-compromise pattern matching.

Extracted from :mod:`investigation.external_tools` (Step 5.4) so the
generic framework and the YARA-specific adapter each have their own
module, mirroring the existing ``SemgrepAdapter`` / ``TrivyAdapter``
layout.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..core.network_security import (
    check_domain_allowlist,
    enforce_https,
    reject_ssrf_target,
)
from .external_tools import (
    DEFAULT_TOOL_TIMEOUT,
    ExternalToolAdapter,
    ExternalToolResult,
    _resolve_venv_tool,
)

logger = logging.getLogger(__name__)


class YaraAdapter(ExternalToolAdapter):
    """IoC pattern matching via the *yara* binary.

    Enhanced to automatically discover and load community YARA rules:
        - PHP-Malware-Finder (php.yar) — LGPL-3.0 webshell/backdoor rules
        - Neo23x0/signature-base    — YARA webshell/exploit signatures
        - User-supplied custom rules

    Community rules are fetched on first use and cached in the REDACTS
    data directory.  Use ``CommunityRulesManager`` to pre-fetch or update.

    Matches are normalised to ``UnifiedFinding`` for cross-tool
    correlation with Semgrep and Trivy.
    """

    name = "yara"
    description = "YARA pattern matching for indicators of compromise"
    install_hint = (
        "Install YARA: https://yara.readthedocs.io/en/stable/gettingstarted.html"
    )

    # Community rule repositories — fetched at runtime if missing
    _COMMUNITY_RULES: list[dict[str, str]] = [
        {
            "name": "php-malware-finder",
            "url": (
                "https://raw.githubusercontent.com/"
                "jvoisin/php-malware-finder/master/data/php.yar"
            ),
            "license": "LGPL-3.0",
            "description": "PHP webshell & backdoor detection rules",
        },
        {
            "name": "signature-base-webshells",
            "url": (
                "https://raw.githubusercontent.com/"
                "Neo23x0/signature-base/master/yara/gen_webshells.yar"
            ),
            "license": "CC-BY-NC-4.0",
            "description": "Generic webshell detection signatures",
        },
        {
            "name": "signature-base-php-webshells",
            "url": (
                "https://raw.githubusercontent.com/"
                "Neo23x0/signature-base/master/yara/thor-webshells.yar"
            ),
            "license": "CC-BY-NC-4.0",
            "description": "PHP-focused webshell signatures",
        },
    ]

    def __init__(self, *, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or self._default_rules_dir()

    @staticmethod
    def _default_rules_dir() -> Path:
        """Return platform-appropriate cache dir for community rules."""
        env_dir = os.environ.get("REDACTS_DATA_DIR", "").strip()
        if env_dir:
            base = Path(env_dir)
        else:
            base = Path.home() / ".redacts"
        rules = base / "yara_rules"
        rules.mkdir(parents=True, exist_ok=True)
        return rules

    def is_available(self) -> bool:
        return _resolve_venv_tool("yara") is not None

    def get_version(self) -> str:
        binary = _resolve_venv_tool("yara") or "yara"
        out, _, rc = self._run_subprocess([binary, "--version"], timeout=10)
        return out.strip() if rc == 0 else ""

    @staticmethod
    def _sanitize_php_malware_finder(rule_file: Path) -> None:
        """Strip unsatisfiable includes from php-malware-finder rules.

        The upstream ``php.yar`` includes ``whitelist.yar`` which in turn
        pulls in 8 CMS-specific hash-whitelists (Drupal, WordPress, …).
        Those are irrelevant for REDCap analysis and would require
        fetching 9 extra files.  Instead we:

        1. Remove ``include "whitelist.yar"``
        2. Remove ``import "hash"`` (only used by the whitelist)
        3. Strip ``and not IsWhitelisted`` conditions
        """
        import re

        text = rule_file.read_text(encoding="utf-8", errors="replace")
        original = text

        # Remove the include and import lines
        text = re.sub(r'^\s*include\s+"whitelist\.yar"\s*$', "", text, flags=re.MULTILINE)
        text = re.sub(r'^\s*import\s+"hash"\s*$', "", text, flags=re.MULTILINE)

        # Remove "and not IsWhitelisted" from rule conditions
        text = re.sub(r"\s+and\s+not\s+IsWhitelisted\b", "", text)

        if text != original:
            rule_file.write_text(text, encoding="utf-8")
            logger.info("Sanitized php-malware-finder rules (stripped whitelist references)")

    @staticmethod
    def _reject_ssrf_target(hostname: str) -> None:
        """Block requests to internal/reserved IPs (delegates to shared utility)."""
        reject_ssrf_target(hostname)

    def ensure_community_rules(self, *, force: bool = False) -> list[Path]:

        """Download community rules if not cached.  Returns paths to rule files."""
        available_rules: list[Path] = []

        for spec in self._COMMUNITY_RULES:
            rule_file = self._rules_dir / f"{spec['name']}.yar"
            if rule_file.is_file() and not force:
                available_rules.append(rule_file)
                continue

            try:
                import requests
                logger.info(
                    "Fetching community YARA rules: %s (%s)",
                    spec["name"], spec["license"],
                )

                # Security: HTTPS-only, domain allowlist, SSRF check
                enforce_https(spec["url"])
                parsed = urlparse(spec["url"])
                check_domain_allowlist(parsed.hostname or "")
                reject_ssrf_target(parsed.hostname or "")

                # Atomic download: write to temp, rename on success
                fd, tmp_name = tempfile.mkstemp(
                    suffix=".yar", dir=str(self._rules_dir)
                )
                tmp_path = Path(tmp_name)
                try:
                    os.close(fd)
                    with requests.get(
                        spec["url"],
                        stream=True,
                        timeout=30,
                        allow_redirects=False,
                    ) as r:
                        r.raise_for_status()
                        with open(tmp_path, "wb") as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                f.write(chunk)
                    tmp_path.replace(rule_file)
                except Exception:
                    tmp_path.unlink(missing_ok=True)
                    raise

                if rule_file.is_file() and rule_file.stat().st_size > 0:
                    # Post-download sanitization for rules with unresolvable includes
                    if spec["name"] == "php-malware-finder":
                        self._sanitize_php_malware_finder(rule_file)
                    available_rules.append(rule_file)
                    logger.info("Cached: %s (%d bytes)", rule_file, rule_file.stat().st_size)
                else:
                    logger.warning("Download produced empty file: %s", spec["name"])
            except Exception as exc:
                logger.warning(
                    "Failed to fetch community rule %s: %s", spec["name"], exc
                )

        return available_rules

    def run(
        self, target_path: Path, config: dict[str, Any] | None = None
    ) -> ExternalToolResult:
        if not self.is_available():
            return self._empty_result()

        cfg = config or {}
        timeout: int = cfg.get("timeout", DEFAULT_TOOL_TIMEOUT)
        rules_path: str | None = cfg.get("rules_path")
        use_community: bool = cfg.get("use_community_rules", True)
        version = self.get_version()
        start = time.monotonic()

        # Collect all rule files: user-supplied + community
        rule_files: list[str] = []
        if rules_path:
            rule_files.append(rules_path)
        if use_community:
            community = self.ensure_community_rules()
            rule_files.extend(str(p) for p in community)

        if not rule_files:
            elapsed = time.monotonic() - start
            return ExternalToolResult(
                tool_name=self.name,
                tool_version=version,
                available=True,
                success=True,
                execution_time_seconds=elapsed,
                raw_output="No YARA rule files available; skipping scan.",
                parsed_data={
                    "matches": [],
                    "note": (
                        "No user rules_path provided and community rules "
                        "could not be fetched.  Set use_community_rules=True "
                        "and ensure network access."
                    ),
                },
            )

        # Run YARA with each rule file (YARA CLI takes one rule file per invocation)
        all_matches: list[dict[str, Any]] = []
        all_raw: list[str] = []
        all_errors: list[str] = []

        for rf in rule_files:
            binary = _resolve_venv_tool("yara") or "yara"
            cmd = [binary, "-r", "-s", rf, str(target_path)]
            out, err, rc = self._run_subprocess(cmd, timeout=timeout)
            all_raw.append(f"=== Rules: {rf} ===\n{out}")

            if err.strip():
                # Filter out benign warnings
                for eline in err.strip().splitlines():
                    if "warning" not in eline.lower():
                        all_errors.append(eline)

            # Parse matches — with -s flag, format is:
            #   RuleName TargetFile
            #   0xOFFSET:$IDENTIFIER: matched_content
            current_rule: str | None = None
            current_target: str | None = None
            current_strings: list[dict[str, str]] = []

            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                # String match line starts with hex offset
                if line.startswith("0x"):
                    parts = line.split(":", 2)
                    if len(parts) >= 3:
                        current_strings.append({
                            "offset": parts[0].strip(),
                            "identifier": parts[1].strip(),
                            "data": parts[2].strip()[:200],  # truncate long matches
                        })
                else:
                    # Flush previous match
                    if current_rule and current_target:
                        all_matches.append({
                            "rule": current_rule,
                            "target": current_target,
                            "rule_file": Path(rf).name,
                            "matched_strings": current_strings,
                        })
                    # Parse new rule match
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        current_rule = parts[0]
                        current_target = parts[1]
                        current_strings = []
                    else:
                        current_rule = None
                        current_target = None
                        current_strings = []

            # Flush last match
            if current_rule and current_target:
                all_matches.append({
                    "rule": current_rule,
                    "target": current_target,
                    "rule_file": Path(rf).name,
                    "matched_strings": current_strings,
                })

        elapsed = time.monotonic() - start

        # Classify matches by severity
        critical_rules = {
            "php_backdoor", "php_webshell", "webshell", "backdoor",
            "php_obfuscation_eval", "phpInPNG", "SuspiciousCodeSignature",
        }
        high_matches = [
            m for m in all_matches
            if any(kw in m["rule"].lower() for kw in ("shell", "backdoor", "exploit", "malware"))
        ]
        critical_matches = [
            m for m in all_matches
            if m["rule"] in critical_rules
        ]

        return ExternalToolResult(
            tool_name=self.name,
            tool_version=version,
            available=True,
            success=not all_errors,
            execution_time_seconds=elapsed,
            raw_output="\n".join(all_raw),
            parsed_data={
                "matches": all_matches,
                "match_count": len(all_matches),
                "critical_match_count": len(critical_matches),
                "high_match_count": len(high_matches),
                "rule_files_used": [Path(rf).name for rf in rule_files],
                "community_rules_loaded": use_community,
            },
            errors=all_errors,
            files_analyzed=1,  # recursive scan counts as one invocation
        )
