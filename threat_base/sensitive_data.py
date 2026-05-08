"""Sensitive-data scanner \u2014 PHI, PII, credentials, financial.

Scope and limits

The scanner is **regex-based by design**. There is no NER model in the
loop: a forensic tool that uses a probabilistic classifier to decide
whether something is PHI is a tool that occasionally hides PHI when the
model is wrong. Patterns live in
``threat_base/data/yaml/sensitive_data_patterns.yaml`` so a reviewer
can audit them.

What counts as PHI follows 45 CFR \u00a7 164.514(b)(2)(i) \u2014 the eighteen
Safe-Harbor identifiers (names, geography below state level, dates tied
to an individual, telephone, fax, email, SSN, MRN, beneficiary number,
account, license, vehicle and device serials, URLs, IP addresses,
biometrics, full-face images, and the catch-all *any other unique
identifying number, characteristic, or code*). REDCap project metadata
collides with most of these, which is why this scanner runs against
filesystem snapshots and not live database content.

Hard invariant

Detection is non-destructive. The scanner reads files; it never writes,
moves, or rewrites them. Findings carry redacted snippets
(``***REDACTED***``) so reports can be circulated without re-leaking
the very data that triggered the finding. If you find yourself adding
a code path that mutates the source tree, you are in the wrong module.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from static.core.file_utils import is_binary as _is_binary_canonical
from .data_loader import load_sensitive_data_patterns

log = logging.getLogger(__name__)

# --- Load externalized data from YAML --------------

_sd_data = load_sensitive_data_patterns()
_constraints = _sd_data.get("scan_constraints", {})

# --- File-scanning constraints  (from sensitive_data_patterns.yaml) ---

MAX_FILE_SIZE: int = _constraints.get("max_file_size_bytes", 10 * 1024 * 1024)

SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    _constraints.get("scannable_extensions", [])
)

SCANNABLE_DOT_FILES: frozenset[str] = frozenset(
    _constraints.get("scannable_dot_files", [])
)

# --- Snippet windowing constraints
# A finding's ``snippet_redacted`` is an excerpt of the source line.
# Without a cap, a single match in a minified asset (JS bundle, source
# map) cloned the entire multi-megabyte line into every finding,
# inflating reports by orders of magnitude. The cap below is bytes of
# the *redacted* snippet; truncated snippets are flagged and carry the
# byte offsets of the visible window plus the file's SHA-256 so a
# reviewer can re-derive the full context from the on-disk artefact.
SNIPPET_MAX_BYTES: int = int(_constraints.get("snippet_max_bytes", 512))
SNIPPET_CONTEXT_RADIUS: int = int(
    _constraints.get("snippet_context_radius", 200)
)
_SNIPPET_TRUNCATION_MARKER: str = "...[+{n} chars]..."

# --- Preview redaction ------------
# When a forensic report needs to embed a snippet of a config file as
# evidence (database.php, .user.ini, .htaccess) the snippet must not
# carry the original credential value out of the analyst host.  The
# rules below are intentionally over-broad: false positives in a
# preview are acceptable, false negatives are not.

_PREVIEW_REDACTORS: tuple[tuple[re.Pattern[str], int], ...] = (
    # PHP/INI assignment style:  $password = "secret";  api_key='abc'
    (re.compile(
        r"""(?ix)
        (pass(?:word)?|passwd|secret|token|api[_-]?key|auth|bearer
         |db[_-]?pass|conn(?:ection)?[_-]?str(?:ing)?)
        \s*[:=]\s*
        ['"]?(?P<val>[^'"\s;,)]+)['"]?
        """),
        0,  # group name "val" handled below
    ),
    # Bare quoted strings of >=8 high-entropy chars (heuristic last-resort).
    (re.compile(
        r"""(?x) (['"]) (?P<val>[A-Za-z0-9+/=_\-!@#$%^&*?]{8,}) \1 """),
        0,
    ),
)

_REDACTED = "***REDACTED***"


def redact_preview(text: str) -> str:
    """Mask credential-shaped substrings in a config-file preview.

    Used wherever a snippet of an audited config file is embedded in a
    finding payload (JSON / Markdown / HTML / SARIF).  The function is
    deliberately aggressive: under-redacting a database password is a
    forensic incident; over-redacting an unrelated quoted string is
    only a cosmetic loss in the report.

    Limits: this is a regex-only mask.  It will not catch credentials
    encoded as PHP heredoc, base64-of-a-URL, or split across string
    concatenation.  For those, the operator must inspect the file
    directly under access controls --- not the report.
    """
    if not text:
        return text

    def _replace_named(m: re.Match[str]) -> str:
        val = m.group("val")
        return m.group(0).replace(val, _REDACTED) if val else m.group(0)

    for pattern, _ in _PREVIEW_REDACTORS:
        text = pattern.sub(_replace_named, text)
    return text


# --- Dataclasses


@dataclass
class SensitiveDataFinding:
    """A single instance of detected sensitive data."""

    file_path: str  # Relative to scan root
    line: int  # 1-based line number
    column: int  # 0-based column offset
    data_type: str  # e.g. "ssn", "email", "api_token", "password"
    category: str  # PHI | CREDENTIAL | PII | FINANCIAL | INFRASTRUCTURE
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    snippet_redacted: str  # Source line with the matched value masked
    original_length: int  # Length of the raw matched value (forensic doc)
    assessment: str  # Human-readable explanation
    hipaa_identifier: bool  # True when the finding maps to one of the 18 identifiers
    # Forensic integrity metadata for snippet windowing. When the
    # underlying source line exceeds ``SNIPPET_MAX_BYTES``, the snippet
    # is centred around the redaction marker and surrounded by literal
    # ``...[+N chars]...`` markers. The fields below let a reviewer locate
    # and verify the original bytes against the on-disk file.
    snippet_truncated: bool = False  # True when the line was longer than the cap
    snippet_window: tuple[int, int] = (0, 0)  # byte offsets within the source line
    line_length: int = 0  # full length of the source line in characters
    file_sha256: str = ""  # SHA-256 of the file's raw bytes ("" if unavailable)


@dataclass
class SensitiveDataReport:
    """Aggregated report produced by ``SensitiveDataScanner.scan_directory``."""

    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    scanned_files: int = 0
    findings: list[SensitiveDataFinding] = field(default_factory=list)
    hipaa_exposure_summary: str = ""
    truncated_snippets: int = 0  # count of findings whose snippet was windowed
    snippet_max_bytes: int = SNIPPET_MAX_BYTES  # the cap that was in effect

    # -- helpers --------

    # Snippet emission modes.
    #
    #   ``windowed`` - default analyst view. Emits the redacted line
    #     bounded to ``SNIPPET_MAX_BYTES`` with explicit truncation
    #     markers. Carries enough context to triage without leaking
    #     entire minified bundles.
    #   ``pointer`` - circulation view. Drops ``snippet_redacted``
    #     entirely and relies on (file_path, line, column,
    #     original_length, file_sha256, snippet_window, line_length)
    #     so the artefact can be re-derived on a host that holds the
    #     source. Use for cross-team or external sharing.
    #   ``full`` - internal forensics only. Returns the snippet
    #     un-windowed (still redacted). Will inflate reports on
    #     minified assets.
    _SNIPPET_MODES: ClassVar[frozenset[str]] = frozenset(
        {"windowed", "pointer", "full"}
    )

    def to_dict(self, snippet_mode: str = "windowed") -> dict:
        """Serialise to a plain ``dict`` suitable for JSON output.

        Parameters
        snippet_mode:
            One of ``"windowed"`` (default), ``"pointer"``, ``"full"``.
            See class docstring for semantics. ``pointer`` omits the
            ``snippet_redacted`` field altogether so the report can
            travel without carrying any source-line bytes.
        """
        if snippet_mode not in self._SNIPPET_MODES:
            raise ValueError(
                f"snippet_mode must be one of {sorted(self._SNIPPET_MODES)}, "
                f"got {snippet_mode!r}"
            )

        findings_out: list[dict] = []
        for f in self.findings:
            entry: dict = {
                "file_path": f.file_path,
                "line": f.line,
                "column": f.column,
                "data_type": f.data_type,
                "category": f.category,
                "severity": f.severity,
                "snippet_truncated": f.snippet_truncated,
                "snippet_window": list(f.snippet_window),
                "line_length": f.line_length,
                "file_sha256": f.file_sha256,
                "original_length": f.original_length,
                "assessment": f.assessment,
                "hipaa_identifier": f.hipaa_identifier,
            }
            if snippet_mode != "pointer":
                entry["snippet_redacted"] = f.snippet_redacted
            findings_out.append(entry)

        return {
            "total_findings": self.total_findings,
            "findings_by_type": dict(self.findings_by_type),
            "findings_by_category": dict(self.findings_by_category),
            "findings_by_severity": dict(self.findings_by_severity),
            "scanned_files": self.scanned_files,
            "hipaa_exposure_summary": self.hipaa_exposure_summary,
            "truncated_snippets": self.truncated_snippets,
            "snippet_max_bytes": self.snippet_max_bytes,
            "snippet_mode": snippet_mode,
            "findings": findings_out,
        }


# --- Pattern definitions ----------

# Each entry: (compiled_regex, data_type, category, severity, assessment_template,
#               hipaa_identifier, group_index_for_value)
# ``group_index_for_value`` selects which regex group contains the actual
# sensitive value to redact.  ``0`` means the entire match.

_PatternTuple = tuple[re.Pattern[str], str, str, str, str, bool, int]


def _build_patterns() -> list[_PatternTuple]:
    """Build detection pattern tuples from externalized YAML data."""
    patterns: list[_PatternTuple] = []
    for p in _sd_data.get("patterns", []):
        compiled = p.get("compiled_regex")
        if compiled is None:
            continue
        patterns.append(
            (
                compiled,
                p["data_type"],
                p["category"],
                p["severity"],
                p["assessment"],
                bool(p.get("hipaa_identifier", False)),
                int(p.get("group_index", 0)),
            )
        )
    return patterns


# --- False-positive guard helpers (Fixes 1, 2, 5, 6, 7) --------------

# Paths whose findings are downgraded to INFO (vendored / generated /
# minified / framework). Matches against forward-slash relative paths.
_DOWNGRADE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"(?:^|/)vendor/",
        r"(?:^|/)node_modules/",
        r"(?:^|/)install_files/",
        r"(?:^|/)examples?/",
        r"(?:^|/)Resources/PDFJS/",
        r"\.min\.js$",
        r"\.bundle\.js$",
        r"\.umd\.min\.js$",
        r"\.map$",
        r"(?:^|/)pdf\.[^/]*\.mjs$",
        r"(?:^|/)openjpeg_nowasm_fallback\.js$",
        r"(?:^|/)StatsAndCharts\.js$",
    )
)

# Well-known constant hashes that must never be flagged as secrets.
# (Empty-input MD5 / SHA-1 / SHA-256 / SHA-512.)
_KNOWN_NONSECRET_HASHES: frozenset[str] = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ),
    }
)

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")
_MINIFIED_LINE_BYTES = 5000


def _path_should_downgrade(rel_path: str) -> bool:
    """Return True when *rel_path* matches a vendored / generated location."""
    norm = rel_path.replace("\\", "/")
    return any(p.search(norm) for p in _DOWNGRADE_PATH_PATTERNS)


def _line_match_in_comment(line: str, span_start: int) -> bool:
    """Heuristic per-line check: is *span_start* inside a `//`, `#`, or `--`
    comment? Block-comment ``/* ... */`` matching is left to upstream callers
    that operate on whole files; this catches the dominant single-line case.
    """
    for marker in ("//", "#", "--"):
        idx = line.find(marker)
        if idx != -1 and idx < span_start:
            # `#` is a comment in PHP/Python/shell/SQL; in CSS colors it is
            # followed by hex digits and never preceded by code that contains
            # a sensitive-data match span anyway.
            return True
    return False


def _is_password_column_context(line: str, span_start: int) -> bool:
    """Suppress ``password`` matches that are clearly SQL column
    references rather than literal credentials.

    Heuristics:
    * UPDATE ... SET ...password = $var / ?  (parameterised)
    * INSERT ... (password, ...) VALUES (?, ...)
    * db_escape($password) wrapping
    * ``:password`` or ``$password`` named/PHP-variable placeholders
    """
    surround = line[max(0, span_start - 80) : span_start + 120]
    low = surround.lower()
    # Parameterised assignment to a column named password.
    if re.search(r"\bset\b[^;]{0,200}\bpassword\s*=\s*[\$\?:]", low):
        return True
    # Function-call wrapping (escape / hash / prepare).
    if re.search(r"\b(?:db_escape|prepare|bind_param|hash|password_hash)\s*\(", low):
        return True
    # Column list in INSERT / SELECT.
    if re.search(r"\b(?:insert\s+into|select)\b[^;]{0,200}\bpassword\b", low):
        return True
    return False


def _is_in_base64_blob(line: str, span: tuple[int, int]) -> bool:
    """The match is embedded in a long base64 run."""
    if len(line) > _MINIFIED_LINE_BYTES:
        return True
    start, end = span
    left = line[max(0, start - 60) : start]
    right = line[end : end + 60]
    blob = (left + right).strip()
    if len(blob) < 40:
        return False
    return bool(_BASE64_RE.match(blob))


def _is_known_nonsecret(value: str) -> bool:
    """Literal value is a well-known empty-input hash."""
    return value.strip().lower() in _KNOWN_NONSECRET_HASHES


# --- Scanner ----


class SensitiveDataScanner:
    """Detects sensitive data in REDCap filesystem snapshots.

    **Design invariant**: this scanner only *reports* findings.  It never
    mutates, removes, or otherwise alters the files it inspects.  Matched
    values are replaced with ``***REDACTED***`` only inside the report
    snippet, preserving the original evidence on disk.
    """

    # Pre-compiled patterns (shared across instances).
    _PATTERNS: ClassVar[list[_PatternTuple]] = _build_patterns()

    # Regex for pre-filtering lines that *cannot* contain anything interesting.
    # This is a cheap gate to avoid running 20+ regexes on every line.
    _QUICK_GATE: ClassVar[re.Pattern[str]] = _sd_data.get(  # type: ignore[assignment]
        "compiled_quick_gate",
        re.compile(r"(?:password|passwd|pwd)", re.IGNORECASE),
    )

    _REDACTED: ClassVar[str] = "***REDACTED***"

    # Credit-card data_type prefixes requiring Luhn validation.
    _CC_TYPES: ClassVar[frozenset[str]] = frozenset(
        {
            "credit_card_visa",
            "credit_card_mc",
            "credit_card_amex",
            "credit_card_discover",
        }
    )

    # Public API                                                          #

    def scan_directory(self, root: Path) -> SensitiveDataReport:
        """Walk *root* recursively and scan every eligible file.

        Returns a populated :class:`SensitiveDataReport`.
        """
        all_findings: list[SensitiveDataFinding] = []
        scanned = 0

        root = root.resolve()
        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file():
                continue
            if not self._is_scannable(file_path):
                continue
            try:
                findings = self._scan_file(file_path, root)
                all_findings.extend(findings)
                scanned += 1
            except Exception:
                log.warning("Failed to scan %s", file_path, exc_info=True)

        report = self._build_report(all_findings, scanned)
        log.info(
            "Scan complete: %d findings across %d files.",
            report.total_findings,
            report.scanned_files,
        )
        return report

    def scan_files(
        self, root: Path, only_files: set[str]
    ) -> SensitiveDataReport:
        """Scan *only* the files whose relative paths are in *only_files*.

        This is the audit-mode entry point: the baseline diff determines
        exactly which files need inspection, so we skip the rest.
        """
        import os as _os

        all_findings: list[SensitiveDataFinding] = []
        scanned = 0
        root = root.resolve()

        for rel in sorted(only_files):
            file_path = root / rel.replace("/", _os.sep)
            if not file_path.is_file():
                continue
            try:
                findings = self._scan_file(file_path, root)
                all_findings.extend(findings)
                scanned += 1
            except Exception:
                log.warning("Failed to scan %s", file_path, exc_info=True)

        report = self._build_report(all_findings, scanned)
        log.info(
            "Audit-mode scan: %d findings across %d/%d delta files.",
            report.total_findings,
            report.scanned_files,
            len(only_files),
        )
        return report

    def _scan_file(
        self,
        file_path: Path,
        root: Path,
    ) -> list[SensitiveDataFinding]:
        """Scan a single file and return a list of findings.

        Parameters
        file_path:
            Absolute path to the file.
        root:
            Scan root - used to compute relative paths for findings.
        """
        findings: list[SensitiveDataFinding] = []

        try:
            size = file_path.stat().st_size
        except OSError:
            log.debug("Cannot stat %s - skipping.", file_path)
            return findings

        if size > MAX_FILE_SIZE:
            log.debug("Skipping %s - exceeds %d-byte limit.", file_path, MAX_FILE_SIZE)
            return findings

        if self._is_binary(file_path):
            return findings

        try:
            raw_bytes = file_path.read_bytes()
        except OSError:
            log.debug("Cannot read %s - skipping.", file_path)
            return findings

        # Forensic integrity: bind every windowed snippet to the
        # specific bytes that produced it. This lets a reviewer with
        # the artefact reproduce the redaction and verify that the
        # truncated context has not been tampered with in transit.
        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        text = raw_bytes.decode("utf-8", errors="replace")

        try:
            rel_path = str(file_path.relative_to(root))
        except ValueError:
            rel_path = str(file_path)

        downgrade = _path_should_downgrade(rel_path)
        truncated_in_file = 0

        for line_no, line in enumerate(text.splitlines(), start=1):
            if not self._QUICK_GATE.search(line):
                continue
            line_findings = self._scan_line(
                line,
                line_no,
                rel_path,
                downgrade=downgrade,
                file_sha256=file_sha256,
            )
            truncated_in_file += sum(1 for f in line_findings if f.snippet_truncated)
            findings.extend(line_findings)

        if truncated_in_file:
            # One INFO line per affected file keeps the audit trail
            # honest: every windowed snippet is accounted for and the
            # cap that was in effect is recorded alongside the count.
            log.info(
                "snippet windowing engaged for %s: %d finding(s) truncated to %d bytes",
                rel_path,
                truncated_in_file,
                SNIPPET_MAX_BYTES,
            )

        return findings

    # Internal helpers                                                    #

    def _scan_line(
        self,
        line: str,
        line_no: int,
        rel_path: str,
        downgrade: bool = False,
        file_sha256: str = "",
    ) -> list[SensitiveDataFinding]:
        """Run every pattern against *line* and yield findings."""

        findings: list[SensitiveDataFinding] = []
        seen_spans: list[tuple[int, int]] = []
        line_len = len(line)

        for (
            pat,
            data_type,
            category,
            severity,
            assessment,
            hipaa,
            grp,
        ) in self._PATTERNS:
            for m in pat.finditer(line):
                value = m.group(grp) if grp else m.group(0)
                span = m.span(grp) if grp else m.span(0)

                # Avoid duplicate findings when spans overlap.
                if any(
                    s_start <= span[0] < s_end or s_start < span[1] <= s_end
                    for s_start, s_end in seen_spans
                ):
                    continue

                # Drop matches that fall inside a single-line comment.
                if _line_match_in_comment(line, span[0]):
                    continue

                # Well-known empty-input hashes are public constants.
                if _is_known_nonsecret(value):
                    continue

                # SQL column-context gate for "password" matches.
                if data_type == "password" and _is_password_column_context(
                    line, span[0]
                ):
                    continue

                # Minified / base64 context gate for CC and SSN.
                if data_type in self._CC_TYPES or data_type.startswith("ssn"):
                    if line_len > _MINIFIED_LINE_BYTES:
                        continue
                    if _is_in_base64_blob(line, span):
                        continue

                # Luhn check for credit-card patterns.
                if data_type in self._CC_TYPES:
                    digits = re.sub(r"[\s\-]", "", value)
                    if not self._luhn_check(digits):
                        continue

                snippet = self._redact(m, line, grp)
                snippet, truncated, win_start, win_end = self._window_snippet(
                    snippet, span
                )
                effective_severity = (
                    "INFO"
                    if downgrade and severity in ("CRITICAL", "HIGH", "MEDIUM")
                    else severity
                )
                findings.append(
                    SensitiveDataFinding(
                        file_path=rel_path,
                        line=line_no,
                        column=span[0],
                        data_type=data_type,
                        category=category,
                        severity=effective_severity,
                        snippet_redacted=snippet,
                        original_length=len(value),
                        assessment=assessment,
                        hipaa_identifier=hipaa,
                        snippet_truncated=truncated,
                        snippet_window=(win_start, win_end),
                        line_length=line_len,
                        file_sha256=file_sha256,
                    )
                )
                seen_spans.append(span)

        return findings

    # -- redaction ---

    @staticmethod
    def _redact(match: re.Match[str], context_line: str, group: int = 0) -> str:
        """Return *context_line* with the matched value replaced by a
        redaction marker.

        Only the portion captured by *group* is replaced so that
        surrounding syntax (quotes, operators) remains visible in the
        snippet for forensic context.
        """
        start, end = match.span(group) if group else match.span(0)
        return context_line[:start] + "***REDACTED***" + context_line[end:]

    # -- snippet windowing ------------

    @staticmethod
    def _window_snippet(
        redacted_line: str, match_span: tuple[int, int]
    ) -> tuple[str, bool, int, int]:
        """Bound the redacted snippet to a deterministic window.

        Returns ``(snippet, truncated, window_start, window_end)`` where
        ``window_start`` / ``window_end`` are byte offsets into the
        ORIGINAL source line (not into the returned snippet) so the
        finding can be cross-referenced against the on-disk file using
        the recorded SHA-256.

        The window is centred on the redaction marker. When the line is
        already short enough the input is returned unchanged with
        ``truncated=False`` and the window covering the whole line.
        Otherwise leading/trailing ``\u2026[+N chars]\u2026`` markers make the
        truncation explicit so reviewers do not silently lose context.
        """
        n = len(redacted_line)
        if n <= SNIPPET_MAX_BYTES:
            return redacted_line, False, 0, n

        # Centre the visible window around the match, not on byte 0.
        # ``match_span`` is in coordinates of the ORIGINAL line; the
        # redaction substitution preserves left-of-match offsets, so
        # ``match_span[0]`` is also a valid index into ``redacted_line``.
        radius = max(SNIPPET_CONTEXT_RADIUS, SNIPPET_MAX_BYTES // 2)
        centre = max(0, min(n, match_span[0]))
        win_start = max(0, centre - radius)
        win_end = min(n, win_start + SNIPPET_MAX_BYTES)
        # If we hit the right edge, slide left so the window stays at the cap.
        win_start = max(0, win_end - SNIPPET_MAX_BYTES)

        body = redacted_line[win_start:win_end]
        prefix = (
            _SNIPPET_TRUNCATION_MARKER.format(n=win_start) if win_start > 0 else ""
        )
        suffix = (
            _SNIPPET_TRUNCATION_MARKER.format(n=n - win_end) if win_end < n else ""
        )
        return prefix + body + suffix, True, win_start, win_end

    # -- Luhn algorithm ----------------

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """Validate a numeric string using the Luhn algorithm.

        Returns ``True`` if *number* passes the check (plausible CC number).
        Non-digit characters are silently ignored.
        """
        digits = [int(ch) for ch in number if ch.isdigit()]
        if len(digits) < 12:
            return False

        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d

        return total % 10 == 0

    # -- file helpers

    @staticmethod
    def _is_scannable(file_path: Path) -> bool:
        """Return *True* when the file extension (or name) is in scope."""
        name = file_path.name.lower()
        if name in SCANNABLE_DOT_FILES:
            return True
        # Handle compound extensions like .user.ini
        suffixes = file_path.suffixes
        if suffixes:
            ext = "".join(suffixes).lower()
            if ext in SCANNABLE_EXTENSIONS:
                return True
            ext = suffixes[-1].lower()
            if ext in SCANNABLE_EXTENSIONS:
                return True
        return False

    @staticmethod
    def _is_binary(file_path: Path) -> bool:
        """Heuristic: delegate to the canonical binary-detection utility."""
        return _is_binary_canonical(file_path)

    # -- report assembly ---------------

    def _build_report(
        self,
        findings: list[SensitiveDataFinding],
        scanned_files: int,
    ) -> SensitiveDataReport:
        """Aggregate raw findings into a :class:`SensitiveDataReport`."""

        by_type: Counter[str] = Counter()
        by_category: Counter[str] = Counter()
        by_severity: Counter[str] = Counter()
        hipaa_types: Counter[str] = Counter()

        for f in findings:
            by_type[f.data_type] += 1
            by_category[f.category] += 1
            by_severity[f.severity] += 1
            if f.hipaa_identifier:
                hipaa_types[f.data_type] += 1

        hipaa_summary = self._hipaa_summary(hipaa_types, len(findings))

        truncated_count = sum(1 for f in findings if f.snippet_truncated)

        return SensitiveDataReport(
            total_findings=len(findings),
            findings_by_type=dict(by_type),
            findings_by_category=dict(by_category),
            findings_by_severity=dict(by_severity),
            scanned_files=scanned_files,
            findings=findings,
            hipaa_exposure_summary=hipaa_summary,
            truncated_snippets=truncated_count,
            snippet_max_bytes=SNIPPET_MAX_BYTES,
        )

    @staticmethod
    def _hipaa_summary(hipaa_types: Counter[str], total: int) -> str:
        """Produce a human-readable summary of HIPAA-relevant exposure."""
        if not hipaa_types:
            return "No HIPAA-relevant sensitive data detected."

        hipaa_total = sum(hipaa_types.values())
        parts: list[str] = []
        for dtype, count in hipaa_types.most_common():
            parts.append(f"{dtype}: {count}")

        pct = (hipaa_total / total * 100) if total else 0.0

        return (
            f"{hipaa_total} HIPAA-relevant finding(s) "
            f"({pct:.1f}% of {total} total). "
            f"Breakdown - {', '.join(parts)}."
        )
