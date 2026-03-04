"""
REDACTS Repomix Integration - Generate compressed codebase representations.

Runs repomix on both REDCap versions and provides:
    - Token/character counts for each version
    - Compressed output files for LLM analysis
    - Comparison of structure between repomix outputs
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class RepomixResult:
    """Result from a repomix run."""

    success: bool = False
    output_file: str = ""
    total_files: int = 0
    total_chars: int = 0
    total_tokens: int = 0
    output_size_bytes: int = 0
    output_hash: str = ""
    error: Optional[str] = None
    command_used: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


@dataclass
class RepomixComparison:
    """Comparison between two repomix outputs."""

    source_result: RepomixResult = field(default_factory=RepomixResult)
    target_result: RepomixResult = field(default_factory=RepomixResult)

    token_difference: int = 0
    char_difference: int = 0
    file_difference: int = 0
    size_difference: int = 0
    token_change_pct: float = 0.0
    char_change_pct: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_result.to_dict(),
            "target": self.target_result.to_dict(),
            "differences": {
                "tokens": self.token_difference,
                "chars": self.char_difference,
                "files": self.file_difference,
                "size_bytes": self.size_difference,
                "token_change_pct": self.token_change_pct,
                "char_change_pct": self.char_change_pct,
            },
        }


class RepomixRunner:
    """
    Wraps repomix CLI to generate compressed codebase representations.

    Requires repomix to be installed: npm install -g repomix
    """

    DEFAULT_EXCLUDE = [
        "vendor/**",
        "node_modules/**",
        ".git/**",
        "*.min.js",
        "*.min.css",
        "*.map",
        "*.png",
        "*.jpg",
        "*.gif",
        "*.ico",
        "*.svg",
        "*.woff",
        "*.woff2",
        "*.ttf",
        "*.eot",
        "*.pdf",
        "*.zip",
        "*.tar",
        "*.gz",
    ]

    def __init__(
        self,
        repomix_cmd: str = "repomix",
        exclude_patterns: Optional[list[str]] = None,
        timeout: int = 600,
    ):
        # Resolve the command to a full path so subprocess.run works
        # on Windows where .cmd/.ps1 wrappers need explicit resolution.
        resolved = shutil.which(repomix_cmd)
        self.repomix_cmd = resolved if resolved else repomix_cmd
        self.exclude = exclude_patterns or self.DEFAULT_EXCLUDE
        self.timeout = timeout

    def is_available(self) -> bool:
        """Check if repomix is installed."""
        cmd = shutil.which(self.repomix_cmd)
        if cmd:
            return True
        # Try npx
        try:
            npx_cmd = shutil.which("npx") or "npx"
            result = subprocess.run(
                [npx_cmd, "--yes", "repomix", "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0
        except Exception:
            return False

    def run(
        self,
        source_dir: Path,
        output_file: Path,
        label: str = "",
    ) -> RepomixResult:
        """
        Run repomix on a directory.

        Args:
            source_dir: Directory to process
            output_file: Where to write output
            label: Label for logging
        """
        import time

        result = RepomixResult()
        start = time.time()

        # Build command
        # Use "." as target since cwd is set to source_dir;
        # passing an absolute source_dir with cwd=source_dir causes
        # repomix to resolve it as source_dir/source_dir.
        cmd = [self.repomix_cmd, "."]
        for pattern in self.exclude:
            cmd.extend(["--ignore", pattern])
        cmd.extend(["-o", str(output_file.resolve())])
        result.command_used = " ".join(cmd)

        try:
            logger.info(f"Running repomix on {label or source_dir}...")
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(source_dir),
            )

            result.duration_seconds = round(time.time() - start, 2)

            if proc.returncode == 0:
                result.success = True

                # Parse output stats from stdout
                stdout = proc.stdout
                files_match = re.search(r"(\d+)\s+files?", stdout, re.IGNORECASE)
                tokens_match = re.search(r"([\d,]+)\s+tokens?", stdout, re.IGNORECASE)
                chars_match = re.search(r"([\d,]+)\s+char", stdout, re.IGNORECASE)

                if files_match:
                    result.total_files = int(files_match.group(1).replace(",", ""))
                if tokens_match:
                    result.total_tokens = int(tokens_match.group(1).replace(",", ""))
                if chars_match:
                    result.total_chars = int(chars_match.group(1).replace(",", ""))

                # File stats
                if output_file.exists():
                    result.output_file = str(output_file)
                    result.output_size_bytes = output_file.stat().st_size
                    result.output_hash = self._file_hash(output_file)

                    # If we couldn't parse from stdout, count from file
                    if result.total_chars == 0:
                        result.total_chars = result.output_size_bytes
            else:
                result.error = proc.stderr[:500]
                logger.warning(f"Repomix failed: {proc.stderr[:200]}")

                # Fallback: try npx
                if "not found" in (proc.stderr or "").lower() or proc.returncode == 127:
                    return self._run_npx_fallback(source_dir, output_file, label, start)

        except subprocess.TimeoutExpired:
            result.error = f"Timeout after {self.timeout}s"
            result.duration_seconds = self.timeout
        except FileNotFoundError:
            # repomix not in PATH, try npx
            return self._run_npx_fallback(source_dir, output_file, label, start)
        except Exception as e:
            result.error = str(e)
            result.duration_seconds = round(time.time() - start, 2)

        return result

    def run_comparison(
        self,
        source_dir: Path,
        target_dir: Path,
        output_dir: Path,
        source_label: str = "source",
        target_label: str = "target",
    ) -> RepomixComparison:
        """
        Run repomix on both versions and compare results.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        source_output = output_dir / f"repomix-{source_label}.txt"
        target_output = output_dir / f"repomix-{target_label}.txt"

        comparison = RepomixComparison()
        comparison.source_result = self.run(source_dir, source_output, source_label)
        comparison.target_result = self.run(target_dir, target_output, target_label)

        # Compute differences
        s = comparison.source_result
        t = comparison.target_result
        comparison.token_difference = t.total_tokens - s.total_tokens
        comparison.char_difference = t.total_chars - s.total_chars
        comparison.file_difference = t.total_files - s.total_files
        comparison.size_difference = t.output_size_bytes - s.output_size_bytes

        if s.total_tokens > 0:
            comparison.token_change_pct = round(
                (comparison.token_difference / s.total_tokens) * 100, 2
            )
        if s.total_chars > 0:
            comparison.char_change_pct = round(
                (comparison.char_difference / s.total_chars) * 100, 2
            )

        return comparison

    def _run_npx_fallback(
        self, source_dir: Path, output_file: Path, label: str, start_time: float
    ) -> RepomixResult:
        """Fallback to npx repomix."""
        import time

        result = RepomixResult()
        # Resolve npx to full path for Windows .cmd compatibility
        npx_cmd = shutil.which("npx") or "npx"
        cmd = [npx_cmd, "--yes", "repomix", "."]
        for pattern in self.exclude:
            cmd.extend(["--ignore", pattern])
        cmd.extend(["-o", str(output_file.resolve())])
        result.command_used = " ".join(cmd)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(source_dir),
            )
            result.duration_seconds = round(time.time() - start_time, 2)

            if proc.returncode == 0 and output_file.exists():
                result.success = True
                result.output_file = str(output_file)
                result.output_size_bytes = output_file.stat().st_size
                result.output_hash = self._file_hash(output_file)
                result.total_chars = result.output_size_bytes
            else:
                result.error = (
                    proc.stderr[:500] if proc.stderr else "npx repomix failed"
                )
        except Exception as e:
            result.error = f"npx fallback failed: {e}"
            result.duration_seconds = round(time.time() - start_time, 2)

        return result

    def _file_hash(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
