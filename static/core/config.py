"""Central configuration dataclasses for REDACTS.

Values come from the active :class:`~static.core.contract.FrozenCaseContract`
via :meth:`REDACTSConfig.from_contract`. The default-constructed values
remain available for unit tests and the bootstrap path before a case is
loaded; they are *not* user-tunable. ``case.toml`` is the single source
of truth and environment-variable overrides are not consulted.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .paths import output_dir as _resolve_output_dir, temp_dir as _resolve_temp_dir

if TYPE_CHECKING:
    from .contract import FrozenCaseContract

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Docker sandbox security configuration."""

    enabled: bool = True
    docker_image: str = "php:8.2-cli-alpine"
    max_execution_time: int = 300  # seconds
    max_memory: str = "512m"
    max_cpu: float = 1.0
    network_disabled: bool = True  # No network in sandbox
    read_only_rootfs: bool = True  # Read-only root filesystem
    no_new_privileges: bool = True  # Prevent privilege escalation
    tmpfs_size: str = "64m"  # Temp filesystem limit
    drop_capabilities: list[str] = field(
        default_factory=lambda: ["ALL"]  # Drop ALL Linux capabilities
    )
    seccomp_profile: str = "default"  # Use default seccomp profile


@dataclass
class AnalysisConfig:
    """Analysis configuration."""

    # File analysis
    max_file_size_mb: int = 50  # Skip files larger than this
    max_total_files: int = 50_000  # Hard cap on total files to process
    hash_algorithms: list[str] = field(
        default_factory=lambda: ["sha256", "sha512"]
    )
    encoding_detection: bool = True
    binary_detection: bool = True

    # Code metrics
    count_lines: bool = True
    count_chars: bool = True
    count_tokens: bool = True
    complexity_analysis: bool = True

    # PHP analysis
    php_lint: bool = True
    php_ast: bool = True
    php_tokenize: bool = True

    # Patterns to ignore
    ignore_patterns: list[str] = field(
        default_factory=lambda: [
            "__pycache__",
            "*.pyc",
            ".git",
            ".svn",
            "node_modules",
            ".DS_Store",
            "Thumbs.db",
            "*.map",
            "*.min.js",
            "*.min.css",
        ]
    )

    # Extensions to analyze as code
    code_extensions: list[str] = field(
        default_factory=lambda: [
            ".php",
            ".js",
            ".css",
            ".html",
            ".htm",
            ".xml",
            ".json",
            ".sql",
            ".py",
            ".sh",
            ".bat",
            ".yml",
            ".yaml",
            ".twig",
            ".tpl",
            ".inc",
            ".module",
            ".ini",
            ".conf",
            ".md",
            ".txt",
            ".csv",
            ".htaccess",
        ]
    )

    # Extensions treated as binary (skip content analysis)
    binary_extensions: list[str] = field(
        default_factory=lambda: [
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".ico",
            ".svg",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".otf",
            ".pdf",
            ".zip",
            ".gz",
            ".tar",
            ".rar",
            ".7z",
            ".exe",
            ".dll",
            ".so",
            ".dylib",
            ".wasm",
            ".bcmap",
            ".pfb",
            ".icc",
            ".mp3",
            ".mp4",
            ".avi",
            ".mov",
        ]
    )

    # Parallel workers
    parallel_workers: int = 4
    timeout_per_file: int = 30


@dataclass
class RepomixConfig:
    """Repomix integration configuration."""

    enabled: bool = True
    command: str = "repomix"
    exclude_patterns: list[str] = field(
        default_factory=lambda: [
            "*.map",
            "vendor/**",
            "node_modules/**",
            "*.min.js",
            "*.min.css",
            "*.wasm",
            "*.bcmap",
            "*.pfb",
        ]
    )
    output_format: str = "txt"
    timeout: int = 600  # seconds


@dataclass
class ReportConfig:
    """Report generation configuration."""

    formats: list[str] = field(default_factory=lambda: ["html", "json", "markdown"])
    include_diffs: bool = True
    include_metrics: bool = True
    include_graphs: bool = True
    max_findings_in_summary: int = 100
    template_dir: str | None = None


@dataclass
class DastConfig:
    """DAST (Dynamic Application Security Testing) configuration."""

    enabled: bool = False
    suites: list[str] = field(default_factory=lambda: ["export", "admin", "upgrade"])
    port: int = 8585
    timeout: int = 600  # Per-suite timeout in seconds
    keep_stack: bool = False  # Keep Docker stack after tests
    output_subdir: str = "dast"  # Subdirectory under output_dir for DAST results
    runtime: str = "docker"  # Runtime backend: "docker" or "nix"


@dataclass
class EvidenceConfig:
    """Evidence collection (Tier 1) configuration."""

    # Output defaults
    default_label_prefix: str = "evidence"
    evidence_subdir: str = "evidence"  # Subdirectory under output_dir

    # Hashing
    hash_algorithms: list[str] = field(
        default_factory=lambda: ["sha256", "sha512"]
    )

    # Manifest options
    detect_anomalies: bool = True
    entropy_threshold: float = 7.5  # High-entropy file threshold (max 8.0 for bytes)
    max_file_size_mb: int = 100  # Skip files larger than this for content analysis

    # Repomix evidence snapshot
    generate_repomix: bool = True

    # Retention
    retain_source_copy: bool = False  # Whether to copy source files into evidence pkg


@dataclass
class InvestigationConfig:
    """Investigation (Tier 2) configuration."""

    # External tool toggles
    enable_external_tools: bool = True
    external_tool_timeout: int = 120  # seconds per tool

    # Tools to enable (checked by name, e.g. "yara", "phplint", "lizard")
    enabled_tools: set[str] = field(
        default_factory=lambda: {
            "phplint", "lizard", "yara", "clamav",
            "radon", "pydeps", "pyan", "code2flow",
        }
    )

    # Sensitivity levels (what to scan for)
    scan_sensitive_data: bool = True
    scan_iocs: bool = True
    scan_config_integrity: bool = True
    scan_attack_vectors: bool = True

    # Thresholds
    complexity_danger_threshold: int = 15  # Cyclomatic complexity
    nloc_danger_threshold: int = 100  # Lines of code per function

    # YARA rules path (optional, custom rules)
    yara_rules_path: str = ""


@dataclass
class REDACTSConfig:
    """Master configuration for REDACTS."""

    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    repomix: RepomixConfig = field(default_factory=RepomixConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    dast: DastConfig = field(default_factory=DastConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    investigation: InvestigationConfig = field(default_factory=InvestigationConfig)

    # Global settings - paths anchored to ~/.redacts/ (not inside the package)
    output_dir: str = field(default_factory=lambda: str(_resolve_output_dir()))
    verbose: bool = False
    log_level: str = "INFO"
    temp_dir: str = field(default_factory=lambda: str(_resolve_temp_dir()))
    global_timeout_seconds: int = 3600  # Overall scan watchdog (1 hour)

    @classmethod
    def from_contract(cls, contract: "FrozenCaseContract") -> "REDACTSConfig":
        """Build a runtime config from the frozen case contract.

        Every value here is sourced from ``case.toml``. There is no
        environment-variable fallback and no JSON/YAML overlay. Callers
        must load the contract first and pass it here.
        """
        config = cls()

        # Sandbox - image is pinned by the dynamic stack's sandbox image.
        config.sandbox.docker_image = contract.dynamic.images.sandbox.full_ref
        config.sandbox.network_disabled = contract.security.network_disabled
        config.sandbox.no_new_privileges = contract.security.sandbox_no_new_priv
        config.sandbox.read_only_rootfs = contract.security.sandbox_read_only
        config.sandbox.drop_capabilities = list(contract.security.sandbox_drop_caps)

        # Analysis
        config.analysis.parallel_workers = contract.static.parallel_workers
        config.analysis.max_total_files = contract.static.max_total_files

        # Reports
        config.report.formats = list(contract.static.formats)

        # DAST
        config.dast.enabled = contract.dynamic.enabled
        config.dast.suites = list(contract.dynamic.suites)
        config.dast.port = contract.dynamic.port
        config.dast.timeout = contract.dynamic.suite_timeout
        config.dast.keep_stack = contract.dynamic.keep_stack
        config.dast.runtime = contract.dynamic.runtime

        # Globals
        config.output_dir = str(contract.paths.output_root)
        config.temp_dir = str(contract.paths.temp_root)
        config.log_level = contract.logging.level.upper()
        config.global_timeout_seconds = contract.static.global_timeout_seconds

        config.validate()
        return config

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to dict."""
        from dataclasses import asdict

        return asdict(self)

    def validate(self) -> None:
        """Validate configuration values. Raises ValueError on invalid config."""
        import os as _os

        errors: list[str] = []

        if self.log_level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            errors.append(f"Invalid log_level: '{self.log_level}'")

        if self.analysis.parallel_workers < 1:
            errors.append(f"analysis.parallel_workers must be >= 1, got {self.analysis.parallel_workers}")

        cpu_count = _os.cpu_count() or 4
        max_workers = cpu_count * 2
        if self.analysis.parallel_workers > max_workers:
            errors.append(
                f"analysis.parallel_workers={self.analysis.parallel_workers} exceeds "
                f"2x CPU count ({cpu_count}). Max allowed: {max_workers}"
            )

        if self.analysis.max_file_size_mb < 1:
            errors.append(f"analysis.max_file_size_mb must be >= 1, got {self.analysis.max_file_size_mb}")

        if self.analysis.max_file_size_mb > 500:
            errors.append(
                f"analysis.max_file_size_mb={self.analysis.max_file_size_mb} exceeds 500 MB safety cap"
            )

        if self.analysis.max_total_files < 1:
            errors.append(f"analysis.max_total_files must be >= 1, got {self.analysis.max_total_files}")

        if self.analysis.max_total_files > 500_000:
            errors.append(
                f"analysis.max_total_files={self.analysis.max_total_files} exceeds 500 000 safety cap"
            )


        if self.sandbox.max_execution_time < 1:
            errors.append(f"sandbox.max_execution_time must be >= 1, got {self.sandbox.max_execution_time}")

        if self.dast.timeout < 1:
            errors.append(f"dast.timeout must be >= 1, got {self.dast.timeout}")

        if self.global_timeout_seconds < 60:
            errors.append(
                f"global_timeout_seconds must be >= 60, got {self.global_timeout_seconds}"
            )

        if self.global_timeout_seconds > 86_400:
            errors.append(
                f"global_timeout_seconds={self.global_timeout_seconds} exceeds 24-hour safety cap"
            )

        valid_formats = {"html", "json", "markdown", "sarif"}
        for fmt in self.report.formats:
            if fmt not in valid_formats:
                errors.append(f"Invalid report format: '{fmt}'. Valid: {valid_formats}")

        if errors:
            raise ValueError(
                "Invalid REDACTS configuration:\n" +
                "\n".join(f"  * {e}" for e in errors)
            )
