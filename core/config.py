"""
REDACTS Configuration Dataclasses
===================================
Central configuration with environment variable overrides and security defaults.

Extracted from ``core/__init__.py`` (Step 5.1).  All public names are
re-exported from ``core.__init__`` for backward compatibility, so
``from core import REDACTSConfig`` continues to work.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Project root = parent of the REDACTS package directory.
# This anchors output/temp paths regardless of CWD.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Docker sandbox security configuration."""

    enabled: bool = True
    docker_image: str = os.environ.get("REDACTS_SANDBOX_IMAGE", "php:8.2-cli-alpine")
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
class ComparisonConfig:
    """Comparison configuration."""

    structural_diff: bool = True
    content_diff: bool = True
    readability_analysis: bool = True
    similarity_threshold: float = 0.85  # Files >85% similar flagged as modified
    context_lines: int = 3  # Lines of context in diffs
    max_diff_size_mb: int = 10  # Skip diff for files larger than this


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
    template_dir: Optional[str] = None


@dataclass
class DastConfig:
    """DAST (Dynamic Application Security Testing) configuration."""

    enabled: bool = False
    suites: list[str] = field(default_factory=lambda: ["export", "admin", "upgrade"])
    port: int = 8585
    timeout: int = 600  # Per-suite timeout in seconds
    keep_stack: bool = False  # Keep Docker stack after tests
    output_subdir: str = "dast"  # Subdirectory under output_dir for DAST results


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

    # Individual tool toggles
    enable_phplint: bool = True
    enable_lizard: bool = True
    enable_yara: bool = True
    enable_clamav: bool = True
    enable_radon: bool = True
    enable_pydeps: bool = True
    enable_pyan: bool = True
    enable_code2flow: bool = True

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
class ForensicReportConfig:
    """Forensic report (Tier 2 output) configuration."""

    formats: list[str] = field(default_factory=lambda: ["html", "json", "markdown"])
    include_out_of_scope: bool = True  # Always include Out of Scope declaration
    include_recommendations: bool = True
    include_chain_of_custody: bool = True
    include_attack_vector_matrix: bool = True
    max_findings_per_category: int = 500  # Cap for very large codebases
    report_subdir: str = "reports"  # Subdirectory under output_dir


@dataclass
class REDACTSConfig:
    """Master configuration for REDACTS."""

    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    comparison: ComparisonConfig = field(default_factory=ComparisonConfig)
    repomix: RepomixConfig = field(default_factory=RepomixConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    dast: DastConfig = field(default_factory=DastConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)
    investigation: InvestigationConfig = field(default_factory=InvestigationConfig)
    forensic_report: ForensicReportConfig = field(default_factory=ForensicReportConfig)

    # Global settings — paths anchored to project root (parent of package dir)
    output_dir: str = field(default_factory=lambda: str(_PROJECT_ROOT / "output"))
    verbose: bool = False
    log_level: str = "INFO"
    temp_dir: str = field(default_factory=lambda: str(_PROJECT_ROOT / ".redacts_tmp"))

    @classmethod
    def from_file(cls, config_path: Path) -> "REDACTSConfig":
        """Load configuration from JSON or YAML file.

        Raises on any error — callers *must* handle failures explicitly.
        """
        if not config_path.exists():
            raise FileNotFoundError(
                f"Config file not found: {config_path}. "
                f"Pass a valid path or omit --config to use defaults."
            )

        raw = config_path.read_text(encoding="utf-8")

        # Support both JSON and YAML
        if config_path.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError:
                raise ImportError(
                    "PyYAML is required to load YAML config files. "
                    "Install it with: pip install pyyaml"
                )
            data = yaml.safe_load(raw)
            if not isinstance(data, dict):
                raise ValueError(f"Config file must contain a mapping, got {type(data).__name__}")
        else:
            data = json.load(config_path.open())

        config = cls()
        # Apply nested configs
        if "sandbox" in data:
            config.sandbox = SandboxConfig(**data["sandbox"])
        if "analysis" in data:
            config.analysis = AnalysisConfig(**data["analysis"])
        if "comparison" in data:
            config.comparison = ComparisonConfig(**data["comparison"])
        if "repomix" in data:
            config.repomix = RepomixConfig(**data["repomix"])
        if "report" in data:
            config.report = ReportConfig(**data["report"])
        if "dast" in data:
            config.dast = DastConfig(**data["dast"])
        if "evidence" in data:
            config.evidence = EvidenceConfig(**data["evidence"])
        if "investigation" in data:
            config.investigation = InvestigationConfig(**data["investigation"])
        if "forensic_report" in data:
            config.forensic_report = ForensicReportConfig(**data["forensic_report"])
        for key in ("output_dir", "verbose", "log_level", "temp_dir"):
            if key in data:
                setattr(config, key, data[key])

        config.validate()
        return config

    @classmethod
    def from_env(cls) -> "REDACTSConfig":
        """Load overrides from environment variables."""
        config = cls()
        if v := os.getenv("REDACTS_SANDBOX_ENABLED"):
            config.sandbox.enabled = v.lower() == "true"
        if v := os.getenv("REDACTS_VERBOSE"):
            config.verbose = v.lower() == "true"
        if v := os.getenv("REDACTS_OUTPUT_DIR"):
            config.output_dir = v
        if v := os.getenv("REDACTS_LOG_LEVEL"):
            if v.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                raise ValueError(
                    f"Invalid REDACTS_LOG_LEVEL='{v}'. "
                    f"Must be DEBUG|INFO|WARNING|ERROR|CRITICAL."
                )
            config.log_level = v.upper()
        if v := os.getenv("REDACTS_WORKERS"):
            try:
                workers = int(v)
            except ValueError:
                raise ValueError(
                    f"Invalid REDACTS_WORKERS='{v}'. Must be a positive integer."
                )
            if workers < 1:
                raise ValueError(
                    f"Invalid REDACTS_WORKERS={workers}. Must be >= 1."
                )
            config.analysis.parallel_workers = workers
        if v := os.getenv("REDACTS_NETWORK_DISABLED"):
            config.sandbox.network_disabled = v.lower() == "true"
        if v := os.getenv("REDACTS_DAST_ENABLED"):
            config.dast.enabled = v.lower() == "true"
        if v := os.getenv("REDACTS_DAST_SUITES"):
            config.dast.suites = [s.strip() for s in v.split(",") if s.strip()]
        return config

    @classmethod
    def load(cls, workspace: Optional[Path] = None) -> "REDACTSConfig":
        """Load with precedence: file > env > defaults."""
        config = cls()
        # Try workspace config
        if workspace:
            for name in (".redacts.json", "redacts.config.json",
                         ".redacts.yaml", "redacts.config.yaml",
                         ".redacts.yml", "redacts.config.yml"):
                cfg_path = workspace / name
                if cfg_path.exists():
                    config = cls.from_file(cfg_path)
                    break

        # Apply ALL env overrides on top of file config
        env = cls.from_env()
        if os.getenv("REDACTS_SANDBOX_ENABLED"):
            config.sandbox.enabled = env.sandbox.enabled
        if os.getenv("REDACTS_VERBOSE"):
            config.verbose = env.verbose
        if os.getenv("REDACTS_OUTPUT_DIR"):
            config.output_dir = env.output_dir
        if os.getenv("REDACTS_LOG_LEVEL"):
            config.log_level = env.log_level
        if os.getenv("REDACTS_WORKERS"):
            config.analysis.parallel_workers = env.analysis.parallel_workers
        if os.getenv("REDACTS_NETWORK_DISABLED"):
            config.sandbox.network_disabled = env.sandbox.network_disabled
        if os.getenv("REDACTS_DAST_ENABLED"):
            config.dast.enabled = env.dast.enabled
        if os.getenv("REDACTS_DAST_SUITES"):
            config.dast.suites = env.dast.suites
        return config

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to dict."""
        from dataclasses import asdict

        return asdict(self)

    def validate(self) -> None:
        """Validate configuration values. Raises ValueError on invalid config."""
        errors: list[str] = []

        if self.log_level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            errors.append(f"Invalid log_level: '{self.log_level}'")

        if self.analysis.parallel_workers < 1:
            errors.append(f"analysis.parallel_workers must be >= 1, got {self.analysis.parallel_workers}")

        if self.analysis.max_file_size_mb < 1:
            errors.append(f"analysis.max_file_size_mb must be >= 1, got {self.analysis.max_file_size_mb}")

        if not (0.0 <= self.comparison.similarity_threshold <= 1.0):
            errors.append(
                f"comparison.similarity_threshold must be 0.0–1.0, "
                f"got {self.comparison.similarity_threshold}"
            )

        if self.sandbox.max_execution_time < 1:
            errors.append(f"sandbox.max_execution_time must be >= 1, got {self.sandbox.max_execution_time}")

        if self.dast.timeout < 1:
            errors.append(f"dast.timeout must be >= 1, got {self.dast.timeout}")

        valid_formats = {"html", "json", "markdown"}
        for fmt in self.report.formats:
            if fmt not in valid_formats:
                errors.append(f"Invalid report format: '{fmt}'. Valid: {valid_formats}")

        if errors:
            raise ValueError(
                "Invalid REDACTS configuration:\n" +
                "\n".join(f"  • {e}" for e in errors)
            )
