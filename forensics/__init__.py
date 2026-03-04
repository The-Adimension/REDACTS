"""REDACTS Forensics module — file analysis, PHP AST, security scanning."""

from .magika_analyzer import MagikaAnalyzer, MagikaResult

# tree-sitter imports are lazy — the package is a runtime dependency,
# not guaranteed present in every test environment.
try:
    from .tree_sitter_analyzer import TreeSitterAnalyzer, PHPFileAST
except ImportError:
    TreeSitterAnalyzer = None  # type: ignore[assignment,misc]
    PHPFileAST = None  # type: ignore[assignment,misc]
