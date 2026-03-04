"""
REDACTS tree-sitter PHP Analyzer — Real AST parsing for PHP.

Replaces the regex-based ``PHPParser`` with a proper AST parser using
tree-sitter-php.  This eliminates the entire class of false positives
and false negatives caused by regex limitations:

    - Matches inside strings/comments are ignored (not possible with re)
    - Full scope awareness (methods assigned to correct class)
    - Accurate brace matching (no naive counting)
    - Precise line/column location for every node
    - Correct cyclomatic complexity (only control flow, not string content)

The output is **PHPFileAST-compatible** so downstream code (comparison,
evidence collection, reporting) continues to work unchanged.

This is NOT optional.  ``tree-sitter`` + ``tree-sitter-php`` are MUST
dependencies.  ImportError is raised with install instructions.

Usage::

    analyzer = TreeSitterAnalyzer()
    ast = analyzer.parse_file(Path("index.php"), root=Path("/redcap"))
    for cls in ast.classes:
        for m in cls.methods:
            print(m.name, m.complexity)
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..core.constants import get_skip_dirs

try:
    import tree_sitter
except ImportError:
    raise ImportError(
        "tree-sitter is REQUIRED for PHP AST analysis.  "
        "Install: pip install tree-sitter tree-sitter-php"
    )

try:
    import tree_sitter_php  # type: ignore[import-untyped]
except ImportError:
    raise ImportError(
        "tree-sitter-php is REQUIRED for PHP AST analysis.  "
        "Install: pip install tree-sitter-php"
    )


# ═══════════════════════════════════════════════════════════════════════════
# PHP data models (formerly in php_parser.py)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class PHPToken:
    """Represents a PHP token."""

    type: str  # keyword, string, variable, operator, comment, etc.
    value: str  # Token text
    line: int  # Line number
    column: int = 0  # Column number


@dataclass
class PHPFunction:
    """Extracted PHP function/method."""

    name: str
    line: int
    end_line: int = 0
    visibility: str = "public"  # public, private, protected
    is_static: bool = False
    is_abstract: bool = False
    parameters: list[dict] = field(default_factory=list)
    return_type: str = ""
    phpdoc: str = ""
    body_lines: int = 0
    complexity: int = 1


@dataclass
class PHPClass:
    """Extracted PHP class."""

    name: str
    line: int
    end_line: int = 0
    extends: str = ""
    implements: list[str] = field(default_factory=list)
    is_abstract: bool = False
    is_final: bool = False
    is_interface: bool = False
    is_trait: bool = False
    namespace: str = ""
    methods: list[PHPFunction] = field(default_factory=list)
    properties: list[dict] = field(default_factory=list)
    constants: list[dict] = field(default_factory=list)
    phpdoc: str = ""


@dataclass
class PHPFileAST:
    """AST-level analysis of a PHP file."""

    path: str
    namespace: str = ""
    use_statements: list[dict] = field(default_factory=list)
    includes: list[dict] = field(default_factory=list)
    classes: list[PHPClass] = field(default_factory=list)
    functions: list[PHPFunction] = field(default_factory=list)
    constants: list[dict] = field(default_factory=list)
    global_variables: list[dict] = field(default_factory=list)
    sql_queries: list[dict] = field(default_factory=list)
    security_patterns: list[dict] = field(default_factory=list)

    # Token statistics
    total_tokens: int = 0
    token_distribution: dict[str, int] = field(default_factory=dict)

    # Raw file content for downstream comparators (string diffing, etc.)
    raw_content: str = ""

    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# tree-sitter language setup
# ═══════════════════════════════════════════════════════════════════════════

def _get_php_language() -> tree_sitter.Language:
    """Get the PHP language for tree-sitter."""
    # tree-sitter-php >= 0.23 exposes language() function directly
    if hasattr(tree_sitter_php, "language"):
        return tree_sitter.Language(tree_sitter_php.language())
    # Fallback for older tree-sitter-php with language_php
    if hasattr(tree_sitter_php, "language_php"):
        return tree_sitter.Language(tree_sitter_php.language_php())
    raise RuntimeError(
        "Cannot obtain PHP language from tree-sitter-php.  "
        "Ensure tree-sitter-php >= 0.23 is installed."
    )

# Complexity-contributing node types (McCabe cyclomatic complexity)
_COMPLEXITY_NODES = frozenset({
    "if_statement",
    "elseif_clause",
    "while_statement",
    "do_statement",
    "for_statement",
    "foreach_statement",
    "case_statement",
    "catch_clause",
    "conditional_expression",    # ternary ? :
    "binary_expression",          # && and || counted below
    "null_coalescing_expression", # ??
})

# Binary operators that increase complexity
_COMPLEXITY_OPERATORS = frozenset({"&&", "||", "and", "or"})


# ═══════════════════════════════════════════════════════════════════════════
# Security patterns to detect in AST
# ═══════════════════════════════════════════════════════════════════════════

# Function call names that indicate security concerns
_DANGEROUS_FUNCTIONS: dict[str, str] = {
    "eval": "eval_usage",
    "exec": "exec_usage",
    "system": "exec_usage",
    "passthru": "exec_usage",
    "shell_exec": "exec_usage",
    "popen": "exec_usage",
    "proc_open": "exec_usage",
    "assert": "eval_usage",
    "preg_replace": "eval_usage",  # /e modifier
    "unserialize": "unsafe_deserialization",
    "var_dump": "debug_function",
    "print_r": "debug_function",
    "debug_print_backtrace": "debug_function",
    "base64_decode": "obfuscation",
    "gzinflate": "obfuscation",
    "str_rot13": "obfuscation",
    "gzuncompress": "obfuscation",
    "mysql_query": "deprecation",
    "mysql_real_escape_string": "deprecation",
    "ereg": "deprecation",
    "split": "deprecation",
    "session_register": "deprecation",
}


class TreeSitterAnalyzer:
    """PHP code analyzer using tree-sitter for accurate AST parsing.

    Provides the same ``PHPFileAST`` output as ``PHPParser`` but using
    real parse trees instead of regular expressions.
    """

    def __init__(self) -> None:
        self._language = _get_php_language()
        self._parser = tree_sitter.Parser(self._language)

    def parse_file(self, file_path: Path, root: Path) -> PHPFileAST:
        """Parse a PHP file into a PHPFileAST.

        API-compatible with ``PHPParser.parse_file()``.

        Args:
            file_path: Absolute path to PHP file
            root: Project root for computing relative paths

        Returns:
            PHPFileAST with classes, functions, security patterns, etc.
        """
        try:
            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path)

        ast = PHPFileAST(path=rel_path)

        try:
            content_bytes = file_path.read_bytes()
            content = content_bytes.decode("utf-8", errors="replace")
            ast.raw_content = content
        except Exception as e:
            ast.error = str(e)
            return ast

        # Parse with tree-sitter
        tree = self._parser.parse(content_bytes)
        root_node = tree.root_node

        # Check for parse errors
        if root_node.has_error:
            logger.debug("tree-sitter parse errors in %s", rel_path)
            # Continue anyway — tree-sitter is error-tolerant

        # Walk the AST
        self._extract_namespace(root_node, content_bytes, ast)
        self._extract_use_statements(root_node, content_bytes, ast)
        self._extract_includes(root_node, content_bytes, ast)
        self._extract_classes(root_node, content_bytes, ast)
        self._extract_functions(root_node, content_bytes, ast)
        self._extract_constants(root_node, content_bytes, ast)
        self._extract_sql_queries(root_node, content_bytes, ast)
        self._extract_security_patterns(root_node, content_bytes, ast)

        # Token statistics
        ast.total_tokens = self._count_tokens(root_node)
        ast.token_distribution = self._compute_token_distribution(
            root_node, content_bytes
        )

        return ast

    def parse_directory(self, root: Path) -> list[PHPFileAST]:
        """Parse all PHP files in a directory.

        API-compatible with ``PHPParser.parse_directory()``.
        """
        results: list[PHPFileAST] = []
        _skip = get_skip_dirs()

        for pattern in ("*.php", "*.inc"):
            for fp in sorted(root.rglob(pattern)):
                parts = fp.relative_to(root).parts
                if any(p in _skip for p in parts):
                    continue
                results.append(self.parse_file(fp, root))
        return results

    def compute_complexity(self, node: tree_sitter.Node) -> int:
        """Compute McCabe cyclomatic complexity for a function/method body.

        Unlike the regex-based approach this ONLY counts actual control
        flow — matches inside strings and comments are correctly ignored.
        """
        complexity = 1  # base path

        def _walk(n: tree_sitter.Node) -> None:
            nonlocal complexity

            if n.type in _COMPLEXITY_NODES:
                if n.type == "binary_expression":
                    # Only count && and ||
                    op_node = n.child_by_field_name("operator")
                    if op_node:
                        op_text = self._node_text(op_node, b"")
                        if op_text in _COMPLEXITY_OPERATORS:
                            complexity += 1
                else:
                    complexity += 1

            for child in n.children:
                _walk(child)

        _walk(node)
        return complexity

    # ───────────────────────────────────────────────────────────────────
    # AST extraction methods
    # ───────────────────────────────────────────────────────────────────

    def _extract_namespace(
        self, root: tree_sitter.Node, src: bytes, ast: PHPFileAST
    ) -> None:
        """Extract namespace declaration."""
        for node in self._find_nodes(root, "namespace_definition"):
            name_node = node.child_by_field_name("name")
            if name_node:
                ast.namespace = self._node_text(name_node, src)

    def _extract_use_statements(
        self, root: tree_sitter.Node, src: bytes, ast: PHPFileAST
    ) -> None:
        """Extract use/import statements."""
        for node in self._find_nodes(root, "namespace_use_declaration"):
            for clause in self._find_nodes(node, "namespace_use_clause"):
                fqn = self._node_text(clause, src)
                # Strip leading backslash and "use" keyword artifacts
                fqn = fqn.strip().lstrip("\\")
                alias = ""
                alias_node = clause.child_by_field_name("alias")
                if alias_node:
                    alias = self._node_text(alias_node, src)
                ast.use_statements.append({
                    "fqn": fqn,
                    "alias": alias,
                    "line": node.start_point[0] + 1,
                })

    def _extract_includes(
        self, root: tree_sitter.Node, src: bytes, ast: PHPFileAST
    ) -> None:
        """Extract include/require statements."""
        include_types = {
            "include_expression", "include_once_expression",
            "require_expression", "require_once_expression",
        }
        for node in self._find_all_types(root, include_types):
            path_str = ""
            # The argument is typically a string node
            for child in node.children:
                if child.type in ("string", "encapsed_string"):
                    path_str = self._node_text(child, src).strip("'\"")
                    break
            if path_str:
                ast.includes.append({
                    "path": path_str,
                    "line": node.start_point[0] + 1,
                })

    def _extract_classes(
        self, root: tree_sitter.Node, src: bytes, ast: PHPFileAST
    ) -> None:
        """Extract class, interface, and trait declarations."""
        class_types = {
            "class_declaration", "interface_declaration", "trait_declaration",
        }
        for node in self._find_all_types(root, class_types):
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue

            cls = PHPClass(
                name=self._node_text(name_node, src),
                line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                namespace=ast.namespace,
                is_interface=node.type == "interface_declaration",
                is_trait=node.type == "trait_declaration",
            )

            # Modifiers (abstract, final)
            for child in node.children:
                text = self._node_text(child, src)
                if text == "abstract":
                    cls.is_abstract = True
                elif text == "final":
                    cls.is_final = True

            # Extends
            base_node = node.child_by_field_name("base_clause")
            if base_node is None:
                # Some tree-sitter-php versions use different field names
                for child in node.children:
                    if child.type == "base_clause":
                        base_node = child
                        break
            if base_node:
                for child in base_node.children:
                    if child.type == "name" or child.type == "qualified_name":
                        cls.extends = self._node_text(child, src)
                        break

            # Implements
            impl_node = node.child_by_field_name("interfaces")
            if impl_node is None:
                for child in node.children:
                    if child.type == "class_interface_clause":
                        impl_node = child
                        break
            if impl_node:
                for child in impl_node.children:
                    if child.type in ("name", "qualified_name"):
                        cls.implements.append(self._node_text(child, src))

            # PHPDoc
            cls.phpdoc = self._find_preceding_comment(node, src)

            # Methods
            body_node = node.child_by_field_name("body")
            if body_node is None:
                for child in node.children:
                    if child.type == "declaration_list":
                        body_node = child
                        break

            if body_node:
                for method_node in self._find_nodes(body_node, "method_declaration"):
                    func = self._parse_function_node(method_node, src)
                    if func:
                        cls.methods.append(func)

                # Properties
                for prop_node in self._find_nodes(body_node, "property_declaration"):
                    for prop_elem in self._find_nodes(prop_node, "property_element"):
                        var_node = prop_elem.child_by_field_name("name")
                        if var_node is None:
                            for child in prop_elem.children:
                                if child.type == "variable_name":
                                    var_node = child
                                    break
                        if var_node:
                            cls.properties.append({
                                "name": self._node_text(var_node, src),
                                "line": prop_node.start_point[0] + 1,
                            })

            ast.classes.append(cls)

    def _extract_functions(
        self, root: tree_sitter.Node, src: bytes, ast: PHPFileAST
    ) -> None:
        """Extract top-level function declarations (not methods)."""
        for node in root.children:
            if hasattr(node, "type") and node.type == "function_definition":
                func = self._parse_function_node(node, src)
                if func:
                    ast.functions.append(func)
            # Also handle program > expression_statement wrapping
            if node.type == "php_tag" or node.type == "text":
                continue
            # Recurse into program-level nodes but NOT class bodies
            if node.type not in (
                "class_declaration", "interface_declaration",
                "trait_declaration",
            ):
                for child in node.children:
                    if child.type == "function_definition":
                        func = self._parse_function_node(child, src)
                        if func:
                            ast.functions.append(func)

    def _extract_constants(
        self, root: tree_sitter.Node, src: bytes, ast: PHPFileAST
    ) -> None:
        """Extract constant definitions (const and define())."""
        # const FOO = ...
        for node in self._find_nodes(root, "const_declaration"):
            for elem in node.children:
                if elem.type == "const_element":
                    name_node = elem.child_by_field_name("name")
                    val_node = elem.child_by_field_name("value")
                    if name_node:
                        ast.constants.append({
                            "name": self._node_text(name_node, src),
                            "value": self._node_text(val_node, src) if val_node else "",
                            "line": node.start_point[0] + 1,
                        })

        # define('FOO', ...)
        for node in self._find_nodes(root, "function_call_expression"):
            fn_node = node.child_by_field_name("function")
            if fn_node and self._node_text(fn_node, src).lower() == "define":
                args_node = node.child_by_field_name("arguments")
                if args_node and args_node.named_child_count >= 2:
                    name_arg = args_node.named_children[0]
                    val_arg = args_node.named_children[1]
                    ast.constants.append({
                        "name": self._node_text(name_arg, src).strip("'\""),
                        "value": self._node_text(val_arg, src),
                        "line": node.start_point[0] + 1,
                    })

    def _extract_sql_queries(
        self, root: tree_sitter.Node, src: bytes, ast: PHPFileAST
    ) -> None:
        """Detect SQL query strings in the AST by examining string nodes."""
        sql_keywords = re.compile(
            r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\b",
            re.IGNORECASE,
        )
        for node in self._find_all_types(root, {"string", "encapsed_string"}):
            text = self._node_text(node, src)
            match = sql_keywords.search(text)
            if match and len(text) > 10:
                ast.sql_queries.append({
                    "type": match.group(1).upper(),
                    "line": node.start_point[0] + 1,
                    "snippet": text[:100],
                })

    def _extract_security_patterns(
        self, root: tree_sitter.Node, src: bytes, ast: PHPFileAST
    ) -> None:
        """Detect security-relevant patterns using AST-aware analysis.

        Unlike regex, this correctly skores:
            - Function calls (eval, exec, etc.) — only real calls, not strings
            - Variable references ($_GET, $_POST) in dangerous contexts
            - Hardcoded credentials in assignments
        """
        # Dangerous function calls
        for node in self._find_nodes(root, "function_call_expression"):
            fn_node = node.child_by_field_name("function")
            if fn_node:
                fn_name = self._node_text(fn_node, src).lower()
                if fn_name in _DANGEROUS_FUNCTIONS:
                    pattern_type = _DANGEROUS_FUNCTIONS[fn_name]
                    ast.security_patterns.append({
                        "type": pattern_type,
                        "line": node.start_point[0] + 1,
                        "snippet": self._node_text(node, src)[:80],
                    })

        # Superglobal usage in echo (XSS risk)
        for node in self._find_nodes(root, "echo_statement"):
            echo_text = self._node_text(node, src)
            if re.search(r"\$_(?:GET|POST|REQUEST|COOKIE)", echo_text):
                ast.security_patterns.append({
                    "type": "xss_risk",
                    "line": node.start_point[0] + 1,
                    "snippet": echo_text[:80],
                })

        # File upload handling
        for node in self._find_nodes(root, "subscript_expression"):
            text = self._node_text(node, src)
            if "$_FILES" in text:
                ast.security_patterns.append({
                    "type": "file_upload_risk",
                    "line": node.start_point[0] + 1,
                    "snippet": text[:80],
                })

        # Dynamic includes (file inclusion risk)
        include_types = {
            "include_expression", "include_once_expression",
            "require_expression", "require_once_expression",
        }
        for node in self._find_all_types(root, include_types):
            # Check if argument contains a variable (dynamic include)
            for child in node.children:
                if child.type == "variable_name" or (
                    child.type == "subscript_expression"
                ):
                    ast.security_patterns.append({
                        "type": "file_inclusion_risk",
                        "line": node.start_point[0] + 1,
                        "snippet": self._node_text(node, src)[:80],
                    })
                    break

        # Hardcoded credentials in assignments
        cred_pattern = re.compile(
            r"(?:password|passwd|secret|api_key|token)", re.IGNORECASE
        )
        for node in self._find_nodes(root, "assignment_expression"):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right:
                left_text = self._node_text(left, src)
                if cred_pattern.search(left_text) and right.type == "string":
                    right_text = self._node_text(right, src)
                    if len(right_text) > 5:  # non-trivial value
                        ast.security_patterns.append({
                            "type": "hardcoded_credential",
                            "line": node.start_point[0] + 1,
                            "snippet": f"{left_text} = {right_text[:40]}",
                        })

    # ───────────────────────────────────────────────────────────────────
    # Helpers
    # ───────────────────────────────────────────────────────────────────

    def _parse_function_node(
        self, node: tree_sitter.Node, src: bytes
    ) -> PHPFunction | None:
        """Parse a function/method node into a PHPFunction."""
        name_node = node.child_by_field_name("name")
        if not name_node:
            return None

        func = PHPFunction(
            name=self._node_text(name_node, src),
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
        )

        # Visibility and modifiers
        for child in node.children:
            text = self._node_text(child, src)
            if text in ("public", "private", "protected"):
                func.visibility = text
            elif text == "static":
                func.is_static = True
            elif text == "abstract":
                func.is_abstract = True

        # Parameters
        params_node = node.child_by_field_name("parameters")
        if params_node:
            func.parameters = self._parse_parameters_node(params_node, src)

        # Return type
        ret_node = node.child_by_field_name("return_type")
        if ret_node:
            func.return_type = self._node_text(ret_node, src).lstrip(": ")

        # PHPDoc
        func.phpdoc = self._find_preceding_comment(node, src)

        # Body and complexity
        body_node = node.child_by_field_name("body")
        if body_node:
            func.body_lines = body_node.end_point[0] - body_node.start_point[0] + 1
            func.complexity = self.compute_complexity(body_node)

        return func

    def _parse_parameters_node(
        self, params_node: tree_sitter.Node, src: bytes
    ) -> list[dict[str, Any]]:
        """Parse function parameters from AST."""
        params: list[dict[str, Any]] = []
        for child in params_node.named_children:
            if child.type in ("simple_parameter", "variadic_parameter"):
                p: dict[str, Any] = {"raw": self._node_text(child, src)}
                # Type
                type_node = child.child_by_field_name("type")
                p["type"] = self._node_text(type_node, src) if type_node else ""
                # Name
                name_node = child.child_by_field_name("name")
                p["name"] = self._node_text(name_node, src) if name_node else ""
                # Default
                default_node = child.child_by_field_name("default_value")
                p["default"] = (
                    self._node_text(default_node, src) if default_node else ""
                )
                params.append(p)
        return params

    def _find_preceding_comment(
        self, node: tree_sitter.Node, src: bytes
    ) -> str:
        """Find PHPDoc comment immediately before a declaration node."""
        prev = node.prev_named_sibling
        if prev and prev.type == "comment":
            text = self._node_text(prev, src)
            if text.startswith("/**"):
                return text
        return ""

    @staticmethod
    def _node_text(node: tree_sitter.Node, src: bytes) -> str:
        """Extract text content of a tree-sitter node."""
        if node is None:
            return ""
        # tree-sitter 0.23+ stores text directly on node if source provided
        if hasattr(node, "text") and node.text is not None:
            return node.text.decode("utf-8", errors="replace")
        if src:
            return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        return ""

    def _find_nodes(
        self, root: tree_sitter.Node, node_type: str
    ) -> list[tree_sitter.Node]:
        """Recursively find all nodes with a given type."""
        results: list[tree_sitter.Node] = []

        def _walk(node: tree_sitter.Node) -> None:
            if node.type == node_type:
                results.append(node)
            for child in node.children:
                _walk(child)

        _walk(root)
        return results

    def _find_all_types(
        self, root: tree_sitter.Node, types: set[str]
    ) -> list[tree_sitter.Node]:
        """Find all nodes matching any of the given types."""
        results: list[tree_sitter.Node] = []

        def _walk(node: tree_sitter.Node) -> None:
            if node.type in types:
                results.append(node)
            for child in node.children:
                _walk(child)

        _walk(root)
        return results

    def _count_tokens(self, root: tree_sitter.Node) -> int:
        """Count named nodes (roughly equivalent to token count)."""
        count = 0

        def _walk(node: tree_sitter.Node) -> None:
            nonlocal count
            if node.is_named and not node.children:
                count += 1
            for child in node.children:
                _walk(child)

        _walk(root)
        return count

    def _compute_token_distribution(
        self, root: tree_sitter.Node, src: bytes
    ) -> dict[str, int]:
        """Compute distribution of token types from AST nodes.

        Uses actual AST node types instead of regex — far more accurate
        than the regex-based approach.
        """
        dist: dict[str, int] = {
            "keywords": 0,
            "variables": 0,
            "strings": 0,
            "numbers": 0,
            "operators": 0,
            "comments": 0,
        }

        keyword_types = frozenset({
            "if", "else", "elseif", "while", "for", "foreach", "do",
            "switch", "case", "break", "continue", "return", "function",
            "class", "interface", "trait", "abstract", "final", "static",
            "public", "private", "protected", "new", "try", "catch",
            "throw", "finally", "namespace", "use", "extends", "implements",
            "echo", "print", "array", "list", "isset", "unset", "empty",
            "null", "true", "false", "const",
        })

        def _walk(node: tree_sitter.Node) -> None:
            if node.type == "comment":
                dist["comments"] += 1
            elif node.type == "variable_name":
                dist["variables"] += 1
            elif node.type in ("string", "encapsed_string", "heredoc", "nowdoc"):
                dist["strings"] += 1
            elif node.type in ("integer", "float"):
                dist["numbers"] += 1
            elif node.type in (
                "binary_expression", "unary_op_expression",
                "assignment_expression",
            ):
                dist["operators"] += 1
            elif not node.is_named:
                text = self._node_text(node, src).lower()
                if text in keyword_types:
                    dist["keywords"] += 1

            for child in node.children:
                _walk(child)

        _walk(root)
        return dist
