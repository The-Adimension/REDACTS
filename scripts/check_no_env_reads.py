#!/usr/bin/env python3
"""AST linter: reject ``os.environ`` and ``os.getenv`` reads in production code.

REDACTS configuration flows through ``case.toml`` -> ``FrozenCaseContract``.
Production code paths under ``static/``, ``dynamic/``, and ``threat_base/``
must not consult environment variables. The bridge between the contract and
the OS is concentrated in a small allowlist of files.

Usage:
    python scripts/check_no_env_reads.py            # exit 1 on violations
    python scripts/check_no_env_reads.py --list     # print allowlist, exit 0

The linter is intended to be run in CI and locally before submitting a PR.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Production trees scanned. Files under any ``tests`` directory segment
# are excluded.
SCAN_ROOTS: tuple[str, ...] = ("static", "dynamic", "threat_base")
TEST_DIR_NAMES: frozenset[str] = frozenset({"tests"})

# Files allowed to bridge the contract to the OS. Adding a new entry
# requires an explicit design discussion.
ALLOWLIST: frozenset[Path] = frozenset(
    {
        Path("static/core/contract.py"),
        Path("static/core/subprocess_env.py"),
        Path("static/core/paths.py"),
        Path("dynamic/helpers/_runtime_env.py"),
    }
)


class EnvReadVisitor(ast.NodeVisitor):
    """Collect ``os.environ`` attribute access and ``os.getenv`` / ``getenv`` calls."""

    def __init__(self) -> None:
        self.hits: list[tuple[int, str]] = []

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "os"
            and node.attr == "environ"
        ):
            self.hits.append((node.lineno, "os.environ"))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
            and func.attr == "getenv"
        ):
            self.hits.append((node.lineno, "os.getenv"))
        elif isinstance(func, ast.Name) and func.id == "getenv":
            self.hits.append((node.lineno, "getenv"))
        self.generic_visit(node)


def _iter_python_files() -> list[Path]:
    files: list[Path] = []
    for root_name in SCAN_ROOTS:
        base = ROOT / root_name
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            rel_parts = set(path.relative_to(ROOT).parts)
            if rel_parts & TEST_DIR_NAMES:
                continue
            files.append(path)
    return files


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv

    if "--list" in args:
        for entry in sorted(ALLOWLIST):
            print(entry.as_posix())
        return 0

    files = _iter_python_files()
    violations: list[str] = []
    for path in files:
        rel = path.relative_to(ROOT)
        if rel in ALLOWLIST:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            violations.append(f"{rel.as_posix()}: parse error: {exc}")
            continue
        visitor = EnvReadVisitor()
        visitor.visit(tree)
        for line, what in visitor.hits:
            violations.append(f"{rel.as_posix()}:{line}: forbidden {what}")

    if violations:
        sys.stderr.write(
            "scripts/check_no_env_reads.py: forbidden environment reads detected\n"
        )
        for entry in violations:
            sys.stderr.write(f"  {entry}\n")
        sys.stderr.write(
            "\nFix: route the value through case.toml and FrozenCaseContract,\n"
            "or extend the allowlist after design review.\n"
        )
        return 1

    print(f"ok: {len(files)} files scanned, allowlist={len(ALLOWLIST)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
