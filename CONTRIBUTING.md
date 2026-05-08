# Contributing to REDACTS

[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg)](https://github.com/The-Adimension/REDACTS/pulls)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-649_passing-brightgreen?logo=pytest&logoColor=white)](tests/)

Thank you for your interest in improving REDACTS. This project exists to protect research institutions running REDCap, and every contribution matters.

> **Note:** REDACTS is a forensic analysis aid - it assists investigators but does not replace thorough manual review. Contributions should maintain this expectation in all user-facing output, documentation, and reports.
>
> (c) 2024-2026 The Adimension / Shehab Anwer - <atrium@theadimension.com>

## Getting Started

```bash
git clone https://github.com/The-Adimension/REDACTS.git
cd REDACTS
python -m venv .venv
.venv\Scripts\activate       # Windows
source .venv/bin/activate    # Linux/macOS
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Running Tests

```bash
python -m pytest tests/ -x -q
```

All 649 tests must pass before submitting a pull request (5 are skipped
by design - they exercise platform-conditional paths).

## Code Style

- Python 3.12+ with type hints on all public APIs
- `from __future__ import annotations` in every module
- Docstrings on every public class and function
- No wildcard imports
- `black` for formatting, `ruff` for linting, `mypy` for type checking

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Write tests for any new functionality
3. Run the full test suite - it must pass with zero failures
4. Update documentation if you changed public APIs
5. Open a pull request with a clear description of what changed and why

## Architecture Overview

REDACTS is **contract-driven**. A single `case.toml` file at the repo
root (or a path passed via `--case`) is loaded, validated, and frozen
into a `FrozenCaseContract` at process startup
([static/core/contract.py](static/core/contract.py)). The contract is
installed on a process-wide runtime context
([static/core/runtime_context.py](static/core/runtime_context.py)) and
is the **only** source of configuration for downstream code. Child
processes receive a curated environment built by
[static/core/subprocess_env.py](static/core/subprocess_env.py) from
the same contract - production code never reads `os.environ` for
behaviour-affecting values.

This invariant is mechanically enforced by
[scripts/check_no_env_reads.py](scripts/check_no_env_reads.py), an AST
linter that scans `static/`, `dynamic/`, and
`threat_base/` for `os.environ` / `os.getenv` access. The allowlist is
the small set of files that legitimately bridge the contract to the
OS:

- `static/core/contract.py` (loader)
- `static/core/subprocess_env.py` (child-env builder)
- `static/core/paths.py` (PATH injection only)
- `dynamic/helpers/_runtime_env.py` (test-runner shim)

If you add a new module that needs to read an env var, do not append
to the allowlist - instead, surface the value through `case.toml` and
`FrozenCaseContract`. PRs that broaden the allowlist without an
explicit design discussion will be declined.

The CLI surface is intentionally minimal and **non-interactive**:
`main.py` builds an `argparse` tree (`scan` / `preflight` / `update`
/ `paths` / `secrets`).
The scan flow does not prompt; if `case.toml` is missing it aborts
with `exit 2`. The only intentionally interactive surface is
`secrets set` (uses `getpass`) and `update` (gated by `--no-confirm`).

Packages:

| Package        | Purpose                                                                              |
|----------------|----------------|
| `static/core/` | Contract, runtime context, paths, findings model, hashing, logging, sandbox         |
| `static/cli/`  | Console UI, workflow orchestration, preflight (no prompts in scan flow)             |
| `static/collect/` | Evidence loading (ZIP/HTTP/FTP/local), manifests, provenance                     |
| `static/audit/` | Baseline-driven audit pipeline and structural diffing                              |
| `static/analyze/` | Investigation steps, security rules, file/DB/upgrade analysis                    |
| `static/scanners/` | External tool adapters (Semgrep, Trivy, YARA, Magika, tree-sitter)              |
| `threat_base/` | ATT&CK vectors, CWE database, IoCs, NVD client                                      |
| `static/report/` | Report generation (HTML/JSON/MD) and SARIF v2.1.0 export                          |
| `dynamic/`     | Docker/Podman + Playwright dynamic analysis                                         |

Tests mirror the source tree: `tests/core/`, `tests/cli/`,
`tests/collect/`, `tests/dast/`, etc.

## What to Contribute

- New security rules for emerging REDCap threats
- Improved INFINITERED detection signatures
- DAST test specs for additional attack surfaces
- Loader support for new source formats
- Report renderer plugins
- Documentation and examples

## Reporting Vulnerabilities

If you discover a security vulnerability in REDACTS itself, please do **not** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code of Conduct

Be respectful, be constructive, be patient. We're all here to protect research data.
