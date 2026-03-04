# Contributing to REDACTS

[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg)](https://github.com/The-Adimension/REDACTS/pulls)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-321_passing-brightgreen?logo=pytest&logoColor=white)](tests/)

Thank you for your interest in improving REDACTS. This project exists to protect research institutions running REDCap, and every contribution matters.

> **Note:** REDACTS is a forensic analysis aid — it assists investigators but does not replace thorough manual review. Contributions should maintain this expectation in all user-facing output, documentation, and reports.
>
> © 2024–2026 The Adimension / Shehab Anwer — <atrium@theadimension.com>

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

All 321 tests must pass before submitting a pull request.

## Code Style

- Python 3.11+ with type hints on all public APIs
- `from __future__ import annotations` in every module
- Docstrings on every public class and function
- No wildcard imports
- `black` for formatting, `ruff` for linting, `mypy` for type checking

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Write tests for any new functionality
3. Run the full test suite — it must pass with zero failures
4. Update documentation if you changed public APIs
5. Open a pull request with a clear description of what changed and why

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
