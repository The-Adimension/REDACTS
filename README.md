## Disclaimer

> **REDACTS is a forensic analysis _aid_.** It is designed to assist security teams in investigating REDCap installations, but it **does not replace** and **cannot substitute for** thorough manual review by qualified professionals. Scan results are **not guaranteed** to be complete or definitive — false positives and false negatives are possible. Use REDACTS as an **auxiliary tool** within your incident response workflow, **not** as the sole basis for security decisions.
>
> REDACTS does **not** modify, patch, or alter the files it scans. It is not affiliated with or endorsed by Vanderbilt University or the REDCap Consortium. REDCap® is a registered trademark of Vanderbilt University.
>
> **If you discover evidence of compromise, contact your security team and the [REDCap Consortium](https://projectredcap.org) immediately.**
>
> © 2024–2026 The Adimension / Shehab Anwer — <atrium@theadimension.com>

# REDACTS | **REDCap Arbitrary Code Threat Scan**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/Version-2.0.0-green.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/Tests-321_passing-brightgreen?logo=pytest&logoColor=white)](tests/)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-orange?logo=github&logoColor=white)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-20_Techniques-red?logo=shield&logoColor=white)](https://attack.mitre.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#quick-start)
[![Security Rules](https://img.shields.io/badge/Security_Rules-57-critical)](#security-rules)

A forensic security scanner purpose-built for [REDCap](https://projectredcap.org) installations. REDACTS performs baseline-driven differential analysis to detect tampering, backdoors, and active threats — including the [INFINITERED](https://projectredcap.org/resources/blog/) malware campaign discovered in February 2026.

> **By [The Adimension](https://github.com/The-Adimension) — developed by Shehab Anwer**

---

## Why REDACTS Exists

REDCap powers clinical research at thousands of institutions worldwide. In early 2026, the INFINITERED campaign demonstrated that dedicated attackers are actively targeting REDCap servers with custom exploits that persist across upgrades. Manual `grep` commands and ad-hoc checksums are insufficient for this threat.

REDACTS automates the forensic workflow: compare your running installation against a known-good reference, flag every deviation, and produce audit-ready reports — all without modifying your server.

---

## How It Works

REDACTS runs a guided interactive workflow from the command line. It walks you through each step with prompts — no complex flags required.

### Pipeline Phases

1. **Evidence Collection** — Loads your REDCap files (ZIP, 7z, RAR, local directory, HTTP, or FTP/SFTP), builds SHA-256 file manifests, and classifies every file using Google Magika AI.
2. **Baseline Diffing** — Compares the target against a clean reference. Files with identical hashes are skipped, focusing analysis on actual deviations only.
3. **Deep Forensics** — Runs 57 security rules, tree-sitter PHP AST analysis, 17 IoC indicators, 34 attack vector assessments, and sensitive data detection — scoped to the modified/added file set only.
4. **External Tool Enrichment** — Invokes Semgrep, Trivy, and YARA (all auto-installed on first run). Optionally runs PHP lint, Lizard complexity analysis, and Radon maintainability scoring if available on the system.
5. **DAST (Dynamic Analysis)** — Playwright-driven browser testing against a live REDCap instance running in Docker. Tests authentication boundaries, upgrade integrity, and export security. _Requires Docker and Node.js._
6. **Reporting** — Generates HTML, JSON, Markdown, and SARIF v2.1.0 output.

### Pipeline Diagram

```
Reference ZIP ──┐
                 ├── Phase 1: Build SHA-256 manifests
Target files ───┘
                     │
                 Phase 2: Structural diff (added / removed / matched)
                     │
                 Phase 3: Hash comparison
                     │         │
                  identical   MODIFIED + ADDED
                  (skip)         │
                           Phase 4: Deep forensic scan
                                 │
                           ┌─────┴──────┐
                           │ 57 rules   │
                           │ AST parse  │
                           │ IoC match  │
                           │ Semgrep    │
                           │ Trivy      │
                           │ YARA       │
                           └─────┬──────┘
                                 │
                           Reports (HTML/JSON/MD/SARIF)
```

---

## INFINITERED Detection

[![INFINITERED](https://img.shields.io/badge/INFINITERED-Active_Threat-red?logo=bitwarden&logoColor=white)](#infinitered-detection)
[![IoCs](https://img.shields.io/badge/IoCs-17_Indicators-orange)](#infinitered-detection)

REDACTS includes dedicated detection capabilities for the INFINITERED malware campaign:

| Rule ID | What It Detects | Severity |
|---------|----------------|----------|
| `SEC060` | `REDCAP-TOKEN` marker string in PHP files | CRITICAL |
| `SEC061` | `eval(gzinflate(base64_decode()))` obfuscation chain | CRITICAL |
| `SEC062` | `redcap.db` SQLite persistence artifact reference | HIGH |
| `IOC-INF-001` | `redcap.db` file presence (SQLite C2/persistence layer) | CRITICAL |
| `IOC-INF-002` | SQLite WAL/journal sidecars (proves active database writes) | CRITICAL |
| `IOC-INF-003` | Injected functions in `hook_functions.php` not matching known REDCap hooks | CRITICAL |
| `IOC-INF-004` | `eval(gzinflate(base64_decode()))` payload delivery pattern | CRITICAL |

**Baseline Validator** classifies these files as CRITICAL integrity targets:

- `Hooks.php` — "primary INFINITERED persistence target"
- `Upgrade.php` — "persistent compromise indicator"
- `Authentication.php` / `auth_functions.php` — "credential-theft risk"
- `.htaccess` — "check for auto_prepend_file persistence"
- `.user.ini` — "PHP runtime persistence"

**Upgrade Hijacking** — 11 rules (`UPG001`, `UPG002`, `UPG003`, `UPG010`, `UPG011`, `UPG020`, `UPG021`, `UPG030`, `UPG031`, `UPG040`, `UPG050`) detect persistence injection, file deletion bypass, skip logic, obfuscation, and config tampering in upgrade scripts.

**MITRE ATT&CK Mapping** — Findings are mapped to 20 technique IDs across 8 tactics, including T1505.003 (Web Shell), T1195 (Supply Chain Compromise), T1546 (Event Triggered Execution), and T1027 (Obfuscated Files).

---

## Quick Start

### Requirements

| Requirement | Version | Purpose | Download |
|-------------|---------|---------|----------|
| [Python](https://www.python.org/downloads/) | 3.11+ | Core runtime | [python.org](https://www.python.org/downloads/) |
| [Docker](https://docs.docker.com/get-docker/) | Any recent | DAST phase only | [docs.docker.com](https://docs.docker.com/get-docker/) |
| [Docker Compose](https://docs.docker.com/compose/install/) | v2+ | DAST phase only | [docs.docker.com](https://docs.docker.com/compose/install/) |
| [Node.js](https://nodejs.org/) | 18+ | DAST phase only | [nodejs.org](https://nodejs.org/en/download/) |

### Install

```bash
# Clone the repository
git clone https://github.com/The-Adimension/REDACTS.git
cd REDACTS

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

# Install Python dependencies
pip install -r requirements.txt
```

On first run, REDACTS automatically downloads and installs **Semgrep**, **Trivy**, and **YARA** if they are not already present. System tools are cached in `~/.redacts/tools/` and persist across virtual environment rebuilds. You can override this path with the `REDACTS_TOOLS_DIR` environment variable.

### Run a Scan

REDACTS uses an interactive guided workflow:

```bash
python -m REDACTS
```

The CLI will:

1. Display a banner with version information
2. Check and report on all dependencies
3. Auto-install any missing Python packages
4. Prompt you for the **target** REDCap files to scan (path to ZIP, directory, URL, or FTP address)
5. Prompt you for the **reference** REDCap package (clean download from the REDCap Consortium)
6. Execute the full scan pipeline and generate reports

Use `python -m REDACTS --help` for usage information.

> **Note:** The CLI is interactive-only. There is no non-interactive/headless mode with command-line flags at this time.

### Run DAST (Dynamic Analysis)

The DAST phase requires Docker and Node.js. It spins up a containerized REDCap instance (MariaDB + Apache/PHP) and runs Playwright browser tests against it.

```bash
cd dast
npm install
docker compose -f docker-compose.dast.yml up -d
npx playwright test
```

> **Note:** The Docker Compose stack requires a REDCap installation image. Since REDCap is proprietary software distributed only to consortium members, you must supply your own REDCap Docker image or build configuration.

### Run Tests

```bash
python -m pytest tests/ -x -q
```

The test suite contains 321 tests.

---

## Project Structure

```
REDACTS/
├── __main__.py                 # Interactive CLI entry point
├── __init__.py                 # Package metadata (v2.0.0)
├── audit/
│   └── pipeline.py             # 4-phase baseline-driven audit pipeline
├── core/
│   ├── config.py               # Typed configuration dataclasses
│   ├── constants.py            # Canonical version string
│   ├── dependencies.py         # Dependency checker and auto-installer
│   ├── models.py               # Unified finding model (SARIF/CVSS/CWE/MITRE)
│   └── logging_setup.py        # Logging configuration
├── dast/
│   ├── orchestrator.py         # Docker Compose + Playwright orchestration
│   ├── docker-compose.dast.yml # REDCap + MariaDB + Playwright stack
│   ├── docker-compose.crawlmaze.yml  # Google Crawl Maze benchmark stack
│   ├── Dockerfile.playwright   # Playwright test runner container
│   ├── Dockerfile.crawlmaze    # Crawl Maze container
│   ├── playwright.config.ts    # Playwright configuration
│   ├── tests/                  # 4 Playwright spec files (102 test cases)
│   │   ├── admin-access.spec.ts       # Auth boundary tests (10)
│   │   ├── crawlmaze-coverage.spec.ts # Crawl Maze benchmark (76)
│   │   ├── export-report.spec.ts      # Data export security (6)
│   │   └── upgrade-flow.spec.ts       # Upgrade integrity tests (10)
│   └── helpers/                # Shared test utilities
│       ├── auth.ts             # REDCap authentication helper
│       ├── security-assertions.ts  # Security check assertions
│       ├── filesystem-snapshot.ts  # File snapshot and diff
│       └── network-monitor.ts  # Network traffic monitoring
├── evidence/
│   ├── collector.py            # Evidence package builder
│   └── manifest.py             # File manifest with SHA-256 hashing
├── forensics/
│   ├── baseline_validator.py   # Structural diff + integrity checking
│   ├── security_scanner.py     # Security rule engine
│   ├── security_rules.py       # 57 PHP security rule definitions
│   ├── tree_sitter_analyzer.py # PHP AST analysis via tree-sitter
│   ├── upgrade_analyzer.py     # 11 upgrade hijacking detection rules
│   ├── file_analyzer.py        # Hashing, entropy, Magika classification
│   ├── magika_analyzer.py      # Google Magika integration
│   └── database_forensics.py   # Database artifact analysis
├── integration/
│   └── repomix.py              # Repomix codebase snapshot integration
├── investigation/
│   ├── investigator.py         # 7-step investigation orchestrator
│   ├── semgrep_adapter.py      # Semgrep CLI adapter
│   ├── trivy_adapter.py        # Trivy CLI adapter
│   └── external_tools.py       # External tool runner
├── knowledge/
│   ├── attack_vectors.py       # 34 attack vectors across 7 categories
│   ├── ioc_database.py         # 17 Indicators of Compromise
│   ├── mitre_mapping.py        # 20 MITRE ATT&CK technique mappings
│   └── sensitive_data.py       # PHI/PII/credential detection patterns
├── loaders/
│   ├── base.py                 # Loader protocol + auto-detection
│   ├── zip_loader.py           # ZIP, 7z, RAR, tar.gz, tar.bz2, tar.xz
│   ├── local_loader.py         # Local directory loading
│   ├── http_loader.py          # HTTP/HTTPS download
│   └── ftp_loader.py           # FTP/SFTP loading (via Paramiko)
├── orchestration/
│   └── tool_orchestrator.py    # External tool coordination
├── reporting/
│   ├── forensic_report.py      # Report generator with pluggable renderers
│   ├── sarif_exporter.py       # SARIF v2.1.0 exporter
│   └── renderers/              # HTML, JSON, Markdown renderer plugins
├── sandbox/
│   └── isolation.py            # Integrity checking utilities
└── tests/                      # 321 pytest tests
```

---

## Output Formats

[![SARIF v2.1.0](https://img.shields.io/badge/SARIF-v2.1.0-orange?logo=github&logoColor=white)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![HTML](https://img.shields.io/badge/HTML-Report-E34F26?logo=html5&logoColor=white)](#output-formats)
[![JSON](https://img.shields.io/badge/JSON-Report-000000?logo=json&logoColor=white)](#output-formats)
[![Markdown](https://img.shields.io/badge/Markdown-Report-083fa1?logo=markdown&logoColor=white)](#output-formats)

| Format | Use Case |
|--------|----------|
| **HTML** | Human review — dark-theme, interactive |
| **JSON** | Machine consumption, CI/CD integration |
| **Markdown** | Documentation, pull request comments |
| **SARIF v2.1.0** | GitHub Code Scanning, SonarQube, DefectDojo, Azure DevOps |

SARIF output conforms to the [OASIS SARIF v2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

---

## Dependencies and Third-Party Attributions

[![Dependencies](https://img.shields.io/badge/Dependencies-11_Packages-blue?logo=pypi&logoColor=white)](#python-packages-installed-via-pip)
[![System Tools](https://img.shields.io/badge/System_Tools-2_Required-yellow)](#system-tools-auto-downloaded-on-first-run)
[![Optional Tools](https://img.shields.io/badge/Optional_Tools-8_Available-lightgrey)](#optional-tools-not-auto-installed)

REDACTS relies on the following open-source tools and libraries. All credit to their respective authors and communities.

### Python Packages (installed via pip)

| Package | Min Version | License | Purpose | Links |
|---------|-------------|---------|---------|-------|
| [chardet](https://github.com/chardet/chardet) | 5.0.0 | LGPL-2.1 | Character encoding detection | [PyPI](https://pypi.org/project/chardet/) |
| [magika](https://github.com/google/magika) | 0.6.0 | Apache-2.0 | AI-powered file-type classification by Google | [PyPI](https://pypi.org/project/magika/) |
| [paramiko](https://github.com/paramiko/paramiko) | 3.4.0 | LGPL-2.1 | SSH/SFTP transport for remote file loading | [PyPI](https://pypi.org/project/paramiko/) |
| [requests](https://github.com/psf/requests) | 2.31.0 | Apache-2.0 | HTTP client for loaders and downloads | [PyPI](https://pypi.org/project/requests/) |
| [py7zr](https://github.com/miurahr/py7zr) | 0.20.0 | LGPL-2.1+ | 7-Zip archive extraction | [PyPI](https://pypi.org/project/py7zr/) |
| [rarfile](https://github.com/markokr/rarfile) | 4.1 | ISC | RAR archive extraction | [PyPI](https://pypi.org/project/rarfile/) |
| [rich](https://github.com/Textualize/rich) | 13.0.0 | MIT | Terminal formatting, progress bars, tables | [PyPI](https://pypi.org/project/rich/) |
| [PyYAML](https://github.com/yaml/pyyaml) | 6.0 | MIT | YAML configuration file parsing | [PyPI](https://pypi.org/project/PyYAML/) |
| [tree-sitter](https://github.com/tree-sitter/py-tree-sitter) | 0.23.0 | MIT | Incremental parsing system for AST analysis | [PyPI](https://pypi.org/project/tree-sitter/) |
| [tree-sitter-php](https://github.com/tree-sitter/tree-sitter-php) | 0.23.0 | MIT | PHP grammar for tree-sitter | [PyPI](https://pypi.org/project/tree-sitter-php/) |
| [semgrep](https://github.com/semgrep/semgrep) | 1.0.0 | LGPL-2.1 | AST-based static analysis for PHP vulnerability scanning | [PyPI](https://pypi.org/project/semgrep/) · [semgrep.dev](https://semgrep.dev) |

### System Tools (auto-downloaded on first run)

| Tool | Required | License | Purpose | Download |
|------|:--------:|---------|---------|----------|
| [Trivy](https://github.com/aquasecurity/trivy) | Yes | Apache-2.0 | Filesystem vulnerability and secret scanning | [GitHub Releases](https://github.com/aquasecurity/trivy/releases) · [trivy.dev](https://trivy.dev) |
| [YARA](https://github.com/VirusTotal/yara) | Yes | BSD-3-Clause | Pattern-based malware signature matching | [GitHub Releases](https://github.com/VirusTotal/yara/releases) · [Docs](https://virustotal.github.io/yara/) |

REDACTS auto-downloads Trivy and YARA binaries to `~/.redacts/tools/` on first run. Override with `REDACTS_TOOLS_DIR` environment variable.

### Optional Tools (not auto-installed)

| Tool | License | Purpose | Install |
|------|---------|---------|---------|
| [Docker](https://www.docker.com) | Apache-2.0 | Container runtime for DAST phase | [Get Docker](https://docs.docker.com/get-docker/) |
| [Docker Compose](https://docs.docker.com/compose/) | Apache-2.0 | Multi-container orchestration for DAST | [Install Compose](https://docs.docker.com/compose/install/) |
| [Node.js](https://nodejs.org) | MIT | Required for DAST (Playwright) and Repomix | [Download](https://nodejs.org/en/download/) |
| [Playwright](https://playwright.dev) | Apache-2.0 | Browser automation for DAST testing | `npm install` (in `dast/`) |
| [Repomix](https://github.com/yamadashy/repomix) | MIT | Compressed codebase snapshot for LLM analysis | `npm install -g repomix` |
| [PHP CLI](https://www.php.net) | PHP License | PHP lint syntax checking (enhanced analysis) | [Download](https://www.php.net/downloads) |
| [Lizard](https://github.com/terryyin/lizard) | MIT | Cyclomatic complexity analysis | `pip install lizard` |
| [Radon](https://github.com/rubik/radon) | MIT | Maintainability index metrics | `pip install radon` |

---

## Investigation Steps

When REDACTS runs a deep investigation on the modified/added file set, it executes 7 steps in order:

| # | Step | What It Does |
|---|------|-------------|
| 1 | IoC Scan | Matches files against 17 known Indicators of Compromise |
| 2 | Config Integrity | Checks `database.php`, `.htaccess`, `.user.ini`, `hook_functions.php` |
| 3 | Security Scan | Applies 57 PHP security rules to each file |
| 4 | Sensitive Data | Detects PHI, PII, credentials, API keys |
| 5 | External Tools | Runs Semgrep, Trivy, YARA, PHP lint, Lizard, Radon |
| 6 | Attack Vector | Evaluates exposure to 34 known attack vectors |
| 7 | Risk Calculation | Computes overall risk score from all findings |

---

## Security Rules

REDACTS defines 57 security rules in `forensics/security_rules.py`:

| Range | Count | Severity | Category |
|-------|:-----:|----------|----------|
| SEC001–SEC004 | 4 | CRITICAL | Eval injection, exec, SQL injection, hardcoded credentials |
| SEC010–SEC014 | 5 | HIGH | Dynamic function calls, XSS, echo output, file read/write |
| SEC020–SEC023 | 4 | MEDIUM | LDAP injection, XXE, SSRF, open redirect |
| SEC030–SEC031 | 2 | LOW | Weak cryptography, weak random number generation |
| SEC040–SEC041 | 2 | INFO | Generic backdoor signatures |
| SEC060–SEC069 | 10 | CRITICAL–MEDIUM | INFINITERED IoCs, debug exposure, information disclosure |
| SEC070–SEC079 | 10 | CRITICAL–HIGH | REDCap changelog-disclosed CVE patterns |
| SEC080–SEC099 | 20 | CRITICAL–MEDIUM | Persistence, config tampering, supply chain indicators |

---

## License

Copyright 2024–2026 The Adimension / Shehab Anwer

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

---

## Contact

- **Email:** <atrium@theadimension.com> · <shehab.anwer@gmail.com>
- **GitHub:** [github.com/The-Adimension/REDACTS](https://github.com/The-Adimension/REDACTS)
