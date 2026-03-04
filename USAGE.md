# REDACTS User Guide

[![Version](https://img.shields.io/badge/Version-2.0.0-green.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Disclaimer

> **REDACTS is a forensic analysis _aid_.** It assists investigators but **does not replace** thorough manual review by qualified security professionals. Results are **not guaranteed** to be complete or definitive — false positives and false negatives are possible. Use REDACTS as an **auxiliary tool** within your incident response workflow, **not** as the sole basis for security decisions. A thorough independent review is required.
>
> © 2024–2026 The Adimension / Shehab Anwer — <atrium@theadimension.com> · <shehab.anwer@gmail.com>

---

## Prerequisites

| Requirement | Minimum | Install |
|-------------|---------|---------|
| Python | 3.11 | [python.org](https://www.python.org/downloads/) |
| pip | any recent | Bundled with Python |

**Optional (DAST phase only):**

| Requirement | Minimum | Install |
|-------------|---------|---------|
| Docker | any recent | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Docker Compose | v2+ | [docs.docker.com](https://docs.docker.com/compose/install/) |
| Node.js | 18+ | [nodejs.org](https://nodejs.org/en/download/) |

You do **not** need to install Semgrep, Trivy, or YARA manually. REDACTS auto-downloads them on first run.

---

## Installation

```bash
git clone https://github.com/The-Adimension/REDACTS.git
cd REDACTS
python -m venv .venv

# Activate the virtual environment
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

---

## Running a Scan

REDACTS is fully interactive. Launch it, answer the prompts, and wait for results.

```bash
python -m REDACTS
```

The workflow proceeds through 5 steps automatically:

### Step 1 — Banner & Version

Displays the REDACTS version banner.

### Step 2 — Dependency Check

Scans your environment and prints a table showing which tools are available and which are missing. Required tools are flagged red; optional tools are flagged yellow.

### Step 3 — Auto-Install Missing Dependencies

Automatically installs any missing Python packages via pip and downloads Trivy + YARA binaries to `~/.redacts/tools/`. If a **required** dependency fails to install, the scan stops here.

### Step 4 — Target Prompt

You are asked for the path to the **REDCap installation to scan** (the files under suspicion).

Accepts:

- Local directory path (e.g., `C:\redcap\server`)
- ZIP / 7z / RAR / tar archive (e.g., `./redcap_v15.7.4-server.zip`)
- HTTP/HTTPS URL (e.g., `https://example.com/redcap.zip`)
- FTP/SFTP URL (e.g., `ftp://server/redcap/`)

### Step 5 — Reference Prompt

You are asked for the path to the **clean/original REDCap package** (the known-good baseline from the REDCap Consortium).

Accepts the same formats as the target prompt.

### Step 6 — Full Scan Pipeline

The scan runs four phases:

| Phase | What Happens |
|-------|-------------|
| **A — Evidence Collection** | Loads all files, computes SHA-256 hashes, classifies file types with Google Magika AI, detects anomalies |
| **B — Baseline Audit** | Structurally diffs target vs. reference. Files with matching hashes are skipped. Modified/added files are deep-scanned with 57 security rules, tree-sitter AST analysis, 17 IoC checks, and 34 attack vector assessments |
| **C — Tool Orchestration** | Runs Semgrep, Trivy, YARA, Magika, and tree-sitter on the delta file set only |
| **D — Report Generation** | Produces HTML, JSON, Markdown, and SARIF v2.1.0 reports |

Progress and findings are printed to terminal as each phase completes.

---

## Output

Reports are written to `output/scan_YYYYMMDD_HHMMSS/` inside the project directory.

```
output/scan_20260304_143022/
├── audit/                      # Baseline diff + investigation results
├── redacts_forensic_*.html     # Human-readable dark-theme report
├── redacts_forensic_*.json     # Machine-readable findings
├── redacts_forensic_*.md       # Markdown report
└── redacts_sarif_*.json        # SARIF v2.1.0 (GitHub Code Scanning compatible)
```

Override the output location with the `REDACTS_OUTPUT_DIR` environment variable.

---

## SARIF Integration

The SARIF output can be uploaded to:

- **GitHub Code Scanning** — via the `upload-sarif` action
- **SonarQube** — import as external issue
- **DefectDojo** — SARIF parser
- **Azure DevOps** — Advanced Security SARIF import

---

## Configuration

REDACTS works with zero configuration. All defaults are production-ready.

### Environment Variables

| Variable | Default | Effect |
|----------|---------|--------|
| `REDACTS_OUTPUT_DIR` | `./output` | Report output directory |
| `REDACTS_LOG_LEVEL` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `REDACTS_VERBOSE` | `false` | Enable verbose terminal output |
| `REDACTS_TOOLS_DIR` | `~/.redacts/tools/` | Where auto-downloaded system tools (Trivy, YARA) are stored |
| `REDACTS_SANDBOX_IMAGE` | `php:8.2-cli-alpine` | Docker image for sandboxed PHP execution |
| `REDACTS_SANDBOX_ENABLED` | `true` | Enable/disable sandboxed execution |
| `REDACTS_WORKERS` | CPU count | Parallel worker count |

### Config File

You can load settings from a JSON or YAML file:

```json
{
  "output_dir": "/custom/output/path",
  "log_level": "DEBUG",
  "verbose": true,
  "analysis": {
    "max_file_size_mb": 100
  },
  "investigation": {
    "enable_external_tools": true,
    "external_tool_timeout": 180
  },
  "forensic_report": {
    "formats": ["html", "json", "markdown"]
  }
}
```

Config sections: `sandbox`, `analysis`, `comparison`, `repomix`, `report`, `dast`, `evidence`, `investigation`, `forensic_report`.

---

## Running DAST (Dynamic Analysis)

The DAST phase tests a live REDCap instance in Docker with Playwright browser automation. This is separate from the main scan.

**Requirements:** Docker, Docker Compose v2+, Node.js 18+.

> REDCap is proprietary software. You must supply your own REDCap Docker image or build configuration. REDACTS does not include REDCap itself.

```bash
cd dast
npm install
docker compose -f docker-compose.dast.yml up -d
npx playwright test
```

The 4 test suites:

| Suite | Tests | What It Checks |
|-------|:-----:|---------------|
| `admin-access.spec.ts` | 10 | Authentication boundaries and privilege escalation |
| `crawlmaze-coverage.spec.ts` | 76 | Google Crawl Maze coverage benchmark |
| `export-report.spec.ts` | 6 | Data export and report security |
| `upgrade-flow.spec.ts` | 10 | Upgrade process integrity |

To tear down the Docker stack after testing:

```bash
docker compose -f docker-compose.dast.yml down -v
```

---

## Running Tests

```bash
python -m pytest tests/ -x -q
```

The test suite contains 321 tests. All must pass before submitting contributions.

---

## Interpreting Results

### Risk Levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Active compromise indicators found (e.g., INFINITERED markers, eval/gzinflate chains) |
| **HIGH** | Dangerous code patterns present (e.g., dynamic code execution, SQL injection) |
| **MEDIUM** | Potentially risky patterns requiring manual review |
| **LOW** | Minor issues (weak crypto, weak random) |
| **CLEAN** | No deviations from the reference baseline |

### Finding Fields

Every finding includes:

| Field | Description |
|-------|-------------|
| `rule_id` | Unique rule identifier (e.g., `SEC060`, `IOC-INF-001`, `UPG010`) |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `file_path` | File where the finding was detected |
| `line` | Line number (when available) |
| `cwe_id` | CWE identifier (when applicable) |
| `cvss_score` | CVSS 3.1 base score |
| `mitre_technique` | MITRE ATT&CK technique ID (e.g., `T1505.003`) |
| `description` | Human-readable explanation |
| `recommendation` | Suggested remediation action |

### What to Do

1. **CRITICAL findings** — Escalate immediately. Isolate the server. Contact your security team and the [REDCap Consortium](https://projectredcap.org).
2. **HIGH findings** — Investigate each one. Compare the flagged code against the reference to confirm it's not a legitimate customization.
3. **MEDIUM/LOW findings** — Review during your next maintenance window.
4. **CLEAN result** — Your installation matches the reference. No action needed.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` inside your virtual environment |
| Trivy/YARA download fails | Check internet connectivity. Manually download from [Trivy releases](https://github.com/aquasecurity/trivy/releases) or [YARA releases](https://github.com/VirusTotal/yara/releases) and place in `~/.redacts/tools/` |
| Scan hangs on large archives | Set `REDACTS_LOG_LEVEL=DEBUG` to see progress. Large REDCap installs (10K+ files) can take 10–15 minutes |
| DAST tests fail to start | Ensure Docker is running and port 8585 is available. Check `docker compose logs` for errors |
| Permission denied on output | Set `REDACTS_OUTPUT_DIR` to a writable directory |

---

## Help

```bash
python -m REDACTS --help
```

**Contact:** <atrium@theadimension.com> · <shehab.anwer@gmail.com>
**Repository:** [github.com/The-Adimension/REDACTS](https://github.com/The-Adimension/REDACTS)

---

> **Reminder:** REDACTS aids forensic investigation but does not guarantee complete or definitive results. Always perform independent manual review. Not a replacement for qualified security analysis.
>
> © 2024–2026 The Adimension / Shehab Anwer. Licensed under Apache 2.0.
