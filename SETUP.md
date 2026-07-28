# REDACTS Complete System Setup & Preflight Verification Guide

> **Third-Party Tool & Integrity Disclaimer:**  
> REDACTS is an orchestration and forensic staging engine designed to bridge and unify specialized third-party security engines (`Trivy`, `YARA`, `Semgrep`, `Repomix`, `tree-sitter`, `Playwright`, `Docker`) into a single end-to-end security workflow. REDACTS orchestrates their execution and aggregates their output; it does not replace their official distribution channels. The security, cryptographic integrity, licensing, stability, and bug-free execution of each third-party tool are solely the responsibility of their respective upstream providers and the user configuring them. 

This document provides granular, item-by-item instructions to configure every dependency across **Layers 1 through 5** of the REDACTS Preflight Checklist.

> **New here? Read this first.**
> - **Use Python 3.13 (or 3.12). Do not use Python 3.14** - Semgrep's engine does not run on it and preflight will (correctly) fail Semgrep as non-functional.
> - **For a static scan - the common case - you do NOT need Docker.** Docker is only for the optional dynamic (DAST) mode. On a static-only setup, `Docker`, `Network`, and `ATT&CK Enterprise` may show as **`WARN`**, and that is **fine** - a `WARN` is optional/informational, not a failure. Preflight only *blocks* on `BLOCK`-tier items.
> - What you actually need for a static scan: Python 3.13, the Python packages (one `pip install`), and three native binaries - **Trivy, YARA, Semgrep**.

---

## 1. Executive Summary: The Preflight Verification Matrix

The table below lists every check and its tier. **`BLOCK`** items must pass to run a scan; **`WARN`** items are optional (they reduce coverage or apply only to dynamic mode) and are safe to leave unresolved. Run `python main.py preflight` (or `redacts preflight`) to see your live status:

| Layer | Item / Dependency | Type / Tier | Purpose in REDACTS Workflow | Target Status |
| :---: | :--- | :---: | :--- | :---: |
| **L1** | `Python runtime` | `BLOCK` | Core runtime (Python 3.12+ required) | `PASS` |
| **L2** | `chardet` | `BLOCK` | Universal character encoding auto-detection for diverse legacy files | `PASS` |
| **L2** | `magika` | `BLOCK` | Deep-learning AI file typing to replace fragile MIME estimation | `PASS` |
| **L2** | `paramiko` | `BLOCK` | SSH/SFTP protocol handler for remote target acquisition & staging | `PASS` |
| **L2** | `requests` | `BLOCK` | HTTP client for NVD/CWE/ATT&CK database sync & enrichment | `PASS` |
| **L2** | `py7zr` | `BLOCK` | Pure-Python 7-Zip archive extraction engine | `PASS` |
| **L2** | `rarfile` | `BLOCK` | RAR archive extraction handler | `PASS` |
| **L2** | `rich` | `BLOCK` | Terminal UI, progress bars, and forensic table rendering | `PASS` |
| **L2** | `pyyaml` | `BLOCK` | YAML parser for threat rules, attack vectors, and campaign definitions | `PASS` |
| **L2** | `tree-sitter` | `BLOCK` | High-speed AST parsing framework for structural analysis | `PASS` |
| **L2** | `tree-sitter-php` | `BLOCK` | PHP grammar bindings for deep structural vulnerability detection | `PASS` |
| **L2** | `stix2` | `BLOCK` | STIX 2.1 threat intelligence export and formatting engine | `PASS` |
| **L2** | `semgrep` | `BLOCK` | AST/pattern-based vulnerability engine (Python bindings & CLI) | `PASS` |
| **L2** | `repomix` | `BLOCK` | Codebase compression engine for analyst summary review (Python package - no Node.js) | `PASS` |
| **L2** | `playwright` | `BLOCK` | Browser automation engine for Dynamic Application Security Testing (DAST) | `PASS` |
| **L2** | `pytest-asyncio` | `BLOCK` | Async testing framework for asynchronous DAST and CLI harnesses | `PASS` |
| **L3** | `IoC Database` | `BLOCK` | Indicators of Compromise verification engine | `PASS` |
| **L3** | `Attack Vectors` | `BLOCK` | Attack surface vector classification definitions | `PASS` |
| **L3** | `Sensitive Data Patterns`| `BLOCK` | Regex rulesets for PII, API keys, JWTs, and credential detection | `PASS` |
| **L3** | `CWE Database` | `BLOCK` | Common Weakness Enumeration taxonomy index | `PASS` |
| **L3** | `MITRE ATT&CK Mapping` | `BLOCK` | Mapping engine linking findings to ATT&CK Enterprise techniques | `PASS` |
| **L3** | `Data: attack_vectors.yaml` | `BLOCK` | Core ruleset: 34+ attack vector definitions | `PASS` |
| **L3** | `Data: infinitered_campaign.yaml` | `BLOCK` | Campaign ruleset: specific persistent C2/backdoor signatures | `PASS` |
| **L3** | `Data: ioc_indicators.yaml` | `BLOCK` | Core ruleset: known malicious hashes and filenames | `PASS` |
| **L3** | `Data: mitre_mapping.yaml` | `BLOCK` | Core ruleset: CWE-to-ATT&CK mapping matrix | `PASS` |
| **L3** | `Data: redcap_baseline.yaml`| `BLOCK` | Baseline ruleset: expected REDCap architecture & directory layout | `PASS` |
| **L3** | `Data: security_rules.yaml` | `BLOCK` | Core ruleset: master security rules & severity weights | `PASS` |
| **L3** | `Data: sensitive_data_patterns.yaml` | `BLOCK` | Core ruleset: credential and PII regular expressions | `PASS` |
| **L3** | `ATT&CK Enterprise` | `WARN` | Cached offline ATT&CK STIX bundle (`python main.py update attack`). Optional - the bundled 34-pattern subset is used when absent | `PASS` |
| **L4** | `trivy` | `BLOCK` | Aqua Security Trivy binary: CVE/SCA dependency & secret scanner | `PASS` |
| **L4** | `yara` | `BLOCK` | YARA malware pattern matching engine binary | `PASS` |
| **L4** | `semgrep` | `BLOCK` | Semgrep CLI executable binary | `PASS` |
| **L4** | `docker` | `BLOCK` (dynamic only) | Docker daemon & CLI for containerized DAST. Required only when `[dynamic].enabled = true`; a static-only scan degrades this to `WARN` | `PASS` |
| **L5** | `Network` | `WARN` | Internet connectivity for external enrichment (NVD/CWE updates). Optional - offline and `[security].network_disabled = true` runs proceed on cached/bundled data | `PASS` |

---

## 2. Layer 1 & Layer 2: Python Runtime & Core Packages

REDACTS requires **Python 3.13 (recommended) or 3.12**. **Do not use Python 3.14** - Semgrep's engine does not run on it. Install the packages using either the fast `uv` package manager (recommended) or standard `pip`.

In the commands below, `cd` into the directory where you cloned/copied REDACTS (the folder containing `main.py`). Replace `<REDACTS_DIR>` accordingly.

### Option A: Using `uv` (Recommended)
`uv` resolves and locks all dependencies instantly without conflict warnings.

```bash
# 1. Install uv if not already present
# Windows (PowerShell):
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
# macOS / Linux:
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Sync REDACTS requirements (from the REDACTS directory)
cd <REDACTS_DIR>
uv sync --all-extras

# 3. Activate environment or run commands via uv
uv run redacts preflight
```

### Option B: Using Standard `pip`
If using standard Python virtual environments:

```bash
cd <REDACTS_DIR>

# 1. Create and activate a clean Python 3.13 (or 3.12) virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# 2. Install REDACTS and all Python dependencies. requirements.txt is the
#    canonical list (mirrors pyproject.toml); this single command installs
#    Semgrep, Repomix, Magika, tree-sitter, and everything else.
pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt

# 3. Install Playwright browser binaries (only needed for dynamic/DAST mode)
playwright install chromium
```

---

## 3. Layer 3: Knowledge Base & Threat Rulesets

Layer 3 checks verify that all built-in YAML security definitions (`security_rules.yaml`, `attack_vectors.yaml`, `ioc_indicators.yaml`, `mitre_mapping.yaml`, `sensitive_data_patterns.yaml`, `infinitered_campaign.yaml`, and `redcap_baseline.yaml`) are present and syntactically valid in `threat_base/data/yaml/`.

### Resolving the `ATT&CK Enterprise` Warning (`WARN` -> `PASS`)
By default, REDACTS ships with a bundled subset of 34 core ATT&CK patterns so offline scans work immediately. To upgrade this check from `WARN` (`Full ATT&CK bundle not cached`) to **`PASS` (`Complete ATT&CK STIX bundle cached offline`)**, run the built-in threat updater once:

```bash
python main.py update attack
```
*Outcome:* Downloads and caches the full MITRE ATT&CK Enterprise STIX 2.1 bundle into `threat_base/data/cache/attack_enterprise.json`.

---

## 4. Layer 4: External Security Scanners & System Binaries

To ensure preflight confirms the external scanner binaries as `[PASS]`, install them via your operating system's official package manager and verify they are on your system `PATH`. The Layer 4 binaries are `trivy`, `yara`, `semgrep`, and `docker`.

> **Node.js is no longer required.** Repomix now runs as a Python package (installed in Layer 2 via `pip`), so `node`, `npm`, and `npx` are not needed on the host. Docker is required **only** for dynamic (DAST) analysis - a static-only scan (`[dynamic].enabled = false`) treats a missing Docker as a warning, not a blocker.

### Item-by-Item Installation & PATH Configuration

#### 1. `semgrep` (CLI Executable)
* **What it does:** AST-based code analysis and vulnerability detection.
* **How to install:** Installed alongside the Python package (`pip install semgrep` or `uv sync`).
* **PATH Check:**
  ```bash
  semgrep --version
  ```

#### 2. `trivy` (CVE & Secret Scanner)
* **What it does:** Scans dependencies, containers, and codebases for known CVEs and leaked secrets.
* **Windows (PowerShell / Winget):**
  ```powershell
  winget install AquaSecurity.Trivy --source winget
  ```
* **macOS (Homebrew):**
  ```bash
  brew install trivy
  ```
* **Linux (Debian/Ubuntu / Official Script):**
  ```bash
  sudo apt-get install wget apt-transport-https gnupg lsb-release
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
  echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
  sudo apt-get update && sudo apt-get install trivy
  ```
* **PATH Check:**
  ```bash
  trivy --version
  ```
  *(If installed via winget on Windows, close and reopen your terminal or append `C:\Program Files\Trivy` to your `PATH` environment variable).*

#### 3. `yara` (Malware Pattern Engine)
* **What it does:** High-speed string and byte-pattern matching for malware signatures and custom IOCs.
* **Windows (Winget / Chocolatey):**
  ```powershell
  winget install YARA.YARA --source winget
  # OR via Chocolatey
  choco install yara
  ```
* **macOS (Homebrew):**
  ```bash
  brew install yara
  ```
* **Linux (Debian/Ubuntu / RHEL):**
  ```bash
  sudo apt-get install yara
  ```
* **PATH Check:**
  ```bash
  yara --version
  ```

#### 4. `repomix` (Codebase Representation Engine)
* **What it does:** Compresses complex repository structures into a structured single-file format for rapid analyst review.
* **Installation:** No Node.js required - Repomix is a Python package installed with the other Layer 2 dependencies:
  ```bash
  pip install repomix
  ```
  (Already covered by `pip install -e .` / `uv sync` in Section 2.)
* **Check:**
  ```bash
  python -c "import repomix; print(repomix.__version__)"
  ```

> **Note:** Node.js, `npm`, and `npx` are no longer REDACTS host dependencies. Repomix runs in-process via its Python package, and Playwright (DAST) uses its own bundled Node runtime inside the Python package and Docker images.

#### 5. `docker` (Container Engine for DAST)
* **What it does:** Provides isolated container runtime environments for Dynamic Application Security Testing (`DASTOrchestrator`).
* **Windows / macOS:** Install [Docker Desktop](https://www.docker.com/products/docker-desktop/).
  ```powershell
  winget install Docker.DockerDesktop --source winget
  ```
* **Linux:** Install `docker-ce` via official Docker repositories.
* **PATH Check:**
  ```bash
  docker --version
  ```
  *(Ensure Docker Desktop is running in the background).*

---

## 5. Layer 5: Network & Enrichment Connectivity

* **What it does:** Checks `[security].network_disabled` in `case.toml` and pings upstream threat repositories (`nvd.nist.gov`, `cve.mitre.org`) to confirm online enrichment capabilities.
* **Configuration:**
  - If connected to the internet, this check automatically reports **`[PASS] Online - enrichment services reachable`**.
  - If operating in an air-gapped/offline forensic lab, set `network_disabled = true` under `[security]` in `case.toml`. REDACTS will switch to pure offline analysis without emitting failure warnings.

---

## 6. Final Verification: Running Complete Preflight

Once you have executed the installation commands above, run the master verification check from your terminal:

```bash
python main.py preflight
# OR if global redacts CLI is active:
redacts preflight
```

### Expected Output (all `BLOCK` items PASS)

Paths below are illustrative - yours reflect your own REDACTS directory and `case.toml`. On a static-only setup, `Docker` (and possibly `Network` / `ATT&CK Enterprise`) will show `WARN`; that is expected and does not block a scan.

```
REDACTS storage locations (driven by case.toml):
  * home    [contract] <REDACTS_DIR>  [exists]
  * output  [contract] <REDACTS_DIR>\output  [exists]
  * tools   [contract] <REDACTS_DIR>\tools  [exists]
  * temp    [contract] <REDACTS_DIR>\tmp  [exists]
  * cache   [contract] <REDACTS_DIR>\cache  [exists]
  (* = sourced from case.toml; otherwise built-in default)

Preflight Status
┏━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ L   ┃ Check                                   ┃ Tier   ┃ Status   ┃ Version ┃ Detail / Fix                                        ┃
┡━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1   │ Python runtime                          │ BLOCK  │ PASS     │ 3.14.4  │                                                     │
│ 2   │ chardet                                 │ BLOCK  │ PASS     │ 7.4.3   │                                                     │
│ 2   │ magika                                  │ BLOCK  │ PASS     │ 1.0.3   │                                                     │
│ 2   │ paramiko                                │ BLOCK  │ PASS     │ 4.0.0   │                                                     │
│ 2   │ requests                                │ BLOCK  │ PASS     │ 2.33.1  │                                                     │
│ 2   │ py7zr                                   │ BLOCK  │ PASS     │ 1.1.3   │                                                     │
│ 2   │ rarfile                                 │ BLOCK  │ PASS     │ 4.2     │                                                     │
│ 2   │ rich                                    │ BLOCK  │ PASS     │ -       │                                                     │
│ 2   │ pyyaml                                  │ BLOCK  │ PASS     │ 6.0.3   │                                                     │
│ 2   │ tree-sitter                             │ BLOCK  │ PASS     │ -       │                                                     │
│ 2   │ tree-sitter-php                         │ BLOCK  │ PASS     │ -       │                                                     │
│ 2   │ stix2                                   │ BLOCK  │ PASS     │ 3.0.2   │                                                     │
│ 2   │ semgrep                                 │ BLOCK  │ PASS     │ 1.166.0 │                                                     │
│ 2   │ repomix                                 │ BLOCK  │ PASS     │ 0.5.0   │                                                     │
│ 2   │ playwright                              │ BLOCK  │ PASS     │ 1.49.1  │                                                     │
│ 2   │ pytest-asyncio                          │ BLOCK  │ PASS     │ 1.3.0   │                                                     │
│ 3   │ IoC Database                            │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Attack Vectors                          │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Sensitive Data Patterns                 │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ CWE Database                            │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ MITRE ATT&CK Mapping                    │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Data: yaml/attack_vectors.yaml          │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Data: yaml/infinitered_campaign.yaml    │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Data: yaml/ioc_indicators.yaml          │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Data: yaml/mitre_mapping.yaml           │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Data: yaml/redcap_baseline.yaml         │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Data: yaml/security_rules.yaml          │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ Data: yaml/sensitive_data_patterns.yaml │ BLOCK  │ PASS     │ -       │                                                     │
│ 3   │ ATT&CK Enterprise                       │ WARN   │ PASS     │ -       │ Complete ATT&CK STIX bundle cached offline          │
│ 4   │ trivy                                   │ BLOCK  │ PASS     │ 0.58.2  │                                                     │
│ 4   │ yara                                    │ BLOCK  │ PASS     │ 4.5.2   │                                                     │
│ 4   │ semgrep                                 │ BLOCK  │ PASS     │ 1.166.0 │                                                     │
│ 4   │ docker                                  │ BLOCK* │ PASS     │ 27.4.0  │ *dynamic only; WARN for a static-only scan          │
│ 5   │ Network                                 │ WARN   │ PASS     │ -       │ Online - enrichment services reachable              │
└─────┴─────────────────────────────────────────┴────────┴──────────┴─────────┴─────────────────────────────────────────────────────┘

[OK] All preflight checks passed.
```

When every **`BLOCK`**-tier item displays `PASS` (any `WARN` items are optional), your system is ready. Next, create a case file and run a scan:

```bash
# Create a case.toml interactively - point it at the installation to check
# (target) and a known-good REDCap release of the same version (reference):
python main.py init --target /path/to/target.zip --reference /path/to/reference.zip

# Run the scan (static by default):
python main.py scan
```

See [USER_GUIDE.md](USER_GUIDE.md) for the full CLI, the `case.toml` schema, and an explanation of the reports REDACTS produces (Audit vs. Forensic vs. SARIF).
