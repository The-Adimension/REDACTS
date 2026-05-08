# REDACTS - REDCap Arbitrary Code Threat Scan

A forensic-analysis aid for REDCap installations. REDACTS compares an
analyst-supplied target tree against a known-good reference release,
then scopes deeper static and dynamic analysis to the differential
delta. It does **not** perform forensic acquisition. It does **not**
replace manual investigation by a qualified analyst.

> Built in response to the INFINITERED malware family (REDCap, May 2025
> disclosure). Designed for use in clinical-research environments where
> the audited tree may contain protected health information.

## Status

- Version: 3.0.0
- Python: 3.14 (tested). 3.13 also works; 3.12 is the minimum.
- License: Apache-2.0

Some optional scanners (notably Semgrep) have not yet shipped Python 3.14
wheels. If the host runs 3.14, the affected scanner is reported as a
runtime gap and the rest of the pipeline continues; see
[USER_GUIDE.md](USER_GUIDE.md) Sec.5.

## What it does

| Phase | Component | Output |
|---|---|---|
| Ingest | `static/collect/` (zip / tar / 7z / rar / http / sftp / local) | SHA-256 manifest |
| Baseline diff | `static/audit/` | Added / modified / deleted file set |
| Static analysis | `static/scanners/` (regex + tree-sitter PHP + Semgrep + Trivy + YARA) | `UnifiedFinding`s |
| Dynamic analysis (optional) | `dynamic/` (Playwright + Docker) | DAST findings |
| Reporting | `static/report/` | JSON / Markdown / HTML / SARIF |

Detection coverage: 57 SEC* rules (REDCap-specific, CVE-cited),
17 IoC indicators, 34 attack vectors, INFINITERED-aware persistence
checks. Knowledge is data-driven (`threat_base/data/yaml/`,
SHA-256-integrity-verified at load).

## Install

```bash
git clone https://github.com/The-Adimension/REDACTS
cd REDACTS
python -m venv .venv && source .venv/bin/activate     # PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
```

The repository does not ship a pre-built `.venv`; create one as above.
Dynamic (DAST) mode additionally requires Docker with the Compose v2
plugin (`docker compose version` must succeed).

## Quickstart

Every run reads its configuration from a single `case.toml`
(and an optional `case.toml.lock`). Configuration via environment
variables is rejected by the production code paths.

```bash
# 1. Author the case file. A documented template ships in the repo.
cp case.example.toml case.toml
$EDITOR case.toml

# 2. Show resolved storage locations.
python main.py paths

# 3. Verify the environment. Exit 0 = ready; exit 1 = required tool missing.
python main.py preflight

# 4. Run the scan. Mode defaults to [dynamic].enabled in case.toml.
python main.py scan
```

Reports land under the `output_root` declared in `case.toml`
(default `output/scan_<timestamp>/`). Scan exit codes:
`0` clean, `1` phase-level failure, `2` severity gate triggered.

### case.toml - single source of truth

`case.toml` is the **only** configuration surface. It declares case
identity, target/reference inputs, storage paths, scanner enablement,
DAST topology, threat-base sources, and tool
versions. The file is loaded once at startup, frozen into a
`FrozenCaseContract`, optionally verified against `case.toml.lock`
(SHA-256), and installed on a process-wide runtime context. Every
downstream module reads from that contract - none of them touch
`os.environ`. An AST linter
([scripts/check_no_env_reads.py](scripts/check_no_env_reads.py))
enforces this invariant in CI.

See [USER_GUIDE.md](USER_GUIDE.md) Sec.2 for the full schema.

## Architecture

```
case.toml      Single source of truth - frozen at startup into FrozenCaseContract.
static/        SAST pipeline (cli, core, collect, analyze, scanners, audit, report)
dynamic/       DAST pipeline (Playwright + Docker)
threat_base/   Detection knowledge (YAML + JSON, integrity-verified)
runtime/       Deployment recipes (docker, k8s, podman; community in contrib/)
```

The CLI is **non-interactive** - it never prompts for paths or
auto-detects case files. Every value that drives a scan flows through
`FrozenCaseContract`. See [USER_GUIDE.md](USER_GUIDE.md) for the full
CLI reference and [DATA_HANDLING.md](DATA_HANDLING.md) for what the
tool reads, where it writes, and how it cleans up.

## Limitations

- Regex-based rules are by design auditable, not exhaustive. Trivial
  obfuscation will bypass them.
- The tool is an analysis aid. It is not a replacement for `dd` /
  `ewfacquire` / `aff4` acquisition or for trained incident-response
  staff.
- atime on the audited tree is updated under default mount options.
  For strict forensic acquisition, mount the working volume `noatime`.
- See [SECURITY.md](SECURITY.md) for the full list.

## Contact

Shehab Anwer - The Adimension

## License

Apache-2.0. See [LICENSE](LICENSE) and [DISCLAIMER](DISCLAIMER).
