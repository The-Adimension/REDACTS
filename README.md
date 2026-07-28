# REDACTS - REDCap Arbitrary Code Threat Scan

A forensic-analysis aid for REDCap installations. REDACTS compares an
analyst-supplied target tree against a known-good reference release,
then scopes deeper static and dynamic analysis to the differential
delta. It does **not** perform forensic acquisition. It does **not**
replace manual investigation by a qualified analyst.

> **REDACTS** is a forensic-analysis aid built in response to the
> INFINITERED malware family (REDCap, May 2025 disclosure). Designed for
> use in clinical-research environments where the audited tree may
> contain protected health information.
>
> REDACTS is **not** a substitute for thorough manual review by qualified
> professionals, REDCap administrators, the REDCap Community, or
> Dev/SecOps teams. Scan results are **not** guaranteed to be complete or
> definitive — false positives and false negatives are possible, especially
> alongside REDCap updates or unknown INFINITERED variants.
> **Expert review is mandatory.**
>
> Use REDACTS as an auxiliary tool within an incident-response workflow,
> never as the sole basis for security decisions. REDACTS does not modify,
> patch, or alter the files it scans.
>
> Built from base scripts the author developed during prior work on PHP,
> MySQL, and REDCap. AI agents (Claude Opus, a local fine-tune of
> FunctionGemma for tool calling) and @repomix were used to accelerate
> pipeline development.
>
> If you discover evidence of compromise, contact your security team and
> the REDCap Consortium immediately. See [DISCLAIMER](DISCLAIMER) for the
> full disclaimer, including non-affiliation with Vanderbilt University /
> the REDCap Consortium and authorisation requirements.
>
> © 2024–2026 The Adimension / Shehab Anwer — atrium@theadimension.com

## Status

- Version: 4.0.0
- **Python: 3.13 recommended, 3.12 also supported. 3.12 is the minimum.**
- License: Apache-2.0

> **Do not use Python 3.14.** Semgrep - the primary PHP code scanner - installs
> on 3.14 but its engine does not run there (it exits without producing any
> output). `preflight` detects this and fails Semgrep as **non-functional**,
> rather than letting a scan silently proceed with no PHP coverage. Run REDACTS
> on Python **3.13 or 3.12**. See [USER_GUIDE.md](USER_GUIDE.md) Sec.5.

## What it does

| Phase | Component | Output |
|---|---|---|
| Ingest | `static/collect/` (zip / tar / 7z / rar / http / sftp / local) | SHA-256 manifest |
| Baseline diff | `static/audit/` | Added / modified / deleted file set |
| Static analysis | `static/scanners/` (regex + tree-sitter PHP + Semgrep + Trivy + YARA) | `UnifiedFinding`s |
| File-type verification | `static/scanners/` (Magika AI content-typing) | Masquerade / hidden-payload flags |
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

This installs the Python side (Semgrep, Repomix, Magika, tree-sitter, etc.).
**Trivy and YARA are separate native binaries** that must be on your `PATH` -
see [SETUP.md](SETUP.md) for per-OS install commands and a full preflight
walkthrough. The repository does not ship a pre-built `.venv`; create one as
above.

Docker is needed **only** for dynamic (DAST) mode (`docker compose version`
must succeed). A static-only scan - the common case - does not need Docker.
Verify your environment at any time with `python main.py preflight`.

## Quickstart

Every run reads its configuration from a single `case.toml`
(and an optional `case.toml.lock`). Configuration via environment
variables is rejected by the production code paths.

```bash
# 1. Create the case file interactively (recommended for first-time users).
#    Point it at the installation to check (target) and a known-good
#    REDCap release of the same version (reference). It auto-computes
#    hashes, detects available scanners, and writes a valid case.toml.
python main.py init --target /path/to/target.zip --reference /path/to/reference.zip

#    (Advanced: copy and hand-edit the template instead -
#     `cp case.example.toml case.toml` then edit.)

# 2. Verify the environment. Exit 0 = ready; exit 1 = a required tool is
#    missing or non-functional. Fixes are printed inline; see SETUP.md.
python main.py preflight

# 3. Run the scan. Mode defaults to [dynamic].enabled in case.toml.
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
