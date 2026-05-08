# REDACTS - User Guide

> REDACTS - REDCap Arbitrary Code Threat Scan. A forensic analysis aid for
> REDCap deployments. This guide documents the **CLI** as it exists in
> the source tree (verified against `main.py`, `static/cli/`,
> `static/core/paths.py`, `threat_base/updater.py`).

> **Disclaimer.** REDACTS is an aid, not a replacement for manual review by
> a qualified security professional. See [`DISCLAIMER`](DISCLAIMER).

---

## 1. Installation & first run

### 1.1 Requirements

- Python **3.12 or newer** (3.14 tested). The pipeline runs on the
  system interpreter; a virtual environment is recommended but not
  bundled with the repository.
- Optional native tools used by static scanners (Trivy, YARA, Semgrep,
  repomix, Magika). Missing optional tools are reported as **WARN** by
  preflight and degrade coverage; they do not block the scan.
- Docker with the **Compose v2** plugin if dynamic (DAST) mode is
  enabled. Verify with `docker compose version`.

Notes on Windows installs:

- `pip install --user <tool>` places console scripts in
  `%APPDATA%\Python\Python<ver>\Scripts\`, which is not on `PATH` by
  default. The Semgrep adapter probes that directory directly via
  `sysconfig`; for other tools either add the directory to `PATH`,
  install system-wide, or drop the binary into
  `contract.paths.tools_root` (auto-prepended to `PATH`).
- Semgrep has no Python 3.14 wheel at the time of writing. On 3.14 the
  binary resolves but its internal `pysemgrep` subprocess fails;
  REDACTS reports it as a runtime gap and continues.

### 1.2 Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt

Copy-Item case.example.toml case.toml   # then edit case.toml for your case
python main.py paths                    # show where artifacts go
python main.py preflight                # verify the environment
python main.py update                   # refresh threat data (optional)
python main.py scan                     # mode comes from case.toml
```

For live progress on Windows PowerShell 5.1 (which buffers redirected
output), set `$env:PYTHONUNBUFFERED = '1'` before invoking `main.py`.

---

## 2. `case.toml` - single source of truth

REDACTS is **contract-driven**. A single `case.toml` file at the
repo root (or any path passed via `--case`) declares every value the
scan needs: case identity, target / reference inputs, storage paths,
scanner enablement, DAST topology, threat-base sources, and pinned
tool versions.

At startup, `main.py::_install_contract` loads the file, validates and
freezes it into a `FrozenCaseContract`, optionally verifies
`case.toml.lock` (SHA-256 over the canonical contract serialisation),
and installs the contract on a process-wide runtime context
(`static.core.runtime_context`). Every downstream module reads from
that contract - **no production code touches `os.environ` for
configuration**. An AST linter
([scripts/check_no_env_reads.py](scripts/check_no_env_reads.py))
enforces this invariant in CI; allowed exceptions are limited to
`static/core/contract.py`, `static/core/subprocess_env.py`,
`static/core/paths.py`, and `dynamic/helpers/_runtime_env.py`.

### 2.1 Required sections

| Section | Frozen as | Notes |
|---|---|---|
| `[case]` | `CaseIdentity` | id / analyst / organization / date / description |
| `[paths]` | `PathsConfig` | workspace_root, output_root, temp_root, cache_root, tools_root, logs_root, audit_trail |
| `[inputs.target]` | `InputArtifact` | path + sha256 (sha256 mandatory for local files) |
| `[inputs.reference]` | `InputArtifact` | same shape as target |
| `[inputs.upgrade_package]` | `InputArtifact \| None` | optional |
| `[static]` | `StaticConfig` | enabled, scanners[], formats[], severity_gate, limits |
| `[dynamic]` | `DynamicConfig` | enabled, runtime, suites, port, suite_timeout, keep_stack |
| `[dynamic.images.*]` | `DynamicImages` | mariadb / php / playwright / sandbox (digest-pinned) |
| `[dynamic.credentials]` | `DynamicCredentials` | admin + db + salt (loopback-only stack) |
| `[dynamic.network]` | `DynamicNetwork` | base_url, internal_hosts, xdebug_mode |
| `[dynamic.playwright]` | `PlaywrightConfig` | chromium executable + args + node version |
| `[threat_base]` | `ThreatBaseConfig` | offline_mode, allow_stale, ttl_hours |
| `[threat_base.sources.*]` | `ThreatBaseSources` | cwe / nvd / attack_stix / yara_rules (URL + sha256) |
| `[tools.*]` | `ToolsConfig` | trivy/yara native ToolSpecs + python ToolSpecs (semgrep, repomix, magika) |
| `[nix]` | `NixRuntimeConfig` | flake_ref, nixpkgs_rev, attribute names |
| `[security]` | `SecurityConfig` | network_disabled, ssrf_allowlist, sandbox flags |
| `[logging]` | `LoggingConfig` | level, format, retention_days, to_file, to_stderr |

[case.example.toml](case.example.toml) is the canonical, fully
populated template. Copy it to `case.toml` and edit in place.

### 2.2 The lockfile

`case.toml.lock` is a sealed snapshot - written by
`static.core.contract.write_lockfile(...)` - containing the SHA-256 of
the canonical contract bytes plus its `loaded_at_utc` timestamp. When a
lockfile is present next to `case.toml`, `_install_contract` runs
`verify_lockfile(...)` and aborts (`exit 2`) if the contract drifts
from the seal. This is how an analyst proves to a reviewer that the
run used exactly the configuration that was reviewed.

### 2.3 Resolved paths

`python main.py paths` prints the storage roots derived from the
contract's `[paths]` section, plus an `[exists]/[missing]` marker.

The `tools_root` directory is auto-prepended to `PATH` at the start of
every preflight / scan run via `paths.inject_tools_on_path()` so
binaries dropped there (manually or by the auto-installer) are visible
to `shutil.which`.

---

## 3. CLI reference

The entry point is `python main.py ...` (also `python -m main`). The
parser is defined in `main.py::build_parser`.

### 3.1 Global options

| Flag | Effect |
|---|---|
| `--case <path>` | Path to `case.toml` (default: `./case.toml`). Required for `scan`; optional for `paths` and `preflight`, which fall back to a built-in default contract when no case file is present. |

> Environment variables are **not** honoured for configuration. The
> only file that can change a scan's behaviour is `case.toml`. This is
> verified by [scripts/check_no_env_reads.py](scripts/check_no_env_reads.py),
> which fails CI on any new `os.environ` / `os.getenv` access in the
> production code paths.

### 3.2 Subcommands

#### `scan` - run analysis (default)

```text
python main.py scan [--mode {static,dynamic,full}]
```

| Mode | Behaviour |
|---|---|
| `static` | Runs the static pipeline only: evidence -> audit -> scan -> report. |
| `dynamic` | Runs the DAST orchestrator only. Boots the runtime stack and executes Playwright suites. |
| `full` | Runs the static pipeline, which itself invokes DAST via the shared `DASTOrchestrator`. |

When `--mode` is omitted the default is derived from the contract:
`full` if `[dynamic].enabled = true`, otherwise `static`. Running
`python main.py` with no subcommand is equivalent to `scan` with that
derived mode.

The scan path is non-interactive. If `case.toml` is missing or invalid
the scan aborts with an explicit error rather than prompting.

**Scan exit codes** (`static/cli/workflow.py`):

| Code | Meaning |
|---|---|
| `0` | Clean run; no phase errors and no findings at or above `[static].severity_gate`. |
| `1` | At least one phase reported a hard error (e.g. evidence collection failed). |
| `2` | Severity gate triggered (one or more findings at or above the configured gate level), or contract validation / lockfile verification failed at startup. |

Exit `2` is therefore the normal outcome for a successful scan that
found real issues; it is distinct from `1` so CI can tell "the scan
worked and found something" apart from "the scan itself broke".

#### `preflight` - verify environment

```text
python main.py preflight [--install]
```

Runs the 5-layer preflight defined in `static/cli/preflight.py`.
With `--install`, BLOCK-tier failures trigger an auto-install attempt
(pip for Python tools; Trivy/YARA via the bundled installer) followed
by a re-check. The auto-installer honours `[security].network_disabled`
and will refuse to reach the network when the contract forbids it.

Exit codes:

- `0` - all required (BLOCK-tier) checks passed. WARN-tier failures
  print a warning line but do not change the exit code.
- `1` - at least one BLOCK check failed.

#### `update` - refresh threat database

```text
python main.py update [{cwe|attack|yara|nvd|all}] [--no-confirm]
```

The positional argument selects a single source; omitting it (or
passing `all`) refreshes every source. `--no-confirm` skips the
interactive y/n prompt and is intended for CI use.

Downloads are routed through `assert_network_allowed`, so an `update`
call will fail fast when `[security].network_disabled = true` or when
the source URL is not in `[security].ssrf_allowlist`. Cached entries
remain usable per `[threat_base].ttl_hours` and `allow_stale`.

#### `paths` - show resolved storage locations

```text
python main.py paths
```

Prints the storage roots from Sec.2.3 and exits `0`.

#### `secrets` - manage the OS credential store

```text
python main.py secrets {set|get|delete|list} [<key>] [<value>]
```

Forwarded to `static.core.secrets.cli_main`. The credential store
(via the `keyring` package) holds runtime secrets - e.g. NVD API keys
or remote-fetch credentials - that must not appear in `case.toml` or
the lockfile. Only `secrets set` prompts (via `getpass`); the scan
flow itself remains non-interactive.

### 3.3 Configuration sources

There are no environment-variable knobs for configuration. Every
run-time behaviour is declared in `case.toml` (Sec.2.1). This is
intentional: in a forensic context, configuration that lives in a
process's environment is invisible to a peer reviewer. The contract
plus lockfile pair makes the run reproducible from disk alone.

---

## 4. Typical workflows

The scan workflow is internally divided into four phases. The labels
appear in log lines and per-tool status blocks:

- **Phase A - collect**: ingest the target/reference trees and build a
  SHA-256 manifest (`static/collect/`).
- **Phase B - audit**: diff target against reference; produce the
  added/modified/deleted file set (`static/audit/`).
- **Phase C - analyse**: run scanners (regex, tree-sitter, Semgrep,
  Trivy, YARA) over the diff (`static/scanners/`, `static/analyze/`).
- **DAST** (optional): drive Playwright suites against a disposable
  Dockerised REDCap (`dynamic/`).

### 4.1 First-time setup verification

```powershell
python main.py paths
python main.py preflight
```

`paths` prints the resolved storage locations. `preflight` runs the
5-layer environment check and exits `0` if every BLOCK-tier check
passes. Add `--install` to let preflight repair missing tools
in-place.

### 4.2 Refresh threat data

```powershell
python main.py update                # all sources
python main.py update cwe            # single source
python main.py update --no-confirm   # for CI
```

On first run, the CWE CSV is absent; preflight and the orchestrator
log `CWE CSV not found at threat_base/data/cwec_v4.19.csv` and CWE
enrichment is silently degraded until `update cwe` runs.

### 4.3 Static scan

```powershell
python main.py scan --mode static
```

Reports land under `contract.paths.output_root`.

### 4.4 Dynamic (DAST) scan

```powershell
python main.py scan --mode dynamic
```

Boots the disposable REDCap stack via `docker compose` and runs the
Playwright suites declared in `[dynamic].suites`. Requires Docker
with the Compose v2 plugin.

### 4.5 How runtime failures are reported

The per-tool status block printed at the end of phase C reflects
actual phase outcome:

- `tool: OK` - phase ran to completion.
- `tool: FAILED` - phase raised or the scanner reported an error;
  the failure is also added to the run's `runtime_gaps` list and
  surfaces in the summary line as `Scan finished in Xs with N
  warning(s)`.
- `tool: SKIPPED` - the phase was disabled by the contract or by an
  earlier dependency check.

A scan that completes with a failed tool still produces reports for
the tools that ran; the reports record which scanners contributed and
which did not.

---

## 5. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `paths` shows `[missing]` for `temp` / `cache` | First run; the directory is created lazily on first use. Run `preflight` to materialize it. |
| Preflight reports `'<tool>' not found on PATH` | Drop the binary into `contract.paths.tools_root` (auto-prepended to `PATH`) or install it system-wide. On Windows, `pip install --user` places scripts in `%APPDATA%\Python\Python<ver>\Scripts\`, which is not on `PATH` by default. |
| `Semgrep: scan failed - executing pysemgrep failed` on Python 3.14 | Upstream incompatibility: Semgrep has no 3.14 wheel yet. The phase is reported as a runtime gap and the rest of the pipeline continues. Pin Python 3.13 to recover Semgrep coverage. |
| `docker compose` rejects `-f` with `unknown shorthand flag` | Compose v1 (the deprecated `docker-compose` Python wrapper) is on `PATH` ahead of the Compose v2 plugin, or the v2 plugin is missing. Install / upgrade Docker so that `docker compose version` succeeds, then re-run. |
| `--mode full` followed by `--mode dynamic` | `full` already invokes DAST inside the static pipeline. Run one of the two, not both. |
| Captured `.log` lags minutes behind the actual run on Windows PowerShell 5.1 | Set `$env:PYTHONUNBUFFERED = '1'` before invoking `main.py` so writes are flushed line-by-line. |
| Scan exits `2` on a clean-looking run | Severity gate triggered. Check the `Severity gate '<level>' triggered: N finding(s) at or above gate.` line at the end of the output. Lower the gate in `[static].severity_gate` if the policy is wrong, or treat the findings. |
| `[FATAL] case.toml is invalid: sha256 mismatch` / `path does not exist` | Contract validation refused the run. The hash in `[inputs.target].sha256` no longer matches the file on disk, or the path was moved. Recompute and update `case.toml`. |

---

## 6. File map (for contributors)

| Path | Role |
|---|---|
| [main.py](main.py) | Argparse entry point + `_install_contract`. |
| [static/core/contract.py](static/core/contract.py) | `FrozenCaseContract` schema, loader, lockfile sealing/verification. |
| [static/core/runtime_context.py](static/core/runtime_context.py) | Process-wide contract holder (`set_contract` / `get_optional_contract`). |
| [static/core/subprocess_env.py](static/core/subprocess_env.py) | Builds the env dict for child processes from the contract. |
| [scripts/check_no_env_reads.py](scripts/check_no_env_reads.py) | AST linter forbidding `os.environ` reads outside the allowlist. |
| [static/cli/preflight.py](static/cli/preflight.py) | 5-layer preflight. |
| [static/cli/workflow.py](static/cli/workflow.py) | Static pipeline phases, per-tool status reporting, severity-gate enforcement. |
| [static/scanners/orchestrator.py](static/scanners/orchestrator.py) | Phase scheduler; collects `phase_failures` and `phase_timings`. |
| [threat_base/updater.py](threat_base/updater.py) | Threat data refresh; routes through `assert_network_allowed`. |
| [dynamic/orchestrator.py](dynamic/orchestrator.py) | DAST orchestrator. |
| [static/core/paths.py](static/core/paths.py) | Single source of truth for storage locations. |
