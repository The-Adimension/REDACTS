# Data handling

This document describes what REDACTS reads from disk, what it writes, and
what it does not do. It is intended for analysts running the tool against
trees that may contain protected health information.

## Inputs

REDACTS reads only what `case.toml` declares:

| Section | What is read |
|---|---|
| `[inputs.target]` | The audited tree. Local path, ZIP / TAR / 7z / RAR archive, HTTP(S) URL, or SFTP URL. |
| `[inputs.reference]` | The known-good baseline used for the differential audit. Same shape as the target. |
| `[inputs.upgrade_package]` | Optional REDCap upgrade package, when an upgrade-flow audit is in scope. |
| `[threat_base.sources.*]` | CWE / NVD / ATT&CK STIX / YARA-rules feeds. Each entry pins a URL and a SHA-256. |

Local paths must declare a `sha256`. The collect layer verifies the digest
before any analyser sees the bytes; mismatch aborts the run.

The tool **does not** scan filesystems outside the declared inputs. There is
no auto-discovery, no recursive walk of `/`, no probing of network shares
beyond the URLs in `case.toml`.

## Outputs

Reports and artefacts are written under the storage roots declared in
`[paths]`:

| Root | Purpose |
|---|---|
| `output_root` | Per-run report directory (`scan_<timestamp>/`). JSON, Markdown, HTML, and SARIF v2.1.0 outputs. |
| `temp_root` | Extraction sandbox for archives and DAST runtime state. |
| `cache_root` | Threat-base downloads, image manifests. |
| `tools_root` | Auto-installed Trivy / YARA binaries (only when the analyst opts in). |
| `logs_root` | Run logs at the level set in `[logging]`. |
| `audit_trail` | Append-only NDJSON of phase boundaries and tool invocations. |

Reports include file paths, hashes, and code excerpts from the audited
tree. Treat the `output_root` directory with the same care you give the
audited tree itself.

## Network

- Static analysis is offline. No outbound network.
- The DAST stack runs on loopback only; `[dynamic.network].base_url`
  defaults to `http://localhost:8585` and `[dynamic.network].internal_hosts`
  whitelists the loopback addresses the test suites are allowed to reach.
- Threat-base updates are explicit. They run only when `python main.py
  update` is invoked, or when `[threat_base].auto_update = true` (default
  is `false`). Each fetch is digest-pinned.
- HTTP / SFTP collection is allowed only against URLs the analyst writes
  into `case.toml`.

## Environment variables

REDACTS does not consume environment variables for configuration. Setting
`REDACTS_*`, `DAST_*`, `REDCAP_*`, or `PLAYWRIGHT_*` in the parent shell
causes the contract loader to abort at startup. Place every value in
`case.toml`. The invariant is enforced at CI time by
`scripts/check_no_env_reads.py`.

The DAST orchestrator does inject a small set of `REDCAP_*` variables into
the **child** containers it boots. Those values are derived from
`[dynamic.credentials]` and `[dynamic.network]` and never inherited from
the analyst's shell.

## Cleanup

REDACTS does not delete `output_root`, `audit_trail`, or `logs_root`. The
analyst is the owner of those artefacts and decides retention. `temp_root`
is cleared at the end of a run unless `[dynamic].keep_stack = true` (used
for post-mortem debugging of a failed DAST run).

## What REDACTS does not do

- It does not perform forensic acquisition. Use `dd`, `ewfacquire`, or
  `aff4` for that.
- It does not phone home. There is no telemetry, no usage reporting, no
  crash uploader.
- It does not modify the audited tree. The tree is opened read-only; the
  static pipeline operates on a SHA-256-anchored copy under `temp_root`.
- It does not authenticate to live REDCap deployments. The DAST stack
  boots its own loopback REDCap container.
