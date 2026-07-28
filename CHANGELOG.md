# Changelog

All notable changes to REDACTS are documented here. This project adheres to
[Semantic Versioning](https://semver.org/). Dates are ISO-8601 (UTC).

## [4.0.0] - 2026-07-24

A security-and-correctness hardening release. Several fixes change observable
behavior, so this is a **major** version. Please read **Breaking changes**
before upgrading.

### ⚠️ Breaking changes (read before upgrading)

- **Python 3.14 is no longer supported for scanning.** Semgrep - the primary
  PHP code scanner - installs on 3.14 but its engine does not run there. REDACTS
  now detects this and **fails Semgrep as non-functional** in `preflight`
  (rather than silently reporting a scan that never ran). **Use Python 3.13 or
  3.12.**
- **Repomix now runs as a Python package**, not the Node CLI. `node`, `npm`, and
  `npx` are **no longer host requirements**. Reinstall dependencies with
  `pip install -r requirements.txt`.
- **The severity gate now spans every analysis layer** (tool scan **and** deep
  investigation, baseline structural changes, and the overall risk verdict).
  Scans that previously exited `0` may now exit `2` when a real forensic finding
  is at or above `[static].severity_gate`. CI thresholds should be reviewed.
- **`[static].scanners` is now honored.** A scanner omitted from the contract no
  longer runs even if it is installed (previously the selection was ignored).
- **Docker is required only for dynamic (DAST) mode.** A static-only scan treats
  a missing Docker as `WARN`, not a blocking failure.
- **REDCap root detection now descends to the versioned application root**
  (`redcap_vX.Y.Z/`). This aligns the official REDCap *source* package (which
  nests the app under an installer wrapper) with a *deployed* tree, so a
  baseline diff between them is meaningful instead of reporting every file as
  changed.

### Security

- **Removed a Windows command-injection surface.** Subprocess resolution no
  longer routes `.cmd`/`.bat` shims through `cmd.exe` (a path where an argument
  such as `target.zip&whoami` could execute); `.ps1` execution-policy bypass was
  removed; and Repomix now runs in-process, eliminating the `npx` shim entirely.
- **The exit-code severity gate is no longer blind to forensic findings.** A
  scan could report CRITICAL risk with a HIGH finding yet exit `0`, so CI would
  pass a compromised deployment. The gate now evaluates all analysis layers.
- **Semgrep silent no-op is surfaced, not masked.** On unsupported runtimes
  Semgrep exited cleanly with no output; REDACTS reported "0 findings." Preflight
  now fails it as non-functional and the scan reports a coverage gap.
- **The contract seal now covers CLI overrides.** A sealed `case.toml.lock`
  refuses `--target` / `--reference` / `--severity-gate` / `--timeout` overrides
  that would change the sealed surface, instead of running an unsealed config.

### Added

- `SETUP.md` - a complete, per-OS environment-preparation and preflight guide.
- `init` wizard (`python main.py init`) for first-time users: hashes inputs,
  detects available scanners, and writes a valid `case.toml`.
- Guided error-recovery messages and per-report identity banners (each report
  states whether it is the Forensic, Audit, or SARIF output and names its
  companions).
- ~180 new tests (total **887 passing**).

### Changed

- **Single tool-resolution path** shared by preflight, the scan, and `init`.
  Preflight now finds `pip install --user` console scripts (e.g. `semgrep.exe`),
  so it no longer blocks a tool that would actually run.
- **Network and ATT&CK-bundle checks are `WARN`**, so offline / air-gapped and
  `[security].network_disabled = true` runs proceed on cached/bundled data.
- **Bundled-artifact noise removed.** A `repomix-output.*` dump (a whole-codebase
  bundle) is excluded from line-by-line content scanning - it was flooding
  reports with hundreds of re-detections - while still reported as an added file
  and still content-typed by Magika.
- Missing CWE data prints a one-time "reduced enrichment" notice and continues,
  rather than prompting mid-scan.
- Report renderers de-duplicated; the HTML audit report was rebuilt as a
  structured, self-contained document.
- Documentation corrected throughout (recommended Python version, Node.js no
  longer required, static scans need no Docker, and the three report types).

### Fixed

- `--case` given before a subcommand is no longer ignored; a bare `redacts`
  invocation no longer crashes.
- The error classifier no longer misclassifies ordinary failures as a
  severity-gate trip or a missing dependency, and no longer rewrites exit codes.
- Large archives are hashed with streamed I/O (no longer read fully into memory).
- Console output no longer drops text that looks like a `[section]` tag.

### Upgrade notes

1. Recreate your virtual environment on **Python 3.13** (or 3.12) and
   `pip install -r requirements.txt -r requirements-dev.txt`.
2. You can uninstall Node.js/`npx` if it was only present for REDACTS.
3. Re-run `python main.py preflight` to confirm the new functional checks pass.
4. If you gate CI on the exit code, note that `2` (severity gate) now reflects
   findings from all analysis layers.

## [3.0.0]

Baseline release. See the Git history for details.
