# Security Policy

## Supported versions

| Version | Status |
|---|---|
| 3.0.x | Supported |
| 2.x | End of life. Not patched. |

## Reporting a vulnerability

Email **`atrium@theadimension.com`** with:

- A description of the issue.
- Steps to reproduce, including the version and platform.
- Any proof-of-concept input or output you can share.

Please do **not** open a public GitHub issue or pull request for security
reports.

Acknowledgement is sent within 7 days. A coordinated-disclosure timeline is
agreed once the report is confirmed. The default embargo is 90 days from
acknowledgement; longer windows are negotiated when a fix requires a
threat-base or container-image update.

## Out of scope

REDACTS analyses third-party REDCap installations. Findings about REDCap
itself, Vanderbilt-shipped code, or any non-REDACTS dependency belong with
their respective upstream projects, not here.

The dynamic-analysis stack (Playwright, Docker images for MariaDB / PHP /
Chromium) is intentionally exposed only on loopback. Vulnerabilities in
those upstream images should be reported to the image maintainers; this
repository does not redistribute them.

## Hardening notes

- Production code paths read configuration only from `case.toml`. The
  invariant is enforced by `scripts/check_no_env_reads.py`.
- `case.toml.lock` seals a SHA-256 of the canonical contract; mismatch
  aborts the run with `exit 2`.
- Threat-base sources (CWE, NVD, ATT&CK STIX, YARA) are pinned by SHA-256
  in `[threat_base.sources.*]`; the loader refuses content that does not
  match.
- Tool images for the DAST stack are referenced by content digest in
  `[dynamic.images.*]`, not by floating tag.
