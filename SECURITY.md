# Security Policy

[![Security Policy](https://img.shields.io/badge/Security-Responsible_Disclosure-blueviolet?logo=hackthebox&logoColor=white)](#reporting-a-vulnerability)
[![Version](https://img.shields.io/badge/Supported-v2.0.x-green.svg)](#supported-versions)

## Disclaimer

> **REDACTS is a forensic analysis _aid_.** It assists investigators but **does not replace** and **cannot substitute for** thorough manual review by qualified security professionals. Results are **not guaranteed** to be complete or definitive. Use REDACTS as an **auxiliary tool** within your incident response workflow, **not** as the sole basis for security decisions.
>
> REDACTS does **not** modify, patch, or alter the files it scans. It is not affiliated with or endorsed by Vanderbilt University or the REDCap Consortium. REDCap® is a registered trademark of Vanderbilt University.
>
> © 2024–2026 The Adimension / Shehab Anwer — <atrium@theadimension.com> · <shehab.anwer@gmail.com>

## Supported Versions

| Version | Supported |
|---------|:---------:|
| 2.0.x   | Yes       |
| < 2.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in REDACTS itself (not in a REDCap installation being scanned), please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email **<atrium@theadimension.com>** or **<shehab.anwer@gmail.com>** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive an acknowledgment within 48 hours
4. A fix will be prioritized based on severity

## Scope

This policy covers vulnerabilities in the REDACTS scanner tool itself, such as:

- Command injection through crafted file names or paths
- Arbitrary code execution via malicious input files
- Information disclosure from scanner output
- Dependency vulnerabilities in REDACTS's toolchain

This policy does **not** cover vulnerabilities in REDCap — report those to the [REDCap Consortium](https://projectredcap.org) directly.

## Threat Model

REDACTS processes untrusted input (potentially compromised REDCap installations). The scanner is designed to:

- Never execute PHP code from scanned files
- Run external tools (Semgrep, Trivy) in sandboxed contexts
- Hash and classify files without interpreting their contents
- Produce read-only reports with no write-back to source

If you find a way to violate these guarantees, that is a reportable vulnerability.
