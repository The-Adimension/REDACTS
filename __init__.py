"""
REDACTS - REDCap Arbitrary Code Threat Scan
=============================================

Forensic security scanner for REDCap installations.

Tools: Semgrep, Trivy, YARA, tree-sitter, Magika, DAST (Playwright)

Usage:
    python -m REDACTS

DISCLAIMER:
    REDACTS is a forensic analysis AID. It is designed to assist security
    teams in investigating REDCap installations, but it does NOT replace
    and cannot substitute for thorough manual review by qualified
    professionals. Results are not guaranteed to be complete or definitive.
    Use as an auxiliary tool within your incident response workflow, not
    as the sole basis for security decisions.

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
Contact: atrium@theadimension.com
"""

__version__ = "2.0.0"
__author__ = "The Adimension / Shehab Anwer"

from .core import REDACTSConfig
