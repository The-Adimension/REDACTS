"""
REDACTS Analyze Module (Phase C Domain) - Investigation & Forensic Analysis.

Merges investigation orchestration with forensic analysis engines.

Components:
    - investigator.py: Tier 2 investigation orchestrator
    - steps.py: 8 concrete investigation steps
    - step_protocol.py: InvestigationStep protocol + context
    - scanner.py: Security scanning engine (regex-based)
    - rules.py: Security analysis rule definitions
    - database_forensics.py: Database.php forensic analysis
    - upgrade_analyzer.py: REDCap upgrade forensics
"""

# Namespace package: import directly from submodules.
__all__: list[str] = []
