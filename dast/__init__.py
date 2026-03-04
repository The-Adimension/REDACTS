"""
REDACTS DAST — Dynamic Application Security Testing
=====================================================
Playwright-driven headless testing of live REDCap instances.

Suites:
    - export:  Report save/export — SEC070, SEC076, SEC074
    - admin:   Admin access / user rights — SEC077, SEC071, SEC021
    - upgrade: REDCap upgrade flow — SEC060-062, SEC063, SEC065
"""

from .orchestrator import DASTOrchestrator, DASTResult

__all__ = ["DASTOrchestrator", "DASTResult"]
