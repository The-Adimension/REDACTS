"""KnowledgeSession - single-instance factory for the threat-base.

The four knowledge databases (CWE, MITRE ATT&CK, IoC indicators,
sensitive-data patterns) all sit on top of integrity-verified YAML
files. Loading is non-trivial (SHA-256 verification + parsing), so we
centralise it here and pass one session through the whole pipeline
rather than reloading per component. Lazy attributes mean a run that
never needs MITRE never pays for it.

Usage::

    session = KnowledgeSession()
    investigator = Investigator(
        config,
        ioc_db=session.ioc_db,
        attack_db=session.attack_vector_db,
        sensitive_scanner=session.sensitive_scanner,
    )

Copyright 2024-2026 The Adimension / Shehab Anwer
Apache-2.0.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .attack_knowledge import AttackKnowledge
    from .attack_vectors import AttackVectorDatabase
    from .cwe_database import CweDatabase
    from .ioc_database import IoCDatabase
    from .sensitive_data import SensitiveDataScanner
    from static.analyze.scanner import SecurityScanner

logger = logging.getLogger(__name__)


class KnowledgeSession:
    """Lazy factory that creates and caches all knowledge sources.

    Each property is initialized on first access and then cached for
    the lifetime of the session.  This avoids:

    - Duplicate YAML/STIX parsing across investigator, pipeline, and exporter
    - Import-time side effects (data files are loaded only when needed)
    - Hard-wired constructor defaults scattered across modules
    """

    def __init__(self) -> None:
        self._attack_knowledge: AttackKnowledge | None = None
        self._attack_vector_db: AttackVectorDatabase | None = None
        self._ioc_db: IoCDatabase | None = None
        self._sensitive_scanner: SensitiveDataScanner | None = None
        self._cwe_db: CweDatabase | None = None
        self._security_scanner: SecurityScanner | None = None

    # Lazy properties

    @property
    def attack_knowledge(self) -> AttackKnowledge:
        """ATT&CK Enterprise STIX 2.1 accessor (techniques + mitigations)."""
        if self._attack_knowledge is None:
            from .attack_knowledge import AttackKnowledge

            self._attack_knowledge = AttackKnowledge()
            logger.debug("KnowledgeSession: AttackKnowledge initialized")
        return self._attack_knowledge

    @property
    def attack_vector_db(self) -> AttackVectorDatabase:
        """30+ attack vector definitions from YAML."""
        if self._attack_vector_db is None:
            from .attack_vectors import AttackVectorDatabase

            self._attack_vector_db = AttackVectorDatabase()
            logger.debug("KnowledgeSession: AttackVectorDatabase initialized")
        return self._attack_vector_db

    @property
    def ioc_db(self) -> IoCDatabase:
        """Indicators of Compromise database."""
        if self._ioc_db is None:
            from .ioc_database import IoCDatabase

            self._ioc_db = IoCDatabase()
            logger.debug("KnowledgeSession: IoCDatabase initialized")
        return self._ioc_db

    @property
    def sensitive_scanner(self) -> SensitiveDataScanner:
        """PHI / credentials / PII pattern scanner."""
        if self._sensitive_scanner is None:
            from .sensitive_data import SensitiveDataScanner

            self._sensitive_scanner = SensitiveDataScanner()
            logger.debug("KnowledgeSession: SensitiveDataScanner initialized")
        return self._sensitive_scanner

    @property
    def cwe_db(self) -> CweDatabase:
        """CWE weakness database (names + recommendations)."""
        if self._cwe_db is None:
            from .cwe_database import CweDatabase

            self._cwe_db = CweDatabase()
            logger.debug("KnowledgeSession: CweDatabase initialized")
        return self._cwe_db

    @property
    def security_scanner(self) -> SecurityScanner:
        """Regex-based security scanner (57+ YAML-compiled rules)."""
        if self._security_scanner is None:
            from static.analyze.scanner import SecurityScanner

            self._security_scanner = SecurityScanner()
            logger.debug("KnowledgeSession: SecurityScanner initialized")
        return self._security_scanner
