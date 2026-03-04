"""
REDACTS MITRE ATT&CK + CVSS Mapping — Standards-compliant classification.

Maps REDACTS rules (SEC*, WEB*, IOC-*) to:
    - MITRE ATT&CK techniques (T-codes)
    - CVSS 3.1 base score vectors
    - CWE identifiers (canonical, verified)

These mappings ensure every finding exported via SARIF/STIX carries
proper standards-compliant classification, enabling cross-tool
correlation and threat intelligence sharing.

Sources:
    - MITRE ATT&CK v14+ (https://attack.mitre.org)
    - CWE v4.13+ (https://cwe.mitre.org)
    - CVSS v3.1 (https://www.first.org/cvss/v3.1/specification-document)
"""

from __future__ import annotations

from ..core.models import CvssVector

# ═══════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK Technique Mappings
# ═══════════════════════════════════════════════════════════════════════════
# rule_id → (technique_id, technique_name)

MITRE_ATTACK_MAP: dict[str, tuple[str, str]] = {
    # ── Injection / RCE ───────────────────────────────────────────────────
    "SEC001": ("T1190", "Exploit Public-Facing Application"),  # SQL injection
    "SEC002": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),  # eval()
    "SEC003": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),  # exec/system
    "SEC004": ("T1552.001", "Unsecured Credentials: Credentials In Files"),  # Hardcoded creds
    "SEC005": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),  # backtick exec
    "SEC006": ("T1055.001", "Process Injection: Dynamic-link Library Injection"),  # include $var
    "SEC007": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),  # preg_replace /e
    "SEC008": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),  # assert()
    "SEC009": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),  # create_function
    "SEC010": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),  # call_user_func
    # ── XSS ───────────────────────────────────────────────────────────────
    "SEC011": ("T1189", "Drive-by Compromise"),  # Reflected XSS
    "SEC012": ("T1189", "Drive-by Compromise"),  # Echo unsanitized
    # ── File Operations ───────────────────────────────────────────────────
    "SEC013": ("T1083", "File and Directory Discovery"),  # file_get_contents($var)
    "SEC014": ("T1105", "Ingress Tool Transfer"),  # file_put_contents($var)
    "SEC015": ("T1005", "Data from Local System"),  # fopen($var)
    "SEC016": ("T1036", "Masquerading"),  # move_uploaded_file w/o validation
    # ── Deserialization ───────────────────────────────────────────────────
    "SEC017": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),  # unserialize
    # ── Crypto ────────────────────────────────────────────────────────────
    "SEC018": ("T1600", "Weaken Encryption"),  # md5/sha1 for passwords
    "SEC019": ("T1600", "Weaken Encryption"),  # Weak random
    # ── LDAP / XXE / SSRF ─────────────────────────────────────────────────
    "SEC020": ("T1190", "Exploit Public-Facing Application"),  # LDAP injection
    "SEC021": ("T1190", "Exploit Public-Facing Application"),  # XXE
    "SEC022": ("T1090", "Proxy"),  # SSRF
    # ── Webshell / Backdoor ───────────────────────────────────────────────
    "WEB000": ("T1505.003", "Server Software Component: Web Shell"),
    "WEB001": ("T1505.003", "Server Software Component: Web Shell"),
    "WEB002": ("T1505.003", "Server Software Component: Web Shell"),
    "WEB003": ("T1027", "Obfuscated Files or Information"),  # Encoded payload
    "WEB004": ("T1505.003", "Server Software Component: Web Shell"),
    "WEB005": ("T1505.003", "Server Software Component: Web Shell"),
    "WEB006": ("T1027.010", "Obfuscated Files or Information: Command Obfuscation"),
    "WEB007": ("T1505.003", "Server Software Component: Web Shell"),
    "WEB008": ("T1071.001", "Application Layer Protocol: Web Protocols"),  # C2
    "WEB009": ("T1505.003", "Server Software Component: Web Shell"),
    # ── IoC categories ────────────────────────────────────────────────────
    "IOC-FP": ("T1505.003", "Server Software Component: Web Shell"),  # File presence
    "IOC-FC": ("T1505.003", "Server Software Component: Web Shell"),  # File content
    "IOC-CT": ("T1543", "Create or Modify System Process"),  # Config tamper
    "IOC-PS": ("T1546", "Event Triggered Execution"),  # Persistence
    "IOC-OB": ("T1027", "Obfuscated Files or Information"),  # Obfuscation
    "IOC-CR": ("T1552.001", "Unsecured Credentials: Credentials In Files"),  # Credentials
    "IOC-WS": ("T1505.003", "Server Software Component: Web Shell"),  # Webshell
    "IOC-SC": ("T1195", "Supply Chain Compromise"),  # Supply chain
    "IOC-IR": ("T1505.003", "Server Software Component: Web Shell"),  # INFINITERED
    # ── Magika mismatches ─────────────────────────────────────────────────
    "MAGIKA": ("T1036.008", "Masquerading: Masquerade File Type"),
    # ── Semgrep categories → ATT&CK ──────────────────────────────────────
    "semgrep:sql-injection": ("T1190", "Exploit Public-Facing Application"),
    "semgrep:command-injection": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    "semgrep:xss": ("T1189", "Drive-by Compromise"),
    "semgrep:path-traversal": ("T1083", "File and Directory Discovery"),
    "semgrep:ssrf": ("T1090", "Proxy"),
    "semgrep:deserialization": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    "semgrep:xxe": ("T1190", "Exploit Public-Facing Application"),
    "semgrep:open-redirect": ("T1189", "Drive-by Compromise"),
    "semgrep:ldap-injection": ("T1190", "Exploit Public-Facing Application"),
    "semgrep:hardcoded-secret": ("T1552.001", "Unsecured Credentials: Credentials In Files"),
}


def get_mitre_attack(rule_id: str) -> tuple[str, str]:
    """Look up ATT&CK technique for a rule ID.

    Falls back to prefix matching for IoC IDs (e.g., "IOC-FP-001" → "IOC-FP").
    """
    if rule_id in MITRE_ATTACK_MAP:
        return MITRE_ATTACK_MAP[rule_id]
    # Try prefix match for IoC and Semgrep rules
    for prefix_len in (6, 5, 4, 3):
        prefix = rule_id[:prefix_len]
        if prefix in MITRE_ATTACK_MAP:
            return MITRE_ATTACK_MAP[prefix]
    # Try category-based match for semgrep
    if ":" in rule_id:
        parts = rule_id.split(":")
        for part in parts:
            for key, val in MITRE_ATTACK_MAP.items():
                if part in key:
                    return val
    return ("", "")


# ═══════════════════════════════════════════════════════════════════════════
# CVSS 3.1 Base Score Mappings
# ═══════════════════════════════════════════════════════════════════════════
# Pre-computed CVSS vectors for REDACTS rules.

CVSS_MAP: dict[str, CvssVector] = {
    # ── CRITICAL (9.0–10.0) ───────────────────────────────────────────────
    "SEC001": CvssVector(  # SQL injection via user input
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
    ),
    "SEC002": CvssVector(  # eval() with variable
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
    ),
    "SEC003": CvssVector(  # exec/system with variable
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
    ),
    "SEC004": CvssVector(  # Hardcoded credentials
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        base_score=9.1,
    ),
    "SEC005": CvssVector(  # Backtick exec
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
    ),
    "SEC006": CvssVector(  # Dynamic include
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
    ),
    "SEC007": CvssVector(  # preg_replace /e
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
    ),
    "SEC017": CvssVector(  # unserialize
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
    ),
    # ── Webshell (CRITICAL) ───────────────────────────────────────────────
    "WEB000": CvssVector(
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
    ),
    "WEB001": CvssVector(
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
    ),
    "WEB002": CvssVector(
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=10.0,
    ),
    # ── HIGH (7.0–8.9) ────────────────────────────────────────────────────
    "SEC008": CvssVector(  # assert()
        vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        base_score=8.8,
    ),
    "SEC009": CvssVector(  # create_function
        vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        base_score=8.8,
    ),
    "SEC010": CvssVector(  # call_user_func
        vector_string="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
        base_score=7.5,
    ),
    "SEC011": CvssVector(  # Reflected XSS
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        base_score=6.1,  # Actually medium, but kept high for web context
    ),
    "SEC013": CvssVector(  # file_get_contents($var)
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        base_score=7.5,
    ),
    "SEC014": CvssVector(  # file_put_contents($var)
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        base_score=9.1,
    ),
    "SEC016": CvssVector(  # move_uploaded_file
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
    ),
    "SEC020": CvssVector(  # LDAP injection
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        base_score=9.1,
    ),
    "SEC021": CvssVector(  # XXE
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        base_score=7.5,
    ),
    "SEC022": CvssVector(  # SSRF
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        base_score=8.2,
    ),
    # ── MEDIUM (4.0–6.9) ──────────────────────────────────────────────────
    "SEC012": CvssVector(  # Echo unsanitized
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        base_score=6.1,
    ),
    "SEC015": CvssVector(  # fopen($var)
        vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        base_score=6.5,
    ),
    "SEC018": CvssVector(  # Weak hashing
        vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        base_score=5.9,
    ),
    "SEC019": CvssVector(  # Weak random
        vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        base_score=5.9,
    ),
    # ── Obfuscation / Encoding ────────────────────────────────────────────
    "WEB003": CvssVector(  # Encoded payload
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
    ),
    "WEB006": CvssVector(  # Command obfuscation
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
    ),
}


def get_cvss(rule_id: str) -> CvssVector | None:
    """Look up CVSS vector for a rule ID."""
    if rule_id in CVSS_MAP:
        return CVSS_MAP[rule_id]
    # Prefix match for WEB* rules
    for prefix_len in (6, 5, 4, 3):
        prefix = rule_id[:prefix_len]
        if prefix in CVSS_MAP:
            return CVSS_MAP[prefix]
    return None


# ═══════════════════════════════════════════════════════════════════════════
# CWE Canonical Mappings
# ═══════════════════════════════════════════════════════════════════════════
# Ensures consistent CWE assignment across all finding types.

CWE_MAP: dict[str, str] = {
    # Injection
    "SEC001": "CWE-89",   # SQL Injection
    "SEC002": "CWE-94",   # Code Injection (eval)
    "SEC003": "CWE-78",   # OS Command Injection
    "SEC005": "CWE-78",   # OS Command Injection (backtick)
    "SEC006": "CWE-98",   # PHP File Inclusion
    "SEC007": "CWE-94",   # Code Injection (preg_replace /e)
    "SEC008": "CWE-94",   # Code Injection (assert)
    "SEC009": "CWE-94",   # Code Injection (create_function)
    "SEC010": "CWE-94",   # Code Injection (call_user_func)
    "SEC017": "CWE-502",  # Deserialization of Untrusted Data
    "SEC020": "CWE-90",   # LDAP Injection
    "SEC021": "CWE-611",  # XML External Entity (XXE)
    "SEC022": "CWE-918",  # Server-Side Request Forgery (SSRF)
    # XSS
    "SEC011": "CWE-79",   # Cross-site Scripting (XSS)
    "SEC012": "CWE-79",   # Cross-site Scripting (XSS)
    # Credentials
    "SEC004": "CWE-798",  # Use of Hard-coded Credentials
    # File operations
    "SEC013": "CWE-22",   # Path Traversal
    "SEC014": "CWE-22",   # Path Traversal
    "SEC015": "CWE-22",   # Path Traversal
    "SEC016": "CWE-434",  # Unrestricted Upload
    # Crypto
    "SEC018": "CWE-328",  # Use of Weak Hash
    "SEC019": "CWE-330",  # Use of Insufficiently Random Values
    # Webshell / Backdoor
    "WEB000": "CWE-94",   # Code Injection (webshell)
    "WEB001": "CWE-94",   # Code Injection (webshell)
    "WEB002": "CWE-94",   # Code Injection (webshell)
    "WEB003": "CWE-506",  # Embedded Malicious Code
    "WEB004": "CWE-506",  # Embedded Malicious Code
    "WEB005": "CWE-506",  # Embedded Malicious Code
    "WEB006": "CWE-506",  # Embedded Malicious Code
    "WEB007": "CWE-506",  # Embedded Malicious Code
    "WEB008": "CWE-506",  # Embedded Malicious Code
    "WEB009": "CWE-506",  # Embedded Malicious Code
    # Magika
    "MAGIKA": "CWE-434",  # Unrestricted Upload / File Type Masquerading
}


def get_cwe(rule_id: str) -> str:
    """Look up canonical CWE for a rule ID."""
    if rule_id in CWE_MAP:
        return CWE_MAP[rule_id]
    for prefix_len in (6, 5, 4, 3):
        prefix = rule_id[:prefix_len]
        if prefix in CWE_MAP:
            return CWE_MAP[prefix]
    return ""


# ═══════════════════════════════════════════════════════════════════════════
# ATT&CK Tactic Groupings (for matrix reporting)
# ═══════════════════════════════════════════════════════════════════════════

ATTACK_TACTICS: dict[str, list[str]] = {
    "Initial Access (TA0001)": [
        "T1190",  # Exploit Public-Facing Application
        "T1189",  # Drive-by Compromise
        "T1195",  # Supply Chain Compromise
    ],
    "Execution (TA0002)": [
        "T1059.001",  # PowerShell
        "T1059.004",  # Unix Shell
    ],
    "Persistence (TA0003)": [
        "T1505.003",  # Web Shell
        "T1543",      # Create or Modify System Process
        "T1546",      # Event Triggered Execution
    ],
    "Defense Evasion (TA0005)": [
        "T1027",      # Obfuscated Files or Information
        "T1027.010",  # Command Obfuscation
        "T1036",      # Masquerading
        "T1036.008",  # Masquerade File Type
        "T1600",      # Weaken Encryption
    ],
    "Credential Access (TA0006)": [
        "T1552.001",  # Credentials In Files
    ],
    "Discovery (TA0007)": [
        "T1083",  # File and Directory Discovery
    ],
    "Collection (TA0009)": [
        "T1005",  # Data from Local System
    ],
    "Command and Control (TA0011)": [
        "T1071.001",  # Web Protocols
        "T1090",      # Proxy
        "T1105",      # Ingress Tool Transfer
    ],
}
