"""
REDACTS Attack Vector Database — filesystem-detectable attack vectors for REDCap.

Defines 30+ attack vectors organized into 7 categories (A–G) that a filesystem
forensic tool can detect in a REDCap PHP web application. REDCap uses MySQL
exclusively; any SQLite artifact is anomalous and linked to the INFINITERED
campaign (Dec 2025 – Feb 2026).

Each vector includes filesystem artifacts, detection patterns, conclusiveness,
and cross-references to IoC IDs defined in ``ioc_database.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# — Categories —

CATEGORY_A = "DATABASE_TO_FILESYSTEM"
CATEGORY_B = "FEATURE_ABUSE"
CATEGORY_C = "CONFIG_PERSISTENCE"
CATEGORY_D = "SUPPLY_CHAIN"
CATEGORY_E = "SERVER_CONFIG"
CATEGORY_F = "PHP_RUNTIME"
CATEGORY_G = "ADDITIONAL"

ALL_CATEGORIES: list[str] = [
    CATEGORY_A,
    CATEGORY_B,
    CATEGORY_C,
    CATEGORY_D,
    CATEGORY_E,
    CATEGORY_F,
    CATEGORY_G,
]


@dataclass
class AttackVector:
    """A single attack vector detectable via filesystem forensics."""

    id: str
    name: str
    description: str
    category: str
    subcategory: str
    filesystem_artifacts: list[str] = field(default_factory=list)
    detection_patterns: list[str] = field(default_factory=list)
    conclusiveness: str = "suspicious"  # conclusive | suspicious | informational
    severity: str = "MEDIUM"
    detection_method: str = ""
    redacts_coverage: str = "none"  # covered | partial | none
    related_iocs: list[str] = field(default_factory=list)
    out_of_scope_note: str = ""


class AttackVectorDatabase:
    """
    Structured knowledge base of filesystem-detectable attack vectors.

    Instantiation builds the full vector catalogue. Query helpers expose
    vectors by category, conclusiveness, and filesystem-detectability.
    """

    def __init__(self) -> None:
        self._vectors: list[AttackVector] = []
        self._by_id: dict[str, AttackVector] = {}
        self._by_category: dict[str, list[AttackVector]] = {}
        self._by_conclusiveness: dict[str, list[AttackVector]] = {}
        self._build_database()

    # — public properties —

    @property
    def all_vectors(self) -> list[AttackVector]:
        """Every attack vector in the database."""
        return list(self._vectors)

    # — internal —

    def _register(self, vector: AttackVector) -> None:
        self._vectors.append(vector)
        self._by_id[vector.id] = vector
        self._by_category.setdefault(vector.category, []).append(vector)
        self._by_conclusiveness.setdefault(vector.conclusiveness, []).append(vector)

    def _build_database(self) -> None:
        """Build the complete vector catalogue."""
        self._build_category_a()
        self._build_category_b()
        self._build_category_c()
        self._build_category_d()
        self._build_category_e()
        self._build_category_f()
        self._build_category_g()

    # ================================================================
    # A — DATABASE_TO_FILESYSTEM
    # ================================================================

    def _build_category_a(self) -> None:
        self._register(
            AttackVector(
                id="AV-A-001",
                name="SQLite persistence (redcap.db)",
                description=(
                    "REDCap uses MySQL exclusively. A SQLite database file "
                    "(redcap.db / redcap_.db) in any webroot directory is a "
                    "conclusive indicator of the INFINITERED campaign, used as "
                    "a C2 side-channel and data-staging area."
                ),
                category=CATEGORY_A,
                subcategory="SQLite persistence",
                filesystem_artifacts=[
                    "**/redcap.db",
                    "**/redcap_.db",
                    "**/redcap.db-wal",
                    "**/redcap.db-journal",
                    "**/redcap.db-shm",
                ],
                detection_patterns=[
                    "file_exists: *.db in webroot",
                    "magic_bytes: SQLite format 3\\x00 header",
                    "sidecar_exists: -wal or -journal proves active writes",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="file_exists + magic_bytes",
                redacts_coverage="covered",
                related_iocs=["IOC-INF-001", "IOC-INF-002"],
                out_of_scope_note="Content-level analysis of SQLite tables requires database tooling.",
            )
        )

        self._register(
            AttackVector(
                id="AV-A-002",
                name="MySQL SELECT INTO OUTFILE",
                description=(
                    "An attacker with MySQL FILE privilege can write arbitrary "
                    "data to the filesystem via SELECT … INTO OUTFILE. The "
                    "resulting file is owned by the mysql user and world-readable."
                ),
                category=CATEGORY_A,
                subcategory="MySQL OUTFILE",
                filesystem_artifacts=[
                    "*.php files owned by mysql user in webroot",
                    "files in /var/lib/mysql-files/ with PHP content",
                    "newly created .php files with unexpected ownership",
                ],
                detection_patterns=[
                    "ownership_check: file owner == mysql/mysqld",
                    "content_regex: <?php in files owned by mysql",
                    "timestamp_anomaly: new PHP file with no corresponding deploy",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="file_ownership + content_check",
                redacts_coverage="partial",
                related_iocs=[],
                out_of_scope_note="Requires OS-level uid/gid metadata not always available in snapshot.",
            )
        )

        self._register(
            AttackVector(
                id="AV-A-003",
                name="Credential exfiltration via database.php copies",
                description=(
                    "Attacker creates copies of database.php (e.g. database.php.bak, "
                    ".database.php.swp, database_backup.php) to exfiltrate MySQL "
                    "credentials. Copies may be placed in web-accessible locations."
                ),
                category=CATEGORY_A,
                subcategory="Credential exfil",
                filesystem_artifacts=[
                    "database.php.bak",
                    "database.php.old",
                    "database.php.save",
                    ".database.php.swp",
                    "database_backup.php",
                    "db.php",
                    "database.php.dist",
                ],
                detection_patterns=[
                    "glob: database*.php* or *database*.bak",
                    "content_match: $hostname and $password in non-canonical paths",
                    "file_count: more than one file containing REDCap DB credentials",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="file_exists + content_check",
                redacts_coverage="covered",
                related_iocs=["IOC-CFG-001"],
            )
        )

        self._register(
            AttackVector(
                id="AV-A-004",
                name="MySQL general/slow log to webshell",
                description=(
                    "By setting general_log_file or slow_query_log_file to a "
                    ".php path under the webroot, an attacker can inject PHP "
                    "code via crafted SQL queries that is then executed by the "
                    "web server."
                ),
                category=CATEGORY_A,
                subcategory="Log-to-webshell",
                filesystem_artifacts=[
                    "*.php files containing '# Time:' or 'SET timestamp=' log markers",
                    "*.php files with MySQL general-log preamble lines",
                ],
                detection_patterns=[
                    "content_regex: /^/.*Time:.*\\d{6}/m in .php files",
                    "content_regex: SET timestamp=\\d+ inside PHP file",
                    "content_combo: MySQL log markers + <?php in same file",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="content_check",
                redacts_coverage="partial",
                related_iocs=[],
                out_of_scope_note="Confirming MySQL runtime config requires DB access, not filesystem.",
            )
        )

    # ================================================================
    # B — FEATURE_ABUSE
    # ================================================================

    def _build_category_b(self) -> None:
        self._register(
            AttackVector(
                id="AV-B-001",
                name="Hook injection (hook_functions.php)",
                description=(
                    "REDCap's hook_functions.php is sourced on every page load. "
                    "An attacker injecting code here—extra functions, eval "
                    "chains, or require statements—achieves persistent execution "
                    "without modifying core files."
                ),
                category=CATEGORY_B,
                subcategory="Hook injection",
                filesystem_artifacts=[
                    "hook_functions.php with functions not in HOOK_FUNCTION_NAMES whitelist",
                    "hook_functions.php containing eval/base64_decode/gzinflate calls",
                    "hook_functions.php with require/include of external paths",
                ],
                detection_patterns=[
                    "function_enum: function names not in whitelist set",
                    "content_regex: eval\\(|base64_decode\\(|gzinflate\\(",
                    "content_regex: (require|include)(_once)?\\s*[('\"]",
                    "hash_compare: SHA-256 vs known-good distribution hash",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="function_enum + content_check",
                redacts_coverage="covered",
                related_iocs=["IOC-INF-003", "IOC-INF-004"],
            )
        )

        self._register(
            AttackVector(
                id="AV-B-002",
                name="External Module backdoor",
                description=(
                    "Malicious External Module installed via the modules/ "
                    "directory. The EM has a valid config.json but contains "
                    "webshell code in its PHP classes or cron methods."
                ),
                category=CATEGORY_B,
                subcategory="External Module abuse",
                filesystem_artifacts=[
                    "modules/*/classes/*.php containing shell_exec/system/exec",
                    "modules/*/config.json with cron-enabled and suspicious PHP",
                    "modules/* with no matching entry in ExternalModules/config table",
                ],
                detection_patterns=[
                    "content_regex: \\b(shell_exec|system|passthru|exec|popen)\\s*\\(",
                    "content_regex: eval\\s*\\(\\s*\\$_(GET|POST|REQUEST)",
                    "structure_check: config.json present but module not in official EM repo",
                    "timestamp_anomaly: module dir mtime differs from deploy baseline",
                ],
                conclusiveness="suspicious",
                severity="CRITICAL",
                detection_method="content_check + structure_validation",
                redacts_coverage="covered",
                related_iocs=["IOC-SC-002"],
                out_of_scope_note="Verifying EM legitimacy requires the REDCap EM library API.",
            )
        )

        self._register(
            AttackVector(
                id="AV-B-003",
                name="Plugin webshell",
                description=(
                    "REDCap's plugins/ directory allows custom PHP pages. An "
                    "attacker can drop a webshell here disguised as a plugin, "
                    "reachable without REDCap authentication if misconfigured."
                ),
                category=CATEGORY_B,
                subcategory="Plugin abuse",
                filesystem_artifacts=[
                    "plugins/*.php containing eval/system/passthru",
                    "plugins/*.php not present in known-good manifest",
                    "plugins/*.php with obfuscated variable names or base64 blobs",
                ],
                detection_patterns=[
                    "content_regex: \\beval\\s*\\(|\\bsystem\\s*\\(|\\bpassthru\\s*\\(",
                    "entropy_check: high Shannon entropy indicating obfuscation",
                    "manifest_diff: file not in distribution manifest",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="content_check + manifest_diff",
                redacts_coverage="covered",
                related_iocs=["IOC-FP-001"],
            )
        )

        self._register(
            AttackVector(
                id="AV-B-004",
                name="edocs PHP upload",
                description=(
                    "PHP files uploaded to the edocs/ directory through a file "
                    "upload vulnerability or direct write. The edocs/ directory "
                    "should NEVER contain executable PHP."
                ),
                category=CATEGORY_B,
                subcategory="Upload abuse",
                filesystem_artifacts=[
                    "edocs/**/*.php",
                    "edocs/**/*.phtml",
                    "edocs/**/*.phar",
                    "edocs/**/*.php5",
                    "edocs/**/*.php7",
                ],
                detection_patterns=[
                    "extension_check: .php/.phtml/.phar in edocs/",
                    "htaccess_verify: edocs/.htaccess must contain 'php_flag engine off'",
                    "content_regex: <\\?php in any edocs/* file",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="file_location + extension_check",
                redacts_coverage="covered",
                related_iocs=["IOC-FP-001"],
            )
        )

        self._register(
            AttackVector(
                id="AV-B-005",
                name="cron.php manipulation",
                description=(
                    "REDCap's cron.php runs scheduled tasks. Modifications can "
                    "inject persistent execution that fires on every cron cycle "
                    "without admin visibility in the REDCap UI."
                ),
                category=CATEGORY_B,
                subcategory="Cron abuse",
                filesystem_artifacts=[
                    "cron.php with hash mismatch against distribution",
                    "cron.php containing eval/base64_decode/shell_exec",
                ],
                detection_patterns=[
                    "hash_compare: SHA-256 vs known-good cron.php hash",
                    "content_regex: (eval|base64_decode|shell_exec|file_get_contents)\\(",
                    "size_check: file size > expected baseline by significant margin",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="hash_compare + content_check",
                redacts_coverage="covered",
                related_iocs=["IOC-INF-004"],
            )
        )

        self._register(
            AttackVector(
                id="AV-B-006",
                name="API token harvest via filesystem",
                description=(
                    "Attacker-planted scripts that enumerate or dump REDCap API "
                    "tokens by including redcap_connect.php and querying the "
                    "redcap_user_rights table. Tokens enable silent data export."
                ),
                category=CATEGORY_B,
                subcategory="API abuse",
                filesystem_artifacts=[
                    "*.php files referencing redcap_user_rights and api_token",
                    "*.php files including redcap_connect.php from non-standard paths",
                    "temp/*.php or edocs/*.php containing db_query calls",
                ],
                detection_patterns=[
                    "content_regex: redcap_user_rights.*api_token",
                    "content_regex: require.*redcap_connect\\.php",
                    "file_location: PHP files in temp/ or edocs/ directories",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="content_check + file_location",
                redacts_coverage="partial",
                related_iocs=["IOC-FP-001"],
                out_of_scope_note="Actual API token usage is logged in REDCap's audit trail, not on disk.",
            )
        )

        self._register(
            AttackVector(
                id="AV-B-007",
                name="Survey template modification",
                description=(
                    "Modification of survey display templates to inject "
                    "credential-harvesting forms, JavaScript keyloggers, or "
                    "data-exfiltration beacons into participant-facing pages."
                ),
                category=CATEGORY_B,
                subcategory="Survey abuse",
                filesystem_artifacts=[
                    "Surveys/*.php with injected <script> or <iframe> tags",
                    "Resources/js/*.js files with unexpected external URLs",
                    "Surveys/survey_page.php with hash mismatch",
                ],
                detection_patterns=[
                    "content_regex: <script[^>]*src=['\"]https?://(?!REDCap-internal)",
                    "content_regex: <iframe\\s",
                    "hash_compare: Surveys/ PHP files vs distribution hashes",
                    "content_regex: XMLHttpRequest|fetch\\(.*external",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="hash_compare + content_check",
                redacts_coverage="partial",
                related_iocs=[],
                out_of_scope_note="JavaScript execution analysis requires browser-based DAST.",
            )
        )

    # ================================================================
    # C — CONFIG_PERSISTENCE
    # ================================================================

    def _build_category_c(self) -> None:
        self._register(
            AttackVector(
                id="AV-C-001",
                name="database.php poisoning",
                description=(
                    "database.php must contain EXACTLY a <?php tag and five "
                    "variable assignments ($hostname, $db, $username, $password, "
                    "$salt). Any additional code—functions, classes, includes, "
                    "or eval—constitutes a persistent backdoor executed on every "
                    "REDCap page load."
                ),
                category=CATEGORY_C,
                subcategory="database.php",
                filesystem_artifacts=[
                    "database.php containing functions or class definitions",
                    "database.php with require/include statements",
                    "database.php with eval/system/exec calls",
                    "database.php with variables beyond the allowed five",
                ],
                detection_patterns=[
                    "structure_validation: exactly 5 allowed variables",
                    "content_regex: \\bfunction\\s+\\w+\\s*\\(",
                    "content_regex: \\bclass\\s+\\w+",
                    "content_regex: (require|include)(_once)?\\s*[('\"]",
                    "content_regex: (eval|exec|system|passthru|shell_exec)\\s*\\(",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="structure_validation + content_check",
                redacts_coverage="covered",
                related_iocs=["IOC-CFG-001"],
            )
        )

        self._register(
            AttackVector(
                id="AV-C-002",
                name=".htaccess manipulation",
                description=(
                    ".htaccess files in the REDCap webroot can set "
                    "auto_prepend_file, enable PHP in upload directories, proxy "
                    "requests to a C2 server, or redirect users to phishing "
                    "pages. Certain directives are conclusively malicious."
                ),
                category=CATEGORY_C,
                subcategory=".htaccess",
                filesystem_artifacts=[
                    ".htaccess with php_value auto_prepend_file",
                    ".htaccess with php_value auto_append_file",
                    ".htaccess with AddHandler/SetHandler enabling PHP execution",
                    ".htaccess with ProxyPass to external host",
                    "edocs/.htaccess missing 'php_flag engine off'",
                ],
                detection_patterns=[
                    "content_regex: php_value\\s+auto_(prepend|append)_file",
                    "content_regex: (Add|Set)Handler\\s+.*php",
                    "content_regex: ProxyPass\\s+",
                    "content_regex: RewriteRule\\s+.*https?://",
                    "negative_check: edocs/.htaccess MUST contain php_flag engine off",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="content_check + negative_check",
                redacts_coverage="covered",
                related_iocs=["IOC-CFG-003"],
            )
        )

        self._register(
            AttackVector(
                id="AV-C-003",
                name=".user.ini persistence",
                description=(
                    "PHP's per-directory .user.ini is processed automatically. "
                    "REDCap ships NO .user.ini files, so any instance is "
                    "anomalous. Common abuse: auto_prepend_file to a webshell, "
                    "or disabling open_basedir restrictions."
                ),
                category=CATEGORY_C,
                subcategory=".user.ini",
                filesystem_artifacts=[
                    "**/.user.ini (REDCap ships none)",
                    ".user.ini containing auto_prepend_file",
                    ".user.ini containing auto_append_file",
                    ".user.ini containing allow_url_include",
                ],
                detection_patterns=[
                    "file_exists: any .user.ini in REDCap directories",
                    "content_regex: auto_prepend_file\\s*=",
                    "content_regex: auto_append_file\\s*=",
                    "content_regex: allow_url_include\\s*=\\s*1",
                    "content_regex: open_basedir\\s*=",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="file_exists + content_check",
                redacts_coverage="covered",
                related_iocs=["IOC-CFG-002"],
            )
        )

        self._register(
            AttackVector(
                id="AV-C-004",
                name="redcap_config table abuse (indirect)",
                description=(
                    "REDCap stores runtime settings in the redcap_config MySQL "
                    "table. An attacker with DB access can modify hook paths, "
                    "enable insecure features, or change file-storage settings. "
                    "Indirect filesystem evidence includes unexpected hook paths "
                    "or newly created files referenced only from the database."
                ),
                category=CATEGORY_C,
                subcategory="Config table",
                filesystem_artifacts=[
                    "PHP files at unusual paths referenced by config table entries",
                    "hook_functions.php path change — new file at non-default location",
                ],
                detection_patterns=[
                    "path_anomaly: hook file located outside expected directory",
                    "orphan_file: PHP file with no referencing require/include in codebase",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="path_analysis + orphan_detection",
                redacts_coverage="partial",
                related_iocs=["IOC-CFG-001"],
                out_of_scope_note=(
                    "Confirming config-table manipulation requires MySQL access; "
                    "filesystem analysis can only detect indirect artifacts."
                ),
            )
        )

    # ================================================================
    # D — SUPPLY_CHAIN
    # ================================================================

    def _build_category_d(self) -> None:
        self._register(
            AttackVector(
                id="AV-D-001",
                name="Composer autoload poisoning",
                description=(
                    "vendor/autoload.php is required on every request. Injecting "
                    "code here or modifying the Composer-generated classmap "
                    "gives persistent invisible execution with full application "
                    "context."
                ),
                category=CATEGORY_D,
                subcategory="Composer",
                filesystem_artifacts=[
                    "vendor/autoload.php with manual modifications",
                    "vendor/composer/autoload_classmap.php pointing to non-vendor paths",
                    "vendor/composer/autoload_files.php with injected entries",
                ],
                detection_patterns=[
                    "hash_compare: vendor/autoload.php vs composer-generated hash",
                    "content_regex: manual additions not matching Composer boilerplate",
                    "path_check: autoload_classmap referencing paths outside vendor/",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="hash_compare + content_check",
                redacts_coverage="covered",
                related_iocs=["IOC-SC-001"],
            )
        )

        self._register(
            AttackVector(
                id="AV-D-002",
                name="Typosquatted External Module",
                description=(
                    "A malicious External Module with a name similar to a "
                    "legitimate one (e.g. 'redcap_autosave' vs 'redcap-autosave') "
                    "installed in modules/. Contains backdoor code masked by "
                    "legitimate-looking functionality."
                ),
                category=CATEGORY_D,
                subcategory="External Module squatting",
                filesystem_artifacts=[
                    "modules/ directory entries with names similar to known EMs",
                    "modules/*/config.json with suspicious cron or hook definitions",
                    "modules/*/classes/*.php containing obfuscated code",
                ],
                detection_patterns=[
                    "name_similarity: Levenshtein distance to official EM names",
                    "content_regex: eval|base64_decode|gzinflate in module PHP files",
                    "entropy_check: high entropy strings in PHP source",
                    "manifest_check: module not listed in official REDCap EM directory",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="name_analysis + content_check",
                redacts_coverage="partial",
                related_iocs=["IOC-SC-002"],
                out_of_scope_note="Official EM directory cross-check requires network access.",
            )
        )

        self._register(
            AttackVector(
                id="AV-D-003",
                name="EM framework tampering",
                description=(
                    "ExternalModules/classes/ contains the framework that loads "
                    "every External Module. Modifying AbstractExternalModule.php "
                    "or Framework.php gives execution in the context of every EM "
                    "hook and cron invocation."
                ),
                category=CATEGORY_D,
                subcategory="EM framework",
                filesystem_artifacts=[
                    "ExternalModules/classes/AbstractExternalModule.php with hash mismatch",
                    "ExternalModules/classes/Framework.php with hash mismatch",
                    "ExternalModules/classes/*.php with injected eval/require",
                ],
                detection_patterns=[
                    "hash_compare: ExternalModules/classes/* vs distribution hashes",
                    "content_regex: eval\\(|base64_decode\\( in framework files",
                    "timestamp_anomaly: framework file mtime newer than deploy date",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="hash_compare",
                redacts_coverage="covered",
                related_iocs=["IOC-SC-002"],
            )
        )

    # ================================================================
    # E — SERVER_CONFIG
    # ================================================================

    def _build_category_e(self) -> None:
        self._register(
            AttackVector(
                id="AV-E-001",
                name="Nginx config modification",
                description=(
                    "Modification of Nginx site configuration to add locations "
                    "that proxy to a C2, enable PHP execution in upload paths, "
                    "or redirect specific URLs to attacker-controlled servers."
                ),
                category=CATEGORY_E,
                subcategory="Nginx",
                filesystem_artifacts=[
                    "/etc/nginx/sites-enabled/* with unexpected location blocks",
                    "/etc/nginx/conf.d/*.conf with proxy_pass to external hosts",
                    "nginx.conf include directives pointing to webroot files",
                ],
                detection_patterns=[
                    "content_regex: proxy_pass\\s+https?://(?!127\\.0\\.0\\.1|localhost)",
                    "content_regex: fastcgi_pass.*edocs|temp|uploads",
                    "content_regex: location\\s+~\\s+\\.php\\$.*edocs",
                    "timestamp_check: config mtime vs deployment baseline",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="content_check + timestamp_check",
                redacts_coverage="none",
                related_iocs=[],
                out_of_scope_note="Server configs may be outside the REDCap webroot snapshot.",
            )
        )

        self._register(
            AttackVector(
                id="AV-E-002",
                name="Apache config modification",
                description=(
                    "Tampering with Apache VirtualHost or directory configuration "
                    "to enable PHP in upload directories, set up reverse proxies, "
                    "or weaken access controls for specific paths."
                ),
                category=CATEGORY_E,
                subcategory="Apache",
                filesystem_artifacts=[
                    "/etc/apache2/sites-enabled/* with unexpected <Directory> blocks",
                    "/etc/httpd/conf.d/*.conf with ProxyPass directives",
                    "Apache config enabling PHP in edocs/ or temp/ directories",
                ],
                detection_patterns=[
                    "content_regex: ProxyPass\\s+/.*\\s+https?://",
                    "content_regex: <Directory.*edocs.*>.*php_admin_flag\\s+engine\\s+on",
                    "content_regex: SetHandler.*php.*edocs|temp|uploads",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="content_check",
                redacts_coverage="none",
                related_iocs=[],
                out_of_scope_note="Apache configs may be outside the REDCap webroot snapshot.",
            )
        )

        self._register(
            AttackVector(
                id="AV-E-003",
                name="TLS certificate manipulation",
                description=(
                    "Replacement or addition of TLS certificates/private keys "
                    "in the webroot or server config directory, enabling "
                    "man-in-the-middle attacks or indicating credential theft."
                ),
                category=CATEGORY_E,
                subcategory="TLS",
                filesystem_artifacts=[
                    "**/*.pem in webroot",
                    "**/*.key in webroot",
                    "**/*.crt in webroot",
                    "**/*.p12 in webroot",
                    "**/*.pfx in webroot",
                ],
                detection_patterns=[
                    "extension_check: .pem/.key/.crt/.p12/.pfx in web-accessible paths",
                    "content_regex: -----BEGIN (RSA )?PRIVATE KEY----- in webroot files",
                    "file_location: certificate files under document root",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="file_exists + extension_check",
                redacts_coverage="covered",
                related_iocs=["IOC-FP-004"],
            )
        )

    # ================================================================
    # F — PHP_RUNTIME
    # ================================================================

    def _build_category_f(self) -> None:
        self._register(
            AttackVector(
                id="AV-F-001",
                name="auto_prepend_file via .user.ini",
                description=(
                    "A .user.ini with auto_prepend_file causes PHP to execute "
                    "the specified file before every script in that directory "
                    "tree. Combined with a webshell, this provides invisible "
                    "persistent access."
                ),
                category=CATEGORY_F,
                subcategory="auto_prepend",
                filesystem_artifacts=[
                    ".user.ini with auto_prepend_file directive",
                    "the target file referenced by auto_prepend_file",
                ],
                detection_patterns=[
                    "file_exists: .user.ini in any directory",
                    "content_regex: auto_prepend_file\\s*=\\s*(.+)",
                    "follow_reference: verify the prepended file exists and inspect it",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="file_exists + content_check + reference_follow",
                redacts_coverage="covered",
                related_iocs=["IOC-CFG-002"],
            )
        )

        self._register(
            AttackVector(
                id="AV-F-002",
                name="PHP stream wrapper hijacking",
                description=(
                    "Registration of custom PHP stream wrappers via "
                    "stream_wrapper_register() in included files. Allows "
                    "interception of file operations, data exfiltration on "
                    "fopen/file_get_contents calls, or code injection via "
                    "include('wrapper://payload')."
                ),
                category=CATEGORY_F,
                subcategory="Stream wrapper",
                filesystem_artifacts=[
                    "*.php files containing stream_wrapper_register calls",
                    "*.php files containing stream_wrapper_unregister",
                    "*.php files defining classes with stream_open/stream_read methods",
                ],
                detection_patterns=[
                    "content_regex: stream_wrapper_register\\s*\\(",
                    "content_regex: stream_wrapper_unregister\\s*\\(",
                    "content_regex: function\\s+stream_open\\s*\\(",
                    "content_regex: class\\s+\\w+.*stream_open",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="content_check",
                redacts_coverage="partial",
                related_iocs=[],
                out_of_scope_note="Runtime wrapper registration requires PHP process inspection.",
            )
        )

        self._register(
            AttackVector(
                id="AV-F-003",
                name="OPcache poisoning",
                description=(
                    "PHP OPcache stores precompiled bytecode on disk. An "
                    "attacker who can write to the OPcache directory can replace "
                    "cached bytecode for legitimate files, achieving persistent "
                    "code execution that survives file-level integrity checks on "
                    "the original .php source."
                ),
                category=CATEGORY_F,
                subcategory="OPcache",
                filesystem_artifacts=[
                    "OPcache file_cache directory with unexpected .php.bin files",
                    "/tmp/opcache/* or configured file_cache path",
                    ".php.bin files with mtime newer than corresponding .php source",
                ],
                detection_patterns=[
                    "file_exists: .php.bin files in OPcache directory",
                    "timestamp_compare: .bin mtime vs .php source mtime",
                    "hash_compare: opcache system_id mismatch with current PHP config",
                ],
                conclusiveness="suspicious",
                severity="CRITICAL",
                detection_method="file_exists + timestamp_compare",
                redacts_coverage="none",
                related_iocs=[],
                out_of_scope_note="OPcache directory may be outside the webroot snapshot.",
            )
        )

        self._register(
            AttackVector(
                id="AV-F-004",
                name="PHP extension injection (.so/.dll)",
                description=(
                    "Loading a malicious PHP extension provides root-level code "
                    "execution within the PHP process. Evidence includes "
                    "unexpected .so/.dll files and extension= directives in "
                    "php.ini or conf.d/ drop-in files."
                ),
                category=CATEGORY_F,
                subcategory="PHP extension",
                filesystem_artifacts=[
                    "*.so or *.dll in PHP extension_dir with unknown hashes",
                    "/etc/php/*/conf.d/*.ini with extension= for unknown module",
                    "php.ini with extension= or zend_extension= for non-standard path",
                ],
                detection_patterns=[
                    "content_regex: ^extension\\s*=.*\\.so in conf.d/ INI files",
                    "content_regex: ^zend_extension\\s*=",
                    "file_hash: .so/.dll files not matching known PHP extension hashes",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="file_exists + hash_compare",
                redacts_coverage="none",
                related_iocs=[],
                out_of_scope_note="PHP extension directory is outside the webroot.",
            )
        )

        self._register(
            AttackVector(
                id="AV-F-005",
                name="include_path manipulation",
                description=(
                    "Modifying PHP's include_path via .user.ini, .htaccess, or "
                    "php.ini causes include/require to resolve from attacker-"
                    "controlled directories first, enabling class/function "
                    "hijacking without modifying the original source."
                ),
                category=CATEGORY_F,
                subcategory="include_path",
                filesystem_artifacts=[
                    ".user.ini with include_path directive",
                    ".htaccess with php_value include_path",
                    "php.ini or conf.d/ INI with modified include_path",
                    "files in the injected include_path shadowing REDCap classes",
                ],
                detection_patterns=[
                    "content_regex: include_path\\s*= in .user.ini",
                    "content_regex: php_value\\s+include_path in .htaccess",
                    "shadow_check: files in injected path matching names of REDCap classes",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="content_check + shadow_detection",
                redacts_coverage="partial",
                related_iocs=["IOC-CFG-002"],
            )
        )

    # ================================================================
    # G — ADDITIONAL
    # ================================================================

    def _build_category_g(self) -> None:
        self._register(
            AttackVector(
                id="AV-G-001",
                name="Temp file persistence",
                description=(
                    "PHP files planted in the REDCap temp/ directory. This "
                    "directory is intended for transient data only. PHP files "
                    "here indicate webshell drop or staging area for exfiltrated "
                    "data."
                ),
                category=CATEGORY_G,
                subcategory="Temp files",
                filesystem_artifacts=[
                    "temp/**/*.php",
                    "temp/**/*.phtml",
                    "temp/**/*.phar",
                    "temp/**/*.inc",
                ],
                detection_patterns=[
                    "extension_check: .php/.phtml/.phar in temp/",
                    "content_regex: <\\?php in temp/ files",
                    "age_check: temp files older than expected retention period",
                ],
                conclusiveness="conclusive",
                severity="HIGH",
                detection_method="file_location + extension_check",
                redacts_coverage="covered",
                related_iocs=["IOC-FP-001"],
            )
        )

        self._register(
            AttackVector(
                id="AV-G-002",
                name=".git directory exposure",
                description=(
                    "A .git/ directory in the webroot exposes the full source "
                    "code, commit history, configuration, and potentially "
                    "credentials committed in earlier revisions."
                ),
                category=CATEGORY_G,
                subcategory="Git exposure",
                filesystem_artifacts=[
                    ".git/config",
                    ".git/HEAD",
                    ".git/objects/",
                    ".git/refs/",
                ],
                detection_patterns=[
                    "directory_exists: .git/ in webroot",
                    "file_exists: .git/config",
                    'content_regex: \\[remote\\s+"origin"\\] in .git/config',
                ],
                conclusiveness="conclusive",
                severity="HIGH",
                detection_method="directory_exists",
                redacts_coverage="covered",
                related_iocs=["IOC-FP-003"],
            )
        )

        self._register(
            AttackVector(
                id="AV-G-003",
                name="Symlink attack",
                description=(
                    "Symbolic links in the webroot pointing to sensitive files "
                    "outside the document root (/etc/passwd, /etc/shadow, "
                    "database.php, private keys). Allows read access via the "
                    "web server."
                ),
                category=CATEGORY_G,
                subcategory="Symlink",
                filesystem_artifacts=[
                    "symlinks in webroot pointing outside document root",
                    "symlinks targeting /etc/passwd, /etc/shadow, /proc/",
                    "symlinks targeting database.php from web-accessible paths",
                ],
                detection_patterns=[
                    "symlink_check: os.path.islink() on all files",
                    "target_check: symlink target resolves outside webroot",
                    "target_sensitivity: target is /etc/passwd, /etc/shadow, *.key, database.php",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="symlink_detection + target_analysis",
                redacts_coverage="partial",
                related_iocs=[],
                out_of_scope_note="Some snapshot methods do not preserve symlink targets.",
            )
        )

        self._register(
            AttackVector(
                id="AV-G-004",
                name="Polyglot file (image + PHP)",
                description=(
                    "A file with a valid image header (JPEG, PNG, GIF) that "
                    "also contains embedded <?php code. Bypasses extension-based "
                    "upload filters and executes if the server processes the "
                    "file as PHP."
                ),
                category=CATEGORY_G,
                subcategory="Polyglot",
                filesystem_artifacts=[
                    "*.jpg/*.png/*.gif files containing <?php",
                    "image files with PHP short tags <? or <?=",
                    "edocs/ or temp/ images with embedded PHP",
                ],
                detection_patterns=[
                    "magic_bytes: valid image header (JFIF/PNG/GIF89a)",
                    "content_regex: <\\?(php|=) in binary image file",
                    "dual_extension: files like image.php.jpg or image.jpg.php",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="magic_bytes + content_check",
                redacts_coverage="covered",
                related_iocs=["IOC-FP-002"],
            )
        )

        self._register(
            AttackVector(
                id="AV-G-005",
                name="Log file poisoning",
                description=(
                    "Injection of PHP code into web-server access/error logs "
                    "or REDCap application logs, which is then executed by "
                    "including the log file via LFI or auto_prepend_file."
                ),
                category=CATEGORY_G,
                subcategory="Log poisoning",
                filesystem_artifacts=[
                    "*.log files containing <?php tags",
                    "access.log or error.log with PHP code in User-Agent or Referer",
                    "REDCap log files (temp/logs/) with embedded PHP",
                ],
                detection_patterns=[
                    "content_regex: <\\?php in *.log files",
                    "content_regex: <\\?php in User-Agent or Referer log fields",
                    "file_inclusion: log file path referenced in auto_prepend_file or include()",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="content_check",
                redacts_coverage="partial",
                related_iocs=[],
                out_of_scope_note="Log files may be outside the webroot or rotated away.",
            )
        )

        self._register(
            AttackVector(
                id="AV-G-006",
                name="Webshell in Classes/ directory",
                description=(
                    "REDCap's Classes/ directory contains core PHP classes loaded "
                    "via autoload. A webshell placed here benefits from the "
                    "autoloader and inherits REDCap's database connection context."
                ),
                category=CATEGORY_G,
                subcategory="Core directory webshell",
                filesystem_artifacts=[
                    "Classes/*.php not present in distribution manifest",
                    "Classes/*.php containing eval/system/passthru/shell_exec",
                    "Classes/*.php with recent mtime and high entropy",
                ],
                detection_patterns=[
                    "manifest_diff: file not in distribution file list",
                    "content_regex: (eval|system|passthru|shell_exec|popen)\\s*\\(",
                    "entropy_check: Shannon entropy > 5.5 indicating obfuscation",
                    "timestamp_anomaly: mtime significantly newer than deployment",
                ],
                conclusiveness="conclusive",
                severity="CRITICAL",
                detection_method="manifest_diff + content_check",
                redacts_coverage="covered",
                related_iocs=["IOC-FP-001"],
            )
        )

        self._register(
            AttackVector(
                id="AV-G-007",
                name="Unexpected cron job scripts",
                description=(
                    "Standalone PHP or shell scripts created in the webroot "
                    "designed to be invoked by system cron (crontab) or "
                    "systemd timers, providing persistent periodic execution "
                    "outside REDCap's built-in cron mechanism."
                ),
                category=CATEGORY_G,
                subcategory="Cron scripts",
                filesystem_artifacts=[
                    "*.sh files in webroot with execution permissions",
                    "*.php files in webroot referenced in /etc/cron.d/ or crontab",
                    "shell scripts calling curl/wget to external URLs",
                ],
                detection_patterns=[
                    "extension_check: .sh files in webroot",
                    "content_regex: #!/bin/(ba)?sh in webroot files",
                    "content_regex: curl|wget.*https?:// in shell scripts",
                    "permission_check: executable bit set on unexpected files",
                ],
                conclusiveness="suspicious",
                severity="HIGH",
                detection_method="file_exists + permission_check + content_check",
                redacts_coverage="partial",
                related_iocs=[],
                out_of_scope_note="System crontab is outside the REDCap webroot snapshot.",
            )
        )

        self._register(
            AttackVector(
                id="AV-G-008",
                name="PHP info / debug endpoint",
                description=(
                    "phpinfo() pages or debug endpoints dropped in the webroot. "
                    "Exposes full server configuration, environment variables, "
                    "database credentials in environment, and PHP module details."
                ),
                category=CATEGORY_G,
                subcategory="Info disclosure",
                filesystem_artifacts=[
                    "info.php or phpinfo.php in webroot",
                    "*.php files containing only phpinfo() call",
                    "debug.php / test.php / i.php with phpinfo()",
                ],
                detection_patterns=[
                    "filename_match: phpinfo.php, info.php, pi.php, test.php",
                    "content_regex: phpinfo\\s*\\(\\s*\\)",
                    "size_check: very small PHP file (~30-100 bytes) in webroot",
                ],
                conclusiveness="suspicious",
                severity="MEDIUM",
                detection_method="file_exists + content_check",
                redacts_coverage="covered",
                related_iocs=[],
            )
        )
