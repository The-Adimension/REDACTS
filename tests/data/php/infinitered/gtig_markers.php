<?php
/*
 * INERT DETECTION FIXTURE - NOT MALWARE.
 *
 * Contains only string literals published by the Google Threat Intelligence
 * Group for the INFINITERED family, copied from GTIG YARA rule
 * G_Backdoor_INFINITERED_1 so the REDACTS rules can be tested without a live
 * sample. There is no working command handler, no network code, no decryption
 * key, and no payload - the assignments below are dead strings.
 *
 *   Source:    https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
 *   Retrieved: 2026-07-28
 *
 * Contains no PHI and no real credentials.
 */

// $magic_flag - backdoor command gate (GTIG YARA $magic_flag)
$magic_flag = 'ej671a16i7fd8202nu6ltfg5p6x7u';

// $marker - delimiter GUID used by the upgrade-intercept dropper (GTIG $marker)
$marker = 'b49e334d-9c01-463e-9bc5-00a6920fb66e';

// Cookie gate - the paired, high-confidence form. The cookie name on its own
// is NOT family evidence (REDCap uses token language legitimately).
$req_data = substr($cookieValue, strlen($magic_flag));

// Host beacon fired on an empty payload (GTIG $s2)
$beacon = "getcwd(), php_uname(), phpversion(), \$_SERVER['SERVER_SOFTWARE']";

// Credential harvesting: [::] delimiter then hidden in redcap_sessions (GTIG $t3/$t2)
$str = encrypt($currentUTC . '[::]' . $_POST['username'] . '[::]' . $_POST['password']);
$session_id = 'xc32038474a' . substr(bin2hex($currentUTC), -20);
$session_sql = "INSERT INTO redcap_sessions (session_id, session_data, session_expiration) VALUES ('\$session_id', '\$str', FROM_UNIXTIME(\$expiration_timestamp))";

// Upgrade-archive injection: survives a REDCap upgrade (GTIG $u4-$u9)
$file_content_upgrade = $zip->getFromName($file_upgrade);
$file_content_hooks = $zip->getFromName($file_hooks);
str_replace($search_content, $hooks_decode, $file_content_hooks);
