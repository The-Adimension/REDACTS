<?php
// REDACTS DAST DB connectivity smoke test.
// Credentials are read from REDCAP_DB_* variables injected by the
// orchestrator into the container's environment; nothing is hardcoded.
$host = getenv('REDCAP_DB_HOST') ?: 'redcap-dast-db';
$port = getenv('REDCAP_DB_PORT') ?: '3306';
$user = getenv('REDCAP_DB_USER');
$pass = getenv('REDCAP_DB_PASS') ?: getenv('REDCAP_DB_PASSWORD');
$db   = getenv('REDCAP_DB_NAME') ?: 'redcap';
if (!$user || !$pass) {
    echo "ERROR: REDCAP_DB_USER / REDCAP_DB_PASS must be set";
    exit(2);
}
$m = new mysqli("$host:$port", $user, $pass, $db);
echo $m->connect_error ?: 'OK';
?>
