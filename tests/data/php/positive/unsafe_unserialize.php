<?php
// Positive: PHP-object-injection vector. Untrusted unserialize() is
// the canonical path to RCE in PHP applications (see CVE-2015-8562
// for the historical reference REDACTS cites).
$blob = $_COOKIE['session'];
$obj = unserialize($blob);
