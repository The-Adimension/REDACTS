<?php
// Positive: deprecated mysql_* API. Any use in a 2024+ REDCap tree is
// either (a) a back-port from a historical fork, or (b) attacker-injected
// code reaching for the lowest-friction DB API still installed on PHP 7
// hosts. Either way it is worth a finding.
$conn = mysql_connect('localhost', 'root', 'root');
$result = mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);
