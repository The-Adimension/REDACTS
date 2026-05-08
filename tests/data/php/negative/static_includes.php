<?php
// Negative: legitimate file include with a hardcoded relative path.
// No dynamic include, no user input, no eval.
require_once __DIR__ . '/../config/redcap_connect.php';
require_once __DIR__ . '/../classes/Project.php';
