<?php
// Positive: shell command execution from request data.
$cmd = $_POST['cmd'];
system("ls " . $cmd);
