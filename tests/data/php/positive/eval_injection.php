<?php
// Positive: classic eval injection. tree-sitter must surface this.
$user = $_GET['x'];
eval($user);
