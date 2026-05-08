<?php
// Negative: parameterised mysqli prepared statement. The "SELECT *
// FROM" string is a literal, not interpolated user input. Dangerous-
// function detector should not trip here.
$stmt = $mysqli->prepare("SELECT id, label FROM redcap_projects WHERE id = ?");
$stmt->bind_param('i', $project_id);
$stmt->execute();
