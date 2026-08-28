<?php
// Negative: ordinary REDCap-style helper. No eval, no shell exec, no
// unserialize, no deprecated API. Must produce no security finding.
function format_subject_label(string $first, string $last): string
{
    return trim($last) . ', ' . trim($first);
}

echo format_subject_label('Ada', 'Lovelace');
