<?php
// Positive: layered base64+gzinflate obfuscation, the staging pattern
// observed in the INFINITERED disclosure (May 2025).
$payload = base64_decode('H4sIAAAAAAAAA...');
eval(gzinflate($payload));
