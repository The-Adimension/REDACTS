<?php
// Negative: configuration constants only. Sentinel that ensures we
// don't false-match the literal text "eval" inside an unrelated
// identifier or string.
define('REDCAP_EVALUATION_MODE', 'closed');
define('REDCAP_VERSION', '14.5.0');
