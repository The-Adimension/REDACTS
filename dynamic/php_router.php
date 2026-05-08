<?php

$webroot = getenv('REDACTS_REDCAP_WEBROOT') ?: '';
$version = getenv('REDACTS_REDCAP_VERSION') ?: '';

if ($webroot === '' || $version === '') {
    http_response_code(500);
    echo 'REDACTS PHP router is missing REDACTS_REDCAP_WEBROOT or REDACTS_REDCAP_VERSION.';
    return true;
}

$rootReal = realpath($webroot);
if ($rootReal === false) {
    http_response_code(500);
    echo 'REDACTS PHP router could not resolve the REDCap webroot.';
    return true;
}

$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if (!preg_match('#^/redcap(?:/|$)#', $uri)) {
    http_response_code(404);
    echo 'Not Found';
    return true;
}

$prefix = '#^/redcap(?:/redcap_v' . preg_quote($version, '#') . ')?/?#';
$relative = preg_replace($prefix, '', $uri);
$relative = ltrim((string) $relative, '/');

if ($relative === '') {
    $relative = 'index.php';
}

if ($relative === 'api' || str_starts_with($relative, 'api/')) {
    $suffix = substr($relative, 3);
    $relative = 'API' . $suffix;
    if ($relative === 'API' || $relative === 'API/') {
        $relative = 'API/index.php';
    }
}

$candidate = $rootReal . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
if (is_dir($candidate)) {
    $candidate = rtrim($candidate, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'index.php';
}

$target = realpath($candidate);
if ($target === false || !str_starts_with($target, $rootReal) || !is_file($target)) {
    http_response_code(404);
    echo 'Not Found';
    return true;
}

$scriptName = '/redcap/' . ltrim($relative, '/');
$_SERVER['DOCUMENT_ROOT'] = dirname($rootReal);
$_SERVER['SCRIPT_FILENAME'] = $target;
$_SERVER['SCRIPT_NAME'] = $scriptName;
$_SERVER['PHP_SELF'] = $scriptName;

$extension = strtolower(pathinfo($target, PATHINFO_EXTENSION));
if ($extension === 'php') {
    chdir(dirname($target));
    require $target;
    return true;
}

$mimeTypes = [
    'css' => 'text/css; charset=UTF-8',
    'gif' => 'image/gif',
    'html' => 'text/html; charset=UTF-8',
    'ico' => 'image/x-icon',
    'jpeg' => 'image/jpeg',
    'jpg' => 'image/jpeg',
    'js' => 'application/javascript; charset=UTF-8',
    'json' => 'application/json; charset=UTF-8',
    'png' => 'image/png',
    'svg' => 'image/svg+xml',
    'txt' => 'text/plain; charset=UTF-8',
    'woff' => 'font/woff',
    'woff2' => 'font/woff2',
    'xml' => 'application/xml; charset=UTF-8',
];

header('Content-Type: ' . ($mimeTypes[$extension] ?? 'application/octet-stream'));
header('Content-Length: ' . filesize($target));
readfile($target);
return true;
