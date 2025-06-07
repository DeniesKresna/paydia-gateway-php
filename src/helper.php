<?php

$env_path = __DIR__ . '/.env';
if (!file_exists($env_path)) {
    die('Environment file not found at: ' . $env_path);
}

$env = parse_ini_file($env_path, false, INI_SCANNER_RAW);

define('DEBUG_MODE', isset($env['DEBUG_MODE']) && strtoupper($env['DEBUG_MODE']) === 'TRUE');

function debug_log($message, $context = null) {
    if (!DEBUG_MODE) {
        return; 
    }

    $logFile = '/tmp/debug.log';
    $timestamp = date('Y-m-d H:i:s');
    $output = "[$timestamp] $message";

    if (!is_null($context)) {
        if (is_array($context) || is_object($context)) {
            $output .= ' => ' . print_r($context, true);
        } else {
            $output .= ' => ' . $context;
        }
    }

    file_put_contents($logFile, $output . PHP_EOL, FILE_APPEND);
}