<?php
declare(strict_types=1);

// Test-only loopback router simulates TLS termination. Never install in WordPress.
// It exercises WordPress Application Password authentication, not a TLS handshake.
if (PHP_SAPI !== 'cli-server' || !in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    exit;
}
$_SERVER['HTTPS'] = 'on';
require rtrim((string) getenv('AFARA_WP_PATH'), '/') . '/index.php';
