<?php
declare(strict_types=1);

// Minimal isolated gate tests; real WordPress integration tests remain TODO.
$GLOBALS['afara_test_options'] = [];
$GLOBALS['afara_test_capability'] = false;
function get_option(string $key, $default = false) { return $GLOBALS['afara_test_options'][$key] ?? $default; }
function home_url(): string { return 'https://staging.example.test'; }
function wp_parse_url(string $url, int $component) { return parse_url($url, $component); }
function current_user_can(string $capability): bool { return $capability === 'manage_options' && $GLOBALS['afara_test_capability']; }

require dirname(__DIR__) . '/src/Security/PermissionGate.php';

use Afara\Security\PermissionGate;
$gate = new PermissionGate();
$assert = static function (bool $condition, string $label): void {
    if (!$condition) { fwrite(STDERR, "FAIL: {$label}\n"); exit(1); }
};
$assert(!$gate->canRead(), 'off by default');
$GLOBALS['afara_test_options'] = ['afara_enabled' => '1', 'afara_domain_lock' => 'other.test'];
$GLOBALS['afara_test_capability'] = true;
$assert(!$gate->canRead(), 'domain mismatch');
$GLOBALS['afara_test_options']['afara_domain_lock'] = 'staging.example.test';
$assert($gate->canRead(), 'matching domain and admin');
$assert(!$gate->canWrite(), 'read-only default');
$GLOBALS['afara_test_options']['afara_read_only'] = '0';
$assert($gate->canWrite(), 'explicit write mode');
$GLOBALS['afara_test_capability'] = false;
$assert(!$gate->canRead(), 'non-admin denied');
echo "PermissionGate tests passed\n";
