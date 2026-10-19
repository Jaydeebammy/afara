<?php
declare(strict_types=1);

require __DIR__ . '/McpServerTest.php';
require dirname(__DIR__) . '/src/Admin/ConnectPage.php';

function esc_html($value): string { return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8'); }
function esc_url($value): string { return esc_html($value); }
function esc_html__($value, $domain): string { return esc_html($value); }
function esc_html_e($value, $domain): void { echo esc_html($value); }
function admin_url($path): string { return 'https://staging.example.test/wp-admin/' . $path; }
function wp_die($message): void { throw new RuntimeException($message); }
function wp_get_current_user(): object { return (object) ['ID' => 1]; }
function wp_is_application_passwords_available_for_user($user): bool { global $passwords; return $passwords; }

$admin = true;
$ssl = true;
$passwords = true;
$page = new \Afara\Admin\ConnectPage();
$render = static function () use ($page): string {
    ob_start();
    try { $page->render(); return (string) ob_get_contents(); }
    finally { ob_end_clean(); }
};
$options = [];
check(str_contains($render(), 'Disabled — enable Afara'), 'Connect off-by-default status');
$options = ['afara_enabled' => '1', 'afara_domain_lock' => 'wrong.test'];
check(str_contains($render(), 'Blocked — domain lock'), 'Connect domain status');
$options['afara_domain_lock'] = 'staging.example.test';
$ssl = false;
check(str_contains($render(), 'Blocked — HTTPS'), 'Connect plaintext status');
$ssl = true;
$passwords = false;
check(str_contains($render(), 'Application Passwords unavailable'), 'Connect password availability status');
$passwords = true;
$html = $render();
check(str_contains($html, 'Configured locally — remote connection not verified'), 'does not claim remote connectivity');
check(str_contains($html, '?rest_route=/afara/v1/mcp'), 'actual endpoint from rest_url');
check(str_contains($html, 'WP_API_PASSWORD=&lt;application-password&gt;'), 'only escaped credential placeholder');
check(str_contains($html, 'afara-site-context') && str_contains($html, 'afara-read-file') && str_contains($html, 'afara-list-directory'), 'MCP tool names');
unset($abilities['afara/read-file']);
check(str_contains($render(), 'Required WordPress abilities unavailable'), 'missing ability status');
$admin = false;
try { $render(); throw new LogicException('non-admin rendered Connect'); }
catch (RuntimeException $e) { check($e->getMessage() === 'Not permitted.', 'Connect requires administrator'); }
echo "Connect page tests passed\n";
