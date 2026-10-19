<?php
declare(strict_types=1);

require __DIR__ . '/McpServerTest.php';
require dirname(__DIR__) . '/src/Admin/ActivityLogPage.php';

const DAY_IN_SECONDS = 86400;
function esc_html($value): string { return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8'); }
function esc_attr($value): string { return esc_html($value); }
function esc_url($value): string { return esc_html($value); }
function esc_html__($value, $domain): string { return esc_html($value); }
function esc_html_e($value, $domain): void { echo esc_html($value); }
function _n($single, $plural, $n, $domain): string { return $n === 1 ? $single : $plural; }
function admin_url($path): string { return 'https://staging.example.test/wp-admin/' . $path; }
function wp_die($message): void { throw new RuntimeException($message); }

use Afara\Admin\ActivityLogPage;
use Afara\Audit\ActivityLog;

$page = new ActivityLogPage();
$render = static function () use ($page): string {
    ob_start();
    try { $page->render(); return (string) ob_get_contents(); }
    finally { ob_end_clean(); }
};

$admin = true;
$options = [];
$_GET = [];
$html = $render();
check(str_contains($html, 'No refused requests in the last 24 hours') && str_contains($html, 'afara-status--on'), 'calm summary when nothing refused');
check(str_contains($html, 'Nothing recorded yet.'), 'empty state');

$userId = 0;
for ($i = 0; $i < 3; $i++) { ActivityLog::refused('incorrect_password'); }
$userId = 1;
ActivityLog::useConnection('<script>alert(1)</script>', 'not-a-uuid');
ActivityLog::record('afara/read-file', false, 'afara_path_denied');
ActivityLog::record('afara/site-context', true);
$html = $render();
check(str_contains($html, '3 refused requests in the last 24 hours') && str_contains($html, 'afara-status--action-needed'), 'summary counts collapsed refusals');
check(str_contains($html, 'Wrong or revoked Application Password'), 'refusal reason in plain words');
check(str_contains($html, 'Path not allowed'), 'error reason in plain words');
check(str_contains($html, '× 3') && str_contains($html, 'times, latest shown'), 'repeat count shown with screen-reader text');
check(str_contains($html, 'Not signed in') && str_contains($html, '>admin<'), 'who column');
check(!str_contains($html, '<script>alert') && str_contains($html, '&lt;script&gt;'), 'connection label escaped');
check(substr_count($html, 'aria-hidden="true"') >= 4 && str_contains($html, '>Refused<') && str_contains($html, '>Allowed<'), 'result uses icon plus words');
check(str_contains($html, 'Refused <span class="count">(1)</span>') && str_contains($html, 'Errors <span class="count">(1)</span>'), 'filter counts');

$_GET = ['view' => 'refused'];
$html = $render();
check(str_contains($html, 'aria-current="page"') && !str_contains($html, 'afara/site-context</code>'), 'refused view filters rows');
$_GET = ['view' => '"><script>'];
$html = $render();
check(!str_contains($html, '"><script>'), 'unknown view ignored');

$admin = false;
try { $render(); check(false, 'non-admin blocked'); } catch (RuntimeException $e) { check($e->getMessage() === 'Not permitted.', 'non-admin blocked'); }
echo "Activity log page tests passed\n";
