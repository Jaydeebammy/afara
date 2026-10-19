<?php
declare(strict_types=1);

require __DIR__ . '/McpServerTest.php';
require dirname(__DIR__) . '/src/Admin/Connections.php';
require dirname(__DIR__) . '/src/Admin/ConnectPage.php';

function esc_html($value): string { return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8'); }
function esc_url($value): string { return esc_html($value); }
function esc_attr($value): string { return esc_html($value); }
function esc_html__($value, $domain): string { return esc_html($value); }
function esc_html_e($value, $domain): void { echo esc_html($value); }
function admin_url($path): string { return 'https://staging.example.test/wp-admin/' . $path; }
final class AfaraTestExit extends RuntimeException {}
function wp_die($message, $title = '', $args = []): void { throw new RuntimeException((string) $message); }
function wp_get_current_user(): object { return (object) ['ID' => 1]; }
function wp_is_application_passwords_available_for_user($user): bool { return true; }
function add_query_arg($args, $value = null, $url = null): string {
    if (!is_array($args)) { $args = [$args => $value]; } else { $url = $value; }
    $parts = explode('#', (string) $url, 2);
    return $parts[0] . (str_contains($parts[0], '?') ? '&' : '?') . http_build_query($args) . (isset($parts[1]) ? '#' . $parts[1] : '');
}
function wp_nonce_field($action): void { echo '<input type="hidden" name="_wpnonce" value="' . esc_attr('nonce:' . $action) . '">'; }
function check_admin_referer($action): void { if (($_POST['_wpnonce'] ?? '') !== 'nonce:' . $action) { throw new RuntimeException('bad nonce'); } }
function wp_unslash($v) { return $v; }
function sanitize_text_field($v): string { return trim((string) $v); }
$redirect = null;
function wp_safe_redirect($url): void { global $redirect; $redirect = $url; throw new AfaraTestExit('redirect'); }
$wpUsers = [];
function get_users($args): array { global $wpUsers; check(($args['capability'] ?? '') === 'manage_options', 'only administrators are listed'); return $wpUsers; }
final class WP_Application_Passwords {
    public static array $store = [];
    public static array $deleted = [];
    public static function get_user_application_passwords($userId): array { return self::$store[$userId] ?? []; }
    public static function delete_application_password($userId, $uuid) {
        self::$deleted[] = [$userId, $uuid];
        self::$store[$userId] = array_values(array_filter(self::$store[$userId] ?? [], fn ($p) => $p['uuid'] !== $uuid));
        return true;
    }
}

use Afara\Admin\Connections;
use Afara\Audit\ActivityLog;

$mine = '11111111-1111-4111-8111-111111111111';
$theirs = '22222222-2222-4222-8222-222222222222';
$old = '33333333-3333-4333-8333-333333333333';
$wpUsers = [(object) ['ID' => 1, 'user_login' => 'jaydee'], (object) ['ID' => 5, 'user_login' => 'other-admin']];
WP_Application_Passwords::$store = [
    1 => [
        ['uuid' => $mine, 'name' => 'Claude Desktop', 'created' => 1760000000, 'last_used' => 1760500000, 'password' => '$P$hash-must-not-leak'],
        ['uuid' => $old, 'name' => '<b>Old laptop</b>', 'created' => 1750000000, 'last_used' => null, 'password' => '$P$hash-must-not-leak'],
    ],
    5 => [['uuid' => $theirs, 'name' => 'Antigravity', 'created' => 1760100000, 'last_used' => null, 'password' => '$P$hash-must-not-leak']],
];
$admin = true; $userId = 1; $editable = [1]; $options = []; $_GET = []; $_POST = [];

// Activity links to the exact connection.
ActivityLog::useConnection('Claude Desktop', $mine);
ActivityLog::record('afara/site-context', true);
ActivityLog::resetConnection();

$rows = Connections::all();
check(count($rows) === 3, 'lists every administrator Application Password');
check($rows[0]['uuid'] === $mine && $rows[0]['afara']['result'] === 'success', 'most recent Afara activity first, linked by ID');
check(!str_contains(json_encode($rows), 'hash-must-not-leak'), 'password hashes never leave Connections::all');
$byUuid = array_column($rows, null, 'uuid');
check($byUuid[$mine]['can_revoke'] && !$byUuid[$theirs]['can_revoke'], 'revoke only for accounts you can edit');

$page = new \Afara\Admin\ConnectPage();
$render = static function () use ($page): string {
    ob_start();
    try { $page->render(); return (string) ob_get_contents(); }
    finally { ob_end_clean(); }
};
$html = $render();
check(str_contains($html, 'id="afara-connections"') && str_contains($html, 'Claude Desktop') && str_contains($html, 'Antigravity'), 'connections table rendered');
check(str_contains($html, '&lt;b&gt;Old laptop&lt;/b&gt;') && !str_contains($html, '<b>Old laptop'), 'connection names escaped');
check(str_contains($html, '>You<') && str_contains($html, 'None recorded') && str_contains($html, 'Never'), 'you badge, empty activity and never-used states');
check(str_contains($html, 'Only that user can revoke'), 'no revoke button for accounts you can’t edit');
check(str_contains($html, 'revoke=' . $mine) && str_contains($html, '<span class="screen-reader-text"> Claude Desktop</span>'), 'revoke link names the connection for screen readers');
check(!str_contains($html, 'id="afara-revoke-confirm"') && !str_contains($html, 'hash-must-not-leak'), 'no confirmation before asked, no hashes');

// Step 1: confirmation panel (GET changes nothing).
$_GET = ['revoke' => $mine, 'revoke_user' => '1'];
$html = $render();
check(str_contains($html, 'id="afara-revoke-confirm"') && str_contains($html, 'Revoke “Claude Desktop” for jaydee?'), 'confirmation names connection and account');
check(str_contains($html, 'method="post"') && str_contains($html, 'nonce:' . Connections::nonceAction(1, $mine)), 'confirmation posts with a per-connection nonce');
check(str_contains($html, "getElementById('afara-revoke-confirm')?.focus()") && str_contains($html, '>Cancel<'), 'confirmation takes focus and can be cancelled');
check(WP_Application_Passwords::$deleted === [], 'viewing the confirmation deletes nothing');
$_GET = ['revoke' => $theirs, 'revoke_user' => '5'];
check(!str_contains($render(), 'id="afara-revoke-confirm"'), 'no confirmation for accounts you can’t edit');

// Step 2: the handler.
$handler = new Connections();
$post = static function (array $data, string $method = 'POST') use ($handler): string {
    global $redirect; $redirect = null;
    $_POST = $data; $_SERVER['REQUEST_METHOD'] = $method;
    try { $handler->handleRevoke(); } catch (AfaraTestExit $e) {}
    return (string) $redirect;
};
check(str_contains($post([], 'GET'), 'page=afara-connect') && WP_Application_Passwords::$deleted === [], 'GET never revokes');
try { $post(['user_id' => '1', 'uuid' => $mine, '_wpnonce' => 'forged']); check(false, 'forged nonce'); }
catch (RuntimeException $e) { check($e->getMessage() === 'bad nonce' && WP_Application_Passwords::$deleted === [], 'forged nonce rejected'); }
$url = $post(['user_id' => '5', 'uuid' => $theirs, '_wpnonce' => 'nonce:' . Connections::nonceAction(5, $theirs)]);
check(str_contains($url, 'afara_revoked=missing') && WP_Application_Passwords::$deleted === [], 'cannot revoke an account you can’t edit');
$url = $post(['user_id' => '1', 'uuid' => strtoupper($mine), '_wpnonce' => 'nonce:' . Connections::nonceAction(1, $mine)]);
check(str_contains($url, 'afara_revoked=ok') && WP_Application_Passwords::$deleted === [[1, $mine]], 'valid revoke deletes exactly that password');
$url = $post(['user_id' => '1', 'uuid' => $mine, '_wpnonce' => 'nonce:' . Connections::nonceAction(1, $mine)]);
check(str_contains($url, 'afara_revoked=missing') && count(WP_Application_Passwords::$deleted) === 1, 'second revoke is a no-op');
$admin = false;
try { $post(['user_id' => '1', 'uuid' => $old, '_wpnonce' => 'nonce:' . Connections::nonceAction(1, $old)]); check(false, 'non-admin'); }
catch (RuntimeException $e) { check($e->getMessage() === 'Not permitted.' && count(WP_Application_Passwords::$deleted) === 1, 'non-admin cannot revoke'); }
$admin = true;

// Result notice after redirect.
$_GET = ['afara_revoked' => 'ok'];
$html = $render();
check(str_contains($html, 'Connection revoked') && str_contains($html, 'role="status"') && str_contains($html, "getElementById('afara-connections-notice')?.focus()"), 'revoke result announced and focused');
check(!str_contains($html, 'Claude Desktop'), 'revoked connection gone from the list');
$_GET = ['afara_revoked' => '<script>'];
check(!str_contains($render(), 'afara-connections-notice'), 'unknown result ignored');

// OAuth apps are connections too, and revoke kills the grant.
$grant = \Afara\OAuth\Grants::create('afara-client', 'Claude (OAuth)', 1, 'afara:read', 'https://staging.example.test/?rest_route=/afara/v1/mcp');
$_GET = [];
$html = $render();
check(str_contains($html, 'Claude (OAuth)') && str_contains($html, 'OAuth app') && str_contains($html, 'Application Password'), 'OAuth grants listed with their type');
$_GET = ['revoke' => $grant, 'revoke_user' => '1'];
check(str_contains($render(), 'all its tokens stop working'), 'OAuth revoke confirmation explains sign-out');
$url = $post(['user_id' => '1', 'uuid' => $grant, '_wpnonce' => 'nonce:' . Connections::nonceAction(1, $grant)]);
check(str_contains($url, 'afara_revoked=ok') && \Afara\OAuth\Grants::find($grant) === null, 'revoking an OAuth app removes its grant');
check(count(WP_Application_Passwords::$deleted) === 1, 'OAuth revoke doesn’t touch Application Passwords');

// Empty state.
WP_Application_Passwords::$store = [];
$_GET = [];
check(str_contains($render(), 'No connections yet'), 'empty state links to profile');
echo "Connections tests passed\n";
