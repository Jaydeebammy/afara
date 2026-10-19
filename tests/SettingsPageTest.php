<?php
declare(strict_types=1);

require __DIR__ . '/McpServerTest.php';
require dirname(__DIR__) . '/src/Admin/SettingsPage.php';

function esc_html($value): string { return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8'); }
function esc_attr($value): string { return esc_html($value); }
function esc_html__($value, $domain): string { return esc_html($value); }
function esc_html_e($value, $domain): void { echo esc_html($value); }
function wp_die($message): void { throw new RuntimeException($message); }
function settings_fields($group): void {}
function submit_button($label): void { echo '<button>' . esc_html($label) . '</button>'; }
function checked($a, $b): void { if ((string) $a === (string) $b) { echo 'checked="checked"'; } }

use Afara\Admin\SettingsPage;

$admin = true;
$page = new SettingsPage();
$render = static function () use ($page): string {
    ob_start();
    try { $page->render(); return (string) ob_get_contents(); }
    finally { ob_end_clean(); }
};

// Off by default: grey state, says what to do, pre-fills the lock.
$options = [];
$_GET = [];
$html = $render();
check(str_contains($html, 'afara-status--off') && str_contains($html, 'Off — no agent can connect'), 'off state rendered in words');
check(str_contains($html, 'dashicons-lock') && str_contains($html, 'aria-hidden="true"'), 'off state has a decorative icon');
check(str_contains($html, 'value="staging.example.test"') && str_contains($html, 'Pre-filled with this site'), 'empty domain lock is pre-filled and explained');
check(!str_contains($html, 'afara-save-notice'), 'no save notice before saving');

// Enabled with a wrong lock: action needed, names both hosts.
$options = ['afara_enabled' => '1', 'afara_domain_lock' => 'wrong.example.test'];
$status = SettingsPage::status(new \Afara\Security\PermissionGate(), 'staging.example.test');
check($status['state'] === SettingsPage::STATE_ACTION_NEEDED, 'mismatch is action needed');
check(str_contains($status['detail'], 'wrong.example.test') && str_contains($status['detail'], 'staging.example.test'), 'mismatch names both hosts');
$options['afara_domain_lock'] = '';
$status = SettingsPage::status(new \Afara\Security\PermissionGate(), 'staging.example.test');
check($status['state'] === SettingsPage::STATE_ACTION_NEEDED && str_contains($status['detail'], 'Enter this site'), 'empty lock asks for the address');

// Enabled and matched: on.
$options = ['afara_enabled' => '1', 'afara_domain_lock' => 'staging.example.test'];
$html = $render();
check(str_contains($html, 'afara-status--on') && str_contains($html, 'On — agents can connect'), 'on state rendered');
check(str_contains($html, 'value="staging.example.test"') && !str_contains($html, 'Pre-filled'), 'saved lock shown without pre-fill hint');

// After saving: a focused, state-specific notice and a one-off highlight.
$_GET = ['settings-updated' => 'true'];
$html = $render();
check(str_contains($html, 'id="afara-save-notice"') && str_contains($html, 'notice-success') && str_contains($html, 'role="status"'), 'success notice after save');
check(str_contains($html, 'Afara is on for administrators') && str_contains($html, 'tabindex="-1"'), 'save notice names the new state and can take focus');
check(str_contains($html, "getElementById('afara-save-notice')?.focus()"), 'save notice receives focus for screen readers');
check(str_contains($html, 'afara-status--changed'), 'status highlights once after save');
$options = ['afara_enabled' => '1', 'afara_domain_lock' => 'wrong.example.test'];
$html = $render();
check(str_contains($html, 'notice-error') && str_contains($html, 'role="alert"'), 'problem after save is an alert');
$options = [];
check(str_contains($render(), 'Settings saved. Afara is off.'), 'off after save is reported');

// Escaping and permissions.
$options = ['afara_enabled' => '1', 'afara_domain_lock' => '<b>x</b>'];
$_GET = [];
check(!str_contains($render(), '<b>x</b>'), 'domain lock is escaped');
$admin = false;
try { $render(); throw new LogicException('non-admin rendered settings'); }
catch (RuntimeException $e) { check($e->getMessage() === 'Not permitted.', 'settings require administrator'); }
echo "Settings page tests passed\n";
