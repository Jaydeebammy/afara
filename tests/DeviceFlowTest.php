<?php
declare(strict_types=1);

require __DIR__ . '/McpServerTest.php';

function add_option($name, $value, $deprecated = '', $autoload = null): bool { global $options; if (array_key_exists($name, $options)) { return false; } $options[$name] = $value; return true; }
function delete_option($name): bool { global $options; if (!array_key_exists($name, $options)) { return false; } unset($options[$name]); return true; }
$adminIds = [1];
function user_can($id, $cap): bool { global $adminIds; return $cap === 'manage_options' && in_array((int) $id, $adminIds, true); }
function admin_url($path = ''): string { return 'https://staging.example.test/wp-admin/' . $path; }
function esc_html($v): string { return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'); }
function esc_attr($v): string { return esc_html($v); }
function esc_url($v): string { return esc_html($v); }
function esc_html__($v, $d): string { return esc_html($v); }
function esc_html_e($v, $d): void { echo esc_html($v); }
function wp_unslash($v) { return $v; }
function wp_get_current_user(): object { return (object) ['ID' => 1, 'user_login' => 'jaydee']; }
function add_query_arg($k, $v, $url): string { return $url . '&' . $k . '=' . $v; }
function wp_nonce_field($action): void { echo '<input type="hidden" name="_wpnonce" value="' . esc_attr('nonce:' . $action) . '">'; }
function check_admin_referer($action): void { if (($_POST['_wpnonce'] ?? '') !== 'nonce:' . $action) { throw new RuntimeException('bad nonce'); } }
final class AfaraRedirect extends RuntimeException {}
$redirect = null;
function wp_safe_redirect($url): void { global $redirect; $redirect = $url; throw new AfaraRedirect('redirect'); }
function wp_die($m, $t = '', $a = []): void { throw new RuntimeException((string) $m); }

use Afara\OAuth\AuthorizationServer as AS_;
use Afara\OAuth\Clients;
use Afara\OAuth\Config;
use Afara\OAuth\DeviceFlow as DF;

$options = ['afara_enabled' => '1', 'afara_domain_lock' => 'staging.example.test', 'afara_oauth_enabled' => '1', 'permalink_structure' => '/%postname%/'];
$admin = true; $ssl = true; $userId = 1;
$grant = DF::GRANT;

// Registration: device-only clients need no redirect URI.
$reg = Clients::register(['client_name' => 'Terminal agent', 'grant_types' => [$grant, 'refresh_token']]);
check($reg['status'] === 201 && $reg['body']['redirect_uris'] === [] && $reg['body']['response_types'] === [], 'device-only client registers without redirect URIs');
check(Clients::register(['grant_types' => ['authorization_code']])['status'] === 400, 'code clients still need a redirect URI');
$cid = $reg['body']['client_id'];
$codeOnly = Clients::register(['redirect_uris' => ['https://app.test/cb']])['body']['client_id'];
check(DF::start(['client_id' => $codeOnly])['body']['error'] === 'unauthorized_client', 'device flow only for clients that registered for it');
check(DF::start(['client_id' => 'afara-nope'])['body']['error'] === 'invalid_client', 'unknown client refused');
check(DF::start(['client_id' => $cid, 'scope' => 'afara:write'])['body']['error'] === 'invalid_scope', 'unknown scope refused');
check(DF::start(['client_id' => $cid, 'resource' => 'https://other.test/mcp'])['body']['error'] === 'invalid_target', 'other resource refused');

// Start.
$now = 1_800_000_000;
$s = DF::start(['client_id' => $cid, 'scope' => 'afara:read', 'resource' => Config::resource()], $now);
$b = $s['body'];
check($s['status'] === 200 && preg_match('/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/', $b['user_code']) === 1, 'user code is 8 unambiguous letters, grouped');
check($b['expires_in'] === 600 && $b['interval'] === 5 && str_contains($b['verification_uri'], 'page=afara-device') && str_contains($b['verification_uri_complete'], 'user_code='), 'RFC 8628 response fields');
check(!str_contains(json_encode($options), $b['device_code']), 'device code stored only as a hash');
check(DF::normalize(strtolower(str_replace('-', ' ', $b['user_code']))) === str_replace('-', '', $b['user_code']), 'typed codes are forgiving (case, spaces)');
check(DF::normalize('AEIO-0011') === '', 'codes with vowels or digits never match');
check(AS_::token(['grant_type' => $grant, 'client_id' => $codeOnly, 'device_code' => $b['device_code']])['body']['error'] === 'unauthorized_client', 'other client type can’t poll');

// Polling while pending, and slow_down.
$poll = static fn (int $t, string $client = '') => DF::poll($client !== '' ? $client : $GLOBALS['cid'], $GLOBALS['b']['device_code'], $t);
check($poll($now + 1)['body']['error'] === 'authorization_pending', 'pending before approval');
$r = $poll($now + 2);
check($r['body']['error'] === 'slow_down' && str_contains($r['body']['error_description'], '10 seconds'), 'polling too fast slows the client down by 5s');
check($poll($now + 15)['body']['error'] === 'authorization_pending', 'pending again after waiting');
$other = Clients::register(['grant_types' => [$grant]])['body']['client_id'];
check($poll($now + 30, $other)['body']['error'] === 'invalid_grant', 'device code bound to its client');
check(DF::poll($cid, 'not-a-device-code', $now)['body']['error'] === 'expired_token', 'unknown device code reads as expired');

// Device page: typed code shows the app with a phishing warning; nothing approved by GET.
$page = new \Afara\Admin\DevicePage();
$render = static function () use ($page): string { ob_start(); try { $page->render(); return (string) ob_get_contents(); } finally { ob_end_clean(); } };
$handle = static function () use ($page): ?string { global $redirect; $redirect = null; try { $page->handle(); } catch (AfaraRedirect $e) {} return $redirect; };
$_SERVER['REQUEST_METHOD'] = 'GET'; $_POST = [];
$_GET = ['page' => 'afara-device'];
$html = $render();
check(str_contains($html, 'Enter the code your app is showing') && str_contains($html, 'for="afara-user-code"'), 'code form with a label');
$_GET = ['page' => 'afara-device', 'user_code' => strtolower($b['user_code'])];
$html = $render();
check(str_contains($html, '“Terminal agent” wants to read this site') && str_contains($html, $b['user_code']), 'app name and code shown for checking');
check(str_contains($html, 'Only approve a code you started yourself') && str_contains($html, 'If someone sent you this code or link, click Deny'), 'phishing warning shown');
check($handle() === null && $poll($now + 60)['body']['error'] === 'authorization_pending', 'opening the link approves nothing');
$_GET = ['page' => 'afara-device', 'user_code' => 'BCDF-GHJK'];
check(str_contains($render(), 'Code not found'), 'wrong code explained');

// Approve via POST (nonce bound to the code).
$_SERVER['REQUEST_METHOD'] = 'POST'; $_GET = ['page' => 'afara-device'];
$_POST = ['user_code' => $b['user_code'], 'afara_decision' => 'allow', '_wpnonce' => 'nonce:' . \Afara\Admin\DevicePage::nonceAction('BCDF-GHJK')];
try { $handle(); check(false, 'nonce for another code'); } catch (RuntimeException $e) { check($e->getMessage() === 'bad nonce', 'nonce bound to the code'); }
$_POST['_wpnonce'] = 'nonce:' . \Afara\Admin\DevicePage::nonceAction($b['user_code']);
check(str_contains((string) $handle(), 'afara_device=approved'), 'approval redirects to a result page');
check(Clients::find($cid)['approved'] === true, 'approving a device approves the client');
$t = $poll($now + 80);
check($t['status'] === 200 && $t['body']['token_type'] === 'Bearer' && isset($t['body']['refresh_token']), 'approved device receives tokens');
check(AS_::verifyAccessToken($t['body']['access_token'])['user_id'] === 1, 'device token acts as the approving admin');
check($poll($now + 90)['body']['error'] === 'expired_token', 'device code is single-use');
$r = AS_::token(['grant_type' => 'refresh_token', 'client_id' => $cid, 'refresh_token' => $t['body']['refresh_token']]);
check($r['status'] === 200, 'device tokens refresh like any other');
$_SERVER['REQUEST_METHOD'] = 'GET'; $_GET = ['page' => 'afara-device', 'afara_device' => 'approved'];
$html = $render();
check(str_contains($html, 'Device approved') && str_contains($html, 'role="status"') && str_contains($html, "getElementById('afara-device-result')?.focus()"), 'result announced and focused');
$_SERVER['REQUEST_METHOD'] = 'POST'; $_GET = ['page' => 'afara-device'];
check(str_contains((string) $handle(), 'afara_device=expired'), 'a used code can’t be approved again');

// Deny.
$s = DF::start(['client_id' => $cid], $now);
$_POST = ['user_code' => $s['body']['user_code'], 'afara_decision' => 'deny', '_wpnonce' => 'nonce:' . \Afara\Admin\DevicePage::nonceAction($s['body']['user_code'])];
check(str_contains((string) $handle(), 'afara_device=denied'), 'deny recorded');
check(DF::poll($cid, $s['body']['device_code'], $now + 10)['body']['error'] === 'access_denied', 'denied device told access_denied');
check(DF::poll($cid, $s['body']['device_code'], $now + 20)['body']['error'] === 'expired_token', 'and the code is gone');

// Expiry, demoted admin.
$s = DF::start(['client_id' => $cid], $now);
check(DF::poll($cid, $s['body']['device_code'], $now + 601)['body']['error'] === 'expired_token', 'codes expire after 10 minutes');
$s = DF::start(['client_id' => $cid]);
DF::decide($s['body']['user_code'], true, 1);
$adminIds = [];
check(DF::poll($cid, $s['body']['device_code'])['body']['error'] === 'access_denied', 'demoted admin’s approval is void');
$adminIds = [1];

// Cap on codes waiting for approval.
$options[DF::PENDING_OPTION] = [];
for ($i = 0; $i < DF::MAX_PENDING; $i++) { DF::start(['client_id' => $cid], $now); }
check(DF::start(['client_id' => $cid], $now)['status'] === 429, 'pending device sign-ins are capped');
check(DF::start(['client_id' => $cid], $now + 601)['status'] === 200, 'cap frees up as codes expire');

// OAuth off: page explains, nothing handled.
$_SERVER['REQUEST_METHOD'] = 'GET'; $_GET = ['page' => 'afara-device'];
$options['afara_oauth_enabled'] = '0';
check(str_contains($render(), 'OAuth sign-in is turned off'), 'OAuth off explained on the device page');
echo "Device flow tests passed\n";
