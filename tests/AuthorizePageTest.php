<?php
declare(strict_types=1);

require __DIR__ . '/McpServerTest.php';

function add_option($name, $value, $deprecated = '', $autoload = null): bool { global $options; if (array_key_exists($name, $options)) { return false; } $options[$name] = $value; return true; }
function delete_option($name): bool { global $options; if (!array_key_exists($name, $options)) { return false; } unset($options[$name]); return true; }
function user_can($id, $cap): bool { return (int) $id === 1 && $cap === 'manage_options'; }
function admin_url($path = ''): string { return 'https://staging.example.test/wp-admin/' . $path; }
function esc_html($v): string { return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'); }
function esc_attr($v): string { return esc_html($v); }
function esc_url($v): string { return esc_html($v); }
function esc_html__($v, $d): string { return esc_html($v); }
function esc_html_e($v, $d): void { echo esc_html($v); }
function wp_unslash($v) { return $v; }
function wp_get_current_user(): object { return (object) ['ID' => 1, 'user_login' => 'jaydee']; }
function add_query_arg($k, $v, $url): string { return $url . '?' . $k . '=' . $v; }
function wp_nonce_field($action): void { echo '<input type="hidden" name="_wpnonce" value="' . esc_attr('nonce:' . $action) . '">'; }
function check_admin_referer($action): void { if (($_POST['_wpnonce'] ?? '') !== 'nonce:' . $action) { throw new RuntimeException('bad nonce'); } }
final class AfaraRedirect extends RuntimeException {}
$redirect = null;
function wp_redirect($url): void { global $redirect; $redirect = $url; throw new AfaraRedirect('redirect'); }
function wp_die($m, $t = '', $a = []): void { throw new RuntimeException((string) $m); }

use Afara\Admin\AuthorizePage;
use Afara\OAuth\Clients;
use Afara\OAuth\Pkce;

$options = ['afara_enabled' => '1', 'afara_domain_lock' => 'staging.example.test', 'afara_oauth_enabled' => '1', 'permalink_structure' => '/%postname%/'];
$admin = true; $ssl = true; $userId = 1;
$page = new AuthorizePage();
$render = static function () use ($page): string { ob_start(); try { $page->render(); return (string) ob_get_contents(); } finally { ob_end_clean(); } };
$handle = static function () use ($page): ?string { global $redirect; $redirect = null; try { $page->handle(); } catch (AfaraRedirect $e) {} return $redirect; };

$cid = Clients::register(['client_name' => 'Claude <script>', 'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback']])['body']['client_id'];
$verifier = str_repeat('v', 50);
$q = ['page' => 'afara-authorize', 'response_type' => 'code', 'client_id' => $cid, 'redirect_uri' => 'https://claude.ai/api/mcp/auth_callback',
      'code_challenge' => Pkce::challengeFor($verifier), 'code_challenge_method' => 'S256', 'state' => 'abc', 'scope' => 'afara:read'];

// Consent screen.
$_SERVER['REQUEST_METHOD'] = 'GET'; $_GET = $q; $_POST = [];
check($handle() === null, 'valid GET renders, no redirect');
$html = $render();
check(str_contains($html, '“Claude &lt;script&gt;” wants to read this site through Afara') && !str_contains($html, '<script>'), 'app name shown, escaped');
check(str_contains($html, 'The app chose this name itself'), 'name flagged as unverified');
check(str_contains($html, '<strong>claude.ai</strong>'), 'return host shown prominently');
check(str_contains($html, 'It can’t change anything') && str_contains($html, 'jaydee'), 'access and acting account explained');
check(!str_contains($html, 'returns to your own computer'), 'no localhost warning for https app');
check(str_contains($html, 'value="allow"') && str_contains($html, 'value="deny"') && str_contains($html, 'method="post"'), 'Allow and Deny post the form');

// Localhost app gets a warning.
$local = Clients::register(['client_name' => 'CLI', 'redirect_uris' => ['http://localhost:4000/cb']])['body']['client_id'];
$_GET = ['client_id' => $local, 'redirect_uri' => 'http://localhost:4000/cb'] + $q;
check(str_contains($render(), 'returns to your own computer (localhost)'), 'localhost-only app warned');

// Untrusted requests: explained here, never redirected.
$_GET = ['redirect_uri' => 'https://evil.test/cb'] + $q;
check($handle() === null && str_contains($render(), 'won’t send you there'), 'unregistered return address shown, not followed');
$_GET = ['client_id' => 'afara-unknown'] + $q;
check($handle() === null && str_contains($render(), 'isn’t registered'), 'unknown app shown, not followed');
// Protocol errors bounce back to the registered address.
$_GET = ['code_challenge_method' => 'plain'] + $q;
$to = $handle();
check(is_string($to) && str_starts_with($to, 'https://claude.ai/api/mcp/auth_callback?error=invalid_request') && str_contains($to, 'state=abc'), 'protocol error redirected back with state');

// POST: nonce required, then allow / deny.
$_SERVER['REQUEST_METHOD'] = 'POST'; $_GET = ['page' => 'afara-authorize'];
$params = \Afara\OAuth\AuthorizationServer::checkAuthorizeRequest($q)['params'];
$_POST = $q + ['afara_decision' => 'allow', '_wpnonce' => 'forged'];
try { $handle(); check(false, 'forged nonce'); } catch (RuntimeException $e) { check($e->getMessage() === 'bad nonce', 'consent needs a valid nonce'); }
$_POST = $q + ['afara_decision' => 'deny', '_wpnonce' => 'nonce:' . AuthorizePage::nonceAction($params)];
check(str_contains((string) $handle(), '?error=access_denied'), 'Deny returns access_denied');
$_POST['afara_decision'] = 'allow';
$to = (string) $handle();
check(str_starts_with($to, 'https://claude.ai/api/mcp/auth_callback?code=') && str_contains($to, 'iss='), 'Allow returns a code');
$other = $q; $other['code_challenge'] = Pkce::challengeFor(str_repeat('w', 50));
$_POST = $other + ['afara_decision' => 'allow', '_wpnonce' => 'nonce:' . AuthorizePage::nonceAction($params)];
try { $handle(); check(false, 'swapped challenge'); } catch (RuntimeException $e) { check($e->getMessage() === 'bad nonce', 'nonce is bound to the request (no swapping the PKCE challenge)'); }

// Not available / not admin.
$_SERVER['REQUEST_METHOD'] = 'GET'; $_GET = $q;
$options['afara_oauth_enabled'] = '0';
check($handle() === null && str_contains($render(), 'OAuth sign-in is turned off'), 'OAuth off: explained, link to settings');
$options['afara_oauth_enabled'] = '1';
$admin = false;
try { $render(); check(false, 'non-admin'); } catch (RuntimeException $e) { check(str_contains($e->getMessage(), 'Only administrators'), 'only administrators can approve'); }
echo "Authorize page tests passed\n";
