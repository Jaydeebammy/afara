<?php
declare(strict_types=1);

require __DIR__ . '/McpServerTest.php';

function add_option($name, $value, $deprecated = '', $autoload = null): bool {
    global $options; if (array_key_exists($name, $options)) { return false; } $options[$name] = $value; return true;
}
function delete_option($name): bool { global $options; if (!array_key_exists($name, $options)) { return false; } unset($options[$name]); return true; }
$adminIds = [1];
function user_can($id, $cap): bool { global $adminIds; return $cap === 'manage_options' && in_array((int) $id, $adminIds, true); }
function admin_url($path = ''): string { return 'https://staging.example.test/wp-admin/' . $path; }

use Afara\OAuth\AuthorizationServer as AS_;
use Afara\OAuth\Clients;
use Afara\OAuth\Config;
use Afara\OAuth\Grants;
use Afara\OAuth\Pkce;
use Afara\OAuth\Store;

$options = [
    'afara_enabled' => '1',
    'afara_domain_lock' => 'staging.example.test',
    'afara_oauth_enabled' => '1',
    'permalink_structure' => '/%postname%/',
];
$ssl = true;
$resource = Config::resource();

// --- Availability and discovery documents.
check(Config::available(), 'available when Afara, lock, OAuth, permalinks and HTTPS are all set');
foreach ([['afara_oauth_enabled', '0', 'oauth_disabled'], ['permalink_structure', '', 'oauth_needs_permalinks'], ['afara_enabled', '0', 'afara_disabled']] as [$k, $v, $why]) {
    $saved = $options[$k]; $options[$k] = $v;
    check(Config::unavailableReason() === $why, "unavailable: $why");
    $options[$k] = $saved;
}
$ssl = false; check(Config::unavailableReason() === 'afara_https_required', 'unavailable over HTTP'); $ssl = true;
$as = Config::authorizationServerMetadata();
check($as['code_challenge_methods_supported'] === ['S256'], 'advertises S256 only (clients refuse without it)');
check($as['token_endpoint_auth_methods_supported'] === ['none'] && $as['grant_types_supported'] === ['authorization_code', 'refresh_token'], 'public clients, code + refresh');
check(!str_contains($as['issuer'], '#'), 'issuer has no fragment');
$prm = Config::protectedResourceMetadata();
check($prm['resource'] === $resource && $prm['authorization_servers'] === [$as['issuer']], 'protected resource metadata points at Afara’s issuer');
check(str_contains(Config::protectedResourceMetadataUrl(), '/.well-known/oauth-protected-resource'), 'RFC 9728 well-known URL');
check(Config::sameResource(strtoupper('HTTPS://STAGING.EXAMPLE.TEST') . '/?rest_route=/afara/v1/mcp/', $resource) || Config::sameResource('https://STAGING.example.test/?rest_route=/afara/v1/mcp', $resource), 'resource matching ignores host case');
check(!Config::sameResource('https://evil.test/?rest_route=/afara/v1/mcp', $resource), 'other hosts are a different resource');

// --- PKCE.
$verifier = Store::secret(48);
$challenge = Pkce::challengeFor($verifier);
check(Pkce::verify($verifier, $challenge), 'PKCE S256 verifies');
check(!Pkce::verify($verifier . 'x', $challenge) && !Pkce::verify('short', Pkce::challengeFor('short')), 'PKCE rejects wrong or short verifiers');
check(Pkce::challengeFor('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') === 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'RFC 7636 appendix B test vector');

// --- Registration.
$bad = [
    ['redirect_uris' => []],
    ['redirect_uris' => ['http://evil.test/cb']],
    ['redirect_uris' => ['https://app.test/cb#frag']],
    ['redirect_uris' => ['https://user:pw@app.test/cb']],
    ['redirect_uris' => ['cursor://callback']],
    ['redirect_uris' => ['https://app.test/cb'], 'token_endpoint_auth_method' => 'client_secret_basic'],
    ['redirect_uris' => ['https://app.test/cb'], 'grant_types' => ['password']],
    ['redirect_uris' => ['https://app.test/cb'], 'response_types' => ['token']],
];
foreach ($bad as $i => $body) {
    check(Clients::register($body)['status'] === 400, "registration rejected #$i");
}
$reg = Clients::register(['client_name' => "Claude\x07 <b>", 'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback']]);
check($reg['status'] === 201 && str_starts_with($reg['body']['client_id'], 'afara-') && $reg['body']['token_endpoint_auth_method'] === 'none', 'registration returns a public client');
check($reg['body']['client_name'] === 'Claude <b>', 'control characters stripped (escaping happens on output)');
$clientId = $reg['body']['client_id'];
$redirect = 'https://claude.ai/api/mcp/auth_callback';
$local = Clients::register(['client_name' => 'CLI', 'redirect_uris' => ['http://127.0.0.1:33418/callback']]);
check($local['status'] === 201 && Clients::localhostOnly(Clients::find($local['body']['client_id'])), 'loopback http allowed and flagged');
check(!Clients::localhostOnly(Clients::find($clientId)), 'https client not flagged as localhost-only');

// --- Authorization request validation.
$q = ['response_type' => 'code', 'client_id' => $clientId, 'redirect_uri' => $redirect, 'code_challenge' => $challenge,
      'code_challenge_method' => 'S256', 'state' => 'st<a>te', 'scope' => 'afara:read', 'resource' => $resource];
$ok = AS_::checkAuthorizeRequest($q);
check($ok['ok'] === true && $ok['params']['resource'] === $resource, 'valid authorization request');
$r = AS_::checkAuthorizeRequest(['client_id' => 'afara-nope'] + $q);
check($r['ok'] === false && $r['redirect'] === null, 'unknown client: show error, never redirect');
$r = AS_::checkAuthorizeRequest(['redirect_uri' => 'https://evil.test/cb'] + $q);
check($r['ok'] === false && $r['redirect'] === null, 'unregistered redirect: never redirect');
$r = AS_::checkAuthorizeRequest(['redirect_uri' => $redirect . '?x=1'] + $q);
check($r['ok'] === false && $r['redirect'] === null, 'redirect must match exactly');
foreach ([['code_challenge_method' => 'plain'], ['code_challenge' => ''], ['response_type' => 'token'], ['scope' => 'afara:write'], ['resource' => 'https://other.test/mcp']] as $i => $override) {
    $r = AS_::checkAuthorizeRequest($override + $q);
    check($r['ok'] === false && is_string($r['redirect']) && str_starts_with($r['redirect'], $redirect . '?error='), "protocol error redirects back with error #$i");
    check(str_contains($r['redirect'], 'state=st%3Ca%3Ete') && str_contains($r['redirect'], 'iss='), "error keeps state and iss #$i");
}
check(AS_::checkAuthorizeRequest(['scope' => ''] + $q)['params']['scope'] === 'afara:read', 'empty scope defaults to afara:read');

// --- Token endpoint: unapproved client can't redeem anything.
check(AS_::token(['grant_type' => 'authorization_code', 'client_id' => $clientId])['body']['error'] === 'invalid_client', 'unapproved client refused at token endpoint');

// --- Approve → code → tokens.
$params = $ok['params'];
$approve = static function () use ($params): string {
    $url = AS_::approve($params, 1);
    parse_str((string) parse_url($url, PHP_URL_QUERY), $out);
    return (string) $out['code'];
};
$url = AS_::approve($params, 1);
check(str_starts_with($url, $redirect . '?code=') && str_contains($url, 'state=st%3Ca%3Ete') && str_contains($url, 'iss=' . rawurlencode(Config::issuer())), 'approval redirects with code, state and iss');
parse_str((string) parse_url($url, PHP_URL_QUERY), $out);
$code = $out['code'];
check(Clients::find($clientId)['approved'] === true, 'consent approves the client');
check(!str_contains(json_encode($options), $code), 'codes are stored hashed');
$exchange = static fn (string $code, string $v, array $extra = []) => AS_::token($extra + ['grant_type' => 'authorization_code', 'client_id' => $clientId, 'code' => $code, 'redirect_uri' => $redirect, 'code_verifier' => $v, 'resource' => $resource]);

check($exchange($approve(), 'wrong-verifier-' . str_repeat('a', 40))['body']['error'] === 'invalid_grant', 'wrong PKCE verifier refused');
check($exchange($approve(), $verifier, ['redirect_uri' => 'https://claude.ai/other'])['body']['error'] === 'invalid_grant', 'different redirect_uri refused');
check($exchange($approve(), $verifier, ['resource' => 'https://other.test/mcp'])['body']['error'] === 'invalid_target', 'other resource refused');
$other = Clients::register(['client_name' => 'Other', 'redirect_uris' => [$redirect]])['body']['client_id'];
Clients::approve($other);
check(AS_::token(['grant_type' => 'authorization_code', 'client_id' => $other, 'code' => $approve(), 'redirect_uri' => $redirect, 'code_verifier' => $verifier])['body']['error'] === 'invalid_grant', 'code issued to another client refused');

$t = $exchange($code, $verifier);
check($t['status'] === 200 && $t['body']['token_type'] === 'Bearer' && $t['body']['expires_in'] === 3600 && $t['body']['scope'] === 'afara:read', 'code exchanged for tokens');
$access = $t['body']['access_token']; $refresh = $t['body']['refresh_token'];
check(!str_contains(json_encode($options), $access) && !str_contains(json_encode($options), $refresh), 'tokens are stored hashed');
$v = AS_::verifyAccessToken($access);
check($v !== null && $v['user_id'] === 1 && $v['client_name'] === 'Claude <b>', 'access token verifies to the approving admin');
check(AS_::verifyAccessToken('not-a-token') === null && AS_::verifyAccessToken($refresh) === null, 'random strings and refresh tokens are not access tokens');

// Code replay revokes what it produced.
check($exchange($code, $verifier)['body']['error'] === 'invalid_grant', 'code is single-use');
check(AS_::verifyAccessToken($access) === null, 'replaying a code revokes the tokens it produced');

// --- Refresh rotation and reuse detection.
$t = $exchange($approve(), $verifier);
$access = $t['body']['access_token']; $refresh = $t['body']['refresh_token'];
$r1 = AS_::token(['grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $refresh]);
check($r1['status'] === 200 && $r1['body']['refresh_token'] !== $refresh, 'refresh rotates the refresh token');
check(AS_::verifyAccessToken($r1['body']['access_token']) !== null, 'new access token works');
check(AS_::token(['grant_type' => 'refresh_token', 'client_id' => $other, 'refresh_token' => $r1['body']['refresh_token']])['body']['error'] === 'invalid_grant', 'refresh token bound to its client');
$t2 = $exchange($approve(), $verifier);
$r2 = AS_::token(['grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $t2['body']['refresh_token']]);
check(AS_::token(['grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $t2['body']['refresh_token']])['body']['error'] === 'invalid_grant', 'old refresh token refused');
check(AS_::verifyAccessToken($r2['body']['access_token']) === null, 'reusing an old refresh token revokes the grant');
check(AS_::token(['grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $r2['body']['refresh_token']])['body']['error'] === 'invalid_grant', 'and its newest refresh token too');
check(AS_::token(['grant_type' => 'password', 'client_id' => $clientId])['body']['error'] === 'unsupported_grant_type', 'password grant unsupported');

// --- Expiry, audience, demoted admin.
$t = $exchange($approve(), $verifier);
$name = 'afara_oauth_r_a_' . hash('sha256', $t['body']['access_token']);
$options[$name]['exp'] = time() - 1;
check(AS_::verifyAccessToken($t['body']['access_token']) === null && !isset($options[$name]), 'expired access token refused and cleaned up');
$t = $exchange($approve(), $verifier);
$name = 'afara_oauth_r_a_' . hash('sha256', $t['body']['access_token']);
$options[$name]['data']['resource'] = 'https://other.test/mcp';
check(AS_::verifyAccessToken($t['body']['access_token']) === null, 'token for another audience refused');
$t = $exchange($approve(), $verifier);
$adminIds = [];
check(AS_::token(['grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $t['body']['refresh_token']])['body']['error'] === 'invalid_grant', 'demoted admin can’t refresh');
check($exchange($approve(), $verifier)['body']['error'] === 'invalid_grant', 'demoted admin’s codes can’t be redeemed');
$adminIds = [1];

// --- Revocation endpoint.
$t = $exchange($approve(), $verifier);
check(AS_::revoke(['token' => $t['body']['access_token'], 'client_id' => $other])['status'] === 200 && AS_::verifyAccessToken($t['body']['access_token']) !== null, 'another client can’t revoke your token (and learns nothing)');
check(AS_::revoke(['token' => $t['body']['refresh_token'], 'client_id' => $clientId])['status'] === 200 && AS_::verifyAccessToken($t['body']['access_token']) === null, 'revoking the refresh token revokes the grant');
check(AS_::revoke(['token' => 'unknown', 'client_id' => $clientId])['status'] === 200, 'unknown tokens still return 200');

// --- Grants: revoke from Connect.
$t = $exchange($approve(), $verifier);
$grantId = AS_::verifyAccessToken($t['body']['access_token'])['grant_id'];
check(preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $grantId) === 1, 'grant IDs are UUID v4');
check(Grants::revoke($grantId) && AS_::verifyAccessToken($t['body']['access_token']) === null, 'revoking a grant kills its tokens');

// --- Bearer plumbing: only on Afara's route.
$http = new \Afara\OAuth\Http();
$t = $exchange($approve(), $verifier);
$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $t['body']['access_token'];
$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/users/me'; $_GET = [];
check($http->authenticate(false) === false, 'token signs nobody in on other WordPress routes');
$_SERVER['REQUEST_URI'] = '/wp-json/afara/v1/mcp';
\Afara\Mcp\Server::resetRequestState(); \Afara\OAuth\Http::resetRequestState();
check($http->authenticate(false) === 1, 'token signs the admin in on Afara’s route');
check($http->authenticationErrors(null) === null, 'valid token: no auth error');
$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer forged';
\Afara\OAuth\Http::resetRequestState();
check($http->authenticate(false) === false, 'forged token signs nobody in');
check($http->authenticationErrors(null) instanceof WP_Error, 'forged token is a 401 error, not anonymous');
check(\Afara\Audit\ActivityLog::recent()[0]['reason'] === 'afara_invalid_token', 'forged token logged as refused');
$options['afara_oauth_enabled'] = '0';
$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $t['body']['access_token'];
\Afara\OAuth\Http::resetRequestState();
check($http->authenticate(false) === false, 'turning OAuth off stops existing tokens');
$options['afara_oauth_enabled'] = '1';
unset($_SERVER['HTTP_AUTHORIZATION']); $_SERVER['REQUEST_URI'] = '/';
\Afara\OAuth\Http::resetRequestState(); \Afara\Mcp\Server::resetRequestState();

// --- Registry bounds.
$options[Clients::OPTION] = [];
for ($i = 0; $i < Clients::MAX_CLIENTS; $i++) { Clients::register(['redirect_uris' => ['https://app.test/cb']]); }
check(Clients::register(['redirect_uris' => ['https://app.test/cb']])['status'] === 429, 'registry is capped');
foreach ($options[Clients::OPTION] as &$c) { $c['created'] -= Clients::PENDING_TTL + 1; } unset($c);
check(Clients::register(['redirect_uris' => ['https://app.test/cb']])['status'] === 201, 'stale unapproved registrations are pruned');

echo "OAuth tests passed\n";
