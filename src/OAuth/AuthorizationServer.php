<?php
declare(strict_types=1);

namespace Afara\OAuth;

/**
 * OAuth 2.1 authorization server logic, independent of HTTP plumbing.
 *
 * - Authorization code grant with PKCE S256 (required), public clients only.
 * - Tokens are bound to Afara's MCP endpoint (RFC 8707 resource).
 * - Codes are single-use; replaying one revokes the grant it produced.
 * - Refresh tokens rotate on every use; replaying an old one revokes the grant.
 */
final class AuthorizationServer
{
    /**
     * Validate an authorization request (the consent screen's GET parameters).
     *
     * If the client or redirect URI can't be trusted, never redirect: show the
     * error on Afara's own page instead (RFC 6749 §4.1.2.1).
     *
     * @param array<string, mixed> $q
     * @return array{ok: true, client: array<string, mixed>, params: array<string, string>}|array{ok: false, redirect: ?string, message: string}
     */
    public static function checkAuthorizeRequest(array $q): array
    {
        $str = static fn (string $k): string => isset($q[$k]) && is_string($q[$k]) ? $q[$k] : '';
        $clientId = $str('client_id');
        $client = $clientId !== '' ? Clients::find($clientId) : null;
        if ($client === null) {
            return ['ok' => false, 'redirect' => null, 'message' => __('This app isn’t registered with Afara, or its registration expired. Start the connection again from the app.', 'afara')];
        }
        $redirect = $str('redirect_uri');
        if ($redirect === '' && count((array) $client['redirect_uris']) === 1) {
            $redirect = (string) $client['redirect_uris'][0];
        }
        if ($redirect === '' || !Clients::hasRedirect($client, $redirect)) {
            return ['ok' => false, 'redirect' => null, 'message' => __('The app sent a return address that it didn’t register. Afara won’t send you there.', 'afara')];
        }
        $state = $str('state');
        $fail = static fn (string $error, string $message): array => [
            'ok' => false,
            'redirect' => self::redirectWith($redirect, ['error' => $error, 'error_description' => $message], $state),
            'message' => $message,
        ];
        if (strlen($state) > 1024) {
            return $fail('invalid_request', 'state is too long.');
        }
        if ($str('response_type') !== 'code') {
            return $fail('unsupported_response_type', 'Only response_type=code is supported.');
        }
        if (!Clients::allowsGrant($client, 'authorization_code')) {
            return $fail('unauthorized_client', 'This client did not register for the authorization_code grant.');
        }
        if ($str('code_challenge_method') !== 'S256' || !Pkce::validChallenge($str('code_challenge'))) {
            return $fail('invalid_request', 'PKCE with code_challenge_method=S256 is required.');
        }
        $scope = self::scope($str('scope'));
        if ($scope === null) {
            return $fail('invalid_scope', 'The only scope Afara offers is ' . Config::SCOPE . '.');
        }
        $resource = $str('resource');
        if ($resource !== '' && !Config::sameResource($resource, Config::resource())) {
            return $fail('invalid_target', 'Tokens can only be issued for this site’s Afara MCP server.');
        }
        return ['ok' => true, 'client' => $client, 'params' => [
            'client_id' => $clientId,
            'redirect_uri' => $redirect,
            'code_challenge' => $str('code_challenge'),
            'state' => $state,
            'scope' => $scope,
            'resource' => Config::resource(),
        ]];
    }

    /** The administrator allowed it: issue a one-time code and return where to send the browser. */
    public static function approve(array $params, int $userId): string
    {
        Clients::approve($params['client_id']);
        $code = Store::secret();
        Store::put(Store::KIND_CODE, $code, [
            'client_id' => $params['client_id'],
            'redirect_uri' => $params['redirect_uri'],
            'code_challenge' => $params['code_challenge'],
            'user_id' => $userId,
            'scope' => $params['scope'],
            'resource' => $params['resource'],
        ], Config::CODE_TTL);
        return self::redirectWith($params['redirect_uri'], ['code' => $code], $params['state']);
    }

    public static function deny(array $params): string
    {
        return self::redirectWith($params['redirect_uri'], ['error' => 'access_denied', 'error_description' => 'The site administrator declined.'], $params['state']);
    }

    /**
     * Token endpoint (form-encoded body).
     *
     * @param array<string, mixed> $body
     * @return array{status: int, body: array<string, mixed>}
     */
    public static function token(array $body): array
    {
        $str = static fn (string $k): string => isset($body[$k]) && is_string($body[$k]) ? $body[$k] : '';
        $client = Clients::find($str('client_id'));
        if ($client === null || empty($client['approved'])) {
            return self::error('invalid_client', 'Unknown or unapproved client_id.');
        }
        $resource = $str('resource');
        if ($resource !== '' && !Config::sameResource($resource, Config::resource())) {
            return self::error('invalid_target', 'Tokens can only be issued for this site’s Afara MCP server.');
        }
        return match ($str('grant_type')) {
            'authorization_code' => self::exchangeCode($str('client_id'), $client, $str('code'), $str('redirect_uri'), $str('code_verifier')),
            'refresh_token' => self::refresh($str('client_id'), $client, $str('refresh_token'), $str('scope')),
            default => self::error('unsupported_grant_type', 'Supported: authorization_code, refresh_token.'),
        };
    }

    /**
     * Revocation endpoint (RFC 7009). Revoking either token revokes the whole grant.
     * Always 200 for unknown tokens, so it can't be used to probe for valid ones.
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public static function revoke(array $body): array
    {
        $token = isset($body['token']) && is_string($body['token']) ? $body['token'] : '';
        $clientId = isset($body['client_id']) && is_string($body['client_id']) ? $body['client_id'] : '';
        if ($token === '') {
            return self::error('invalid_request', 'token is required.');
        }
        foreach ([Store::KIND_ACCESS, Store::KIND_REFRESH] as $kind) {
            $record = Store::get($kind, $token);
            if ($record !== null && hash_equals((string) $record['client_id'], $clientId)) {
                Grants::revoke((string) $record['grant_id']);
                break;
            }
        }
        return ['status' => 200, 'body' => []];
    }

    /**
     * Resource-server check for a bearer token presented to Afara's MCP route.
     *
     * @return array{user_id: int, grant_id: string, client_name: string, scope: string}|null
     */
    public static function verifyAccessToken(string $token): ?array
    {
        $record = Store::get(Store::KIND_ACCESS, $token);
        if ($record === null) {
            return null;
        }
        $grant = Grants::find((string) ($record['grant_id'] ?? ''));
        if ($grant === null
            || (int) $grant['user_id'] !== (int) $record['user_id']
            || !Config::sameResource((string) $record['resource'], Config::resource())
            || !in_array(Config::SCOPE, explode(' ', (string) $record['scope']), true)) {
            return null;
        }
        return [
            'user_id' => (int) $record['user_id'],
            'grant_id' => (string) $record['grant_id'],
            'client_name' => (string) $grant['client_name'],
            'scope' => (string) $record['scope'],
        ];
    }

    /** @param array<string, mixed> $client */
    private static function exchangeCode(string $clientId, array $client, string $code, string $redirectUri, string $verifier): array
    {
        if (!Clients::allowsGrant($client, 'authorization_code')) {
            return self::error('unauthorized_client', 'This client did not register for the authorization_code grant.');
        }
        $data = Store::claim(Store::KIND_CODE, $code);
        if ($data === null) {
            $used = Store::get(Store::KIND_USED_CODE, $code);
            if ($used !== null) {
                Grants::revoke((string) $used['grant_id']); // Replay: someone else has this code.
            }
            return self::error('invalid_grant', 'The code is invalid, expired or already used.');
        }
        if (!hash_equals((string) $data['client_id'], $clientId)) {
            return self::error('invalid_grant', 'The code was issued to a different client.');
        }
        if ($redirectUri !== '' && !hash_equals((string) $data['redirect_uri'], $redirectUri)) {
            return self::error('invalid_grant', 'redirect_uri does not match the authorization request.');
        }
        if (!Pkce::verify($verifier, (string) $data['code_challenge'])) {
            return self::error('invalid_grant', 'PKCE verification failed.');
        }
        $userId = (int) $data['user_id'];
        if (!user_can($userId, 'manage_options')) {
            return self::error('invalid_grant', 'The approving account is no longer an administrator.');
        }
        $grantId = Grants::create($clientId, (string) $client['client_name'], $userId, (string) $data['scope'], (string) $data['resource']);
        Store::put(Store::KIND_USED_CODE, $code, ['grant_id' => $grantId], Config::USED_CODE_TTL);
        return self::issue($grantId, Grants::find($grantId) ?? []);
    }

    /** @param array<string, mixed> $client */
    private static function refresh(string $clientId, array $client, string $token, string $scope): array
    {
        if (!Clients::allowsGrant($client, 'refresh_token')) {
            return self::error('unauthorized_client', 'This client did not register for the refresh_token grant.');
        }
        $data = Store::claim(Store::KIND_REFRESH, $token);
        if ($data === null) {
            $used = Store::get(Store::KIND_USED_REFRESH, $token);
            if ($used !== null) {
                Grants::revoke((string) $used['grant_id']); // Rotation replay: assume the token was stolen.
            }
            return self::error('invalid_grant', 'The refresh token is invalid, expired or already used.');
        }
        if (!hash_equals((string) $data['client_id'], $clientId)) {
            return self::error('invalid_grant', 'The refresh token was issued to a different client.');
        }
        $grantId = (string) $data['grant_id'];
        $grant = Grants::find($grantId);
        if ($grant === null) {
            return self::error('invalid_grant', 'This connection was revoked.');
        }
        if ($scope !== '' && self::scope($scope) === null) {
            return self::error('invalid_scope', 'The only scope Afara offers is ' . Config::SCOPE . '.');
        }
        if (!user_can((int) $grant['user_id'], 'manage_options')) {
            Grants::revoke($grantId);
            return self::error('invalid_grant', 'The approving account is no longer an administrator.');
        }
        Store::put(Store::KIND_USED_REFRESH, $token, ['grant_id' => $grantId], Config::REFRESH_TTL);
        return self::issue($grantId, $grant);
    }

    /** @param array<string, mixed> $grant */
    private static function issue(string $grantId, array $grant): array
    {
        $access = Store::secret();
        $refresh = Store::secret();
        Store::put(Store::KIND_ACCESS, $access, [
            'grant_id' => $grantId,
            'user_id' => (int) $grant['user_id'],
            'client_id' => (string) $grant['client_id'],
            'scope' => (string) $grant['scope'],
            'resource' => (string) $grant['resource'],
        ], Config::ACCESS_TTL);
        Store::put(Store::KIND_REFRESH, $refresh, [
            'grant_id' => $grantId,
            'client_id' => (string) $grant['client_id'],
        ], Config::REFRESH_TTL);
        return ['status' => 200, 'body' => [
            'access_token' => $access,
            'token_type' => 'Bearer',
            'expires_in' => Config::ACCESS_TTL,
            'refresh_token' => $refresh,
            'scope' => (string) $grant['scope'],
        ]];
    }

    /** Space-separated scopes; empty means the default. Returns null for anything Afara doesn't offer. */
    private static function scope(string $requested): ?string
    {
        $parts = array_values(array_filter(explode(' ', trim($requested)), static fn (string $s): bool => $s !== ''));
        if ($parts === []) {
            return Config::SCOPE;
        }
        return array_diff($parts, [Config::SCOPE]) === [] ? Config::SCOPE : null;
    }

    /** @param array<string, string> $params */
    private static function redirectWith(string $uri, array $params, string $state): string
    {
        if ($state !== '') {
            $params['state'] = $state;
        }
        $params['iss'] = Config::issuer(); // RFC 9207 mix-up protection.
        return $uri . (str_contains($uri, '?') ? '&' : '?') . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /** @return array{status: int, body: array<string, string>} */
    private static function error(string $code, string $description, int $status = 400): array
    {
        return ['status' => $status, 'body' => ['error' => $code, 'error_description' => $description]];
    }
}
