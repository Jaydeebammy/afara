<?php
declare(strict_types=1);

namespace Afara\OAuth;

/**
 * OAuth clients created by Dynamic Client Registration (RFC 7591).
 *
 * Public clients only (no client secret); PKCE protects the code instead.
 * Redirect URIs must be HTTPS or loopback, as the MCP spec requires, and are
 * matched exactly. A client is "approved" once an administrator allows it on
 * the consent screen. Unapproved registrations expire after a day so the
 * registry can't be filled up by strangers.
 */
final class Clients
{
    public const OPTION = 'afara_oauth_clients';
    public const MAX_CLIENTS = 50;
    public const MAX_REDIRECTS = 10;
    public const PENDING_TTL = 86400;
    public const GRANT_TYPES = ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'];

    /** @return array<string, array<string, mixed>> */
    public static function all(): array
    {
        $clients = get_option(self::OPTION, []);
        return is_array($clients) ? $clients : [];
    }

    /** @return array<string, mixed>|null */
    public static function find(string $clientId): ?array
    {
        $clients = self::all();
        return isset($clients[$clientId]) && is_array($clients[$clientId]) ? $clients[$clientId] : null;
    }

    public static function hasRedirect(array $client, string $redirectUri): bool
    {
        foreach ((array) ($client['redirect_uris'] ?? []) as $registered) {
            if (is_string($registered) && hash_equals($registered, $redirectUri)) {
                return true;
            }
        }
        return false;
    }

    public static function allowsGrant(array $client, string $grant): bool
    {
        return in_array($grant, (array) ($client['grant_types'] ?? []), true);
    }

    public static function approve(string $clientId, ?int $now = null): void
    {
        $clients = self::all();
        if (isset($clients[$clientId])) {
            $clients[$clientId]['approved'] = true;
            $clients[$clientId]['approved_at'] = $now ?? time();
            update_option(self::OPTION, $clients, false);
        }
    }

    public static function remove(string $clientId): void
    {
        $clients = self::all();
        unset($clients[$clientId]);
        update_option(self::OPTION, $clients, false);
    }

    /**
     * Register a client from an RFC 7591 request body.
     *
     * @param array<string, mixed> $body
     * @return array{status: int, body: array<string, mixed>}
     */
    public static function register(array $body, ?int $now = null): array
    {
        $now ??= time();
        $redirects = $body['redirect_uris'] ?? null;
        if (!is_array($redirects) || $redirects === [] || count($redirects) > self::MAX_REDIRECTS) {
            return self::error('invalid_redirect_uri', 'Provide between 1 and 10 redirect_uris.');
        }
        $clean = [];
        foreach ($redirects as $uri) {
            if (!is_string($uri) || !self::validRedirect($uri)) {
                return self::error('invalid_redirect_uri', 'Redirect URIs must use HTTPS, or http on localhost, with no fragment.');
            }
            $clean[] = $uri;
        }
        $method = $body['token_endpoint_auth_method'] ?? 'none';
        if ($method !== 'none') {
            return self::error('invalid_client_metadata', 'Only public clients (token_endpoint_auth_method "none") are supported. PKCE is required.');
        }
        $grants = $body['grant_types'] ?? ['authorization_code', 'refresh_token'];
        if (!is_array($grants) || $grants === [] || array_diff($grants, self::GRANT_TYPES) !== []) {
            return self::error('invalid_client_metadata', 'Unsupported grant_types.');
        }
        $responses = $body['response_types'] ?? ['code'];
        if (!is_array($responses) || array_diff($responses, ['code']) !== []) {
            return self::error('invalid_client_metadata', 'Only response_types ["code"] is supported.');
        }
        $name = self::name(is_string($body['client_name'] ?? null) ? $body['client_name'] : '');

        $clients = self::prunePending(self::all(), $now);
        if (count($clients) >= self::MAX_CLIENTS) {
            return ['status' => 429, 'body' => ['error' => 'temporarily_unavailable', 'error_description' => 'Too many registered clients. Revoke unused ones in Afara → Connect.']];
        }
        $clientId = 'afara-' . bin2hex(random_bytes(16));
        $clients[$clientId] = [
            'client_name' => $name,
            'redirect_uris' => array_values(array_unique($clean)),
            'grant_types' => array_values(array_unique($grants)),
            'created' => $now,
            'approved' => false,
        ];
        update_option(self::OPTION, $clients, false);

        return ['status' => 201, 'body' => [
            'client_id' => $clientId,
            'client_id_issued_at' => $now,
            'client_name' => $name,
            'redirect_uris' => $clients[$clientId]['redirect_uris'],
            'grant_types' => $clients[$clientId]['grant_types'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ]];
    }

    /** HTTPS anywhere, or http only on a loopback host. No fragments, no credentials in the URL. */
    public static function validRedirect(string $uri): bool
    {
        if (strlen($uri) > 2000 || preg_match('/[\s<>"]/', $uri)) {
            return false;
        }
        $parts = parse_url($uri);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme === 'https') {
            return true;
        }
        return $scheme === 'http' && self::isLoopback((string) $parts['host']);
    }

    public static function isLoopback(string $host): bool
    {
        return in_array(strtolower(trim($host, '[]')), ['localhost', '127.0.0.1', '::1'], true);
    }

    /** True when every redirect goes to the user's own machine, so the name can't be trusted. */
    public static function localhostOnly(array $client): bool
    {
        foreach ((array) ($client['redirect_uris'] ?? []) as $uri) {
            if (!self::isLoopback((string) parse_url((string) $uri, PHP_URL_HOST))) {
                return false;
            }
        }
        return true;
    }

    private static function name(string $name): string
    {
        $name = trim((string) preg_replace('/[^\P{C}]+/u', '', $name));
        $name = function_exists('mb_substr') ? mb_substr($name, 0, 80) : substr($name, 0, 80);
        return $name !== '' ? $name : 'Unnamed app';
    }

    /**
     * @param array<string, array<string, mixed>> $clients
     * @return array<string, array<string, mixed>>
     */
    private static function prunePending(array $clients, int $now): array
    {
        return array_filter($clients, static fn (array $c): bool => !empty($c['approved']) || (int) ($c['created'] ?? 0) > $now - self::PENDING_TTL);
    }

    /** @return array{status: int, body: array<string, string>} */
    private static function error(string $code, string $description): array
    {
        return ['status' => 400, 'body' => ['error' => $code, 'error_description' => $description]];
    }
}
