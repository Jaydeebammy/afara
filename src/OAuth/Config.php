<?php
declare(strict_types=1);

namespace Afara\OAuth;

use Afara\Mcp\Server;
use Afara\Security\PermissionGate;

/** OAuth settings, URLs and the two discovery documents. */
final class Config
{
    public const OPTION_ENABLED = 'afara_oauth_enabled';
    public const SCOPE = 'afara:read';
    public const ACCESS_TTL = 3600;
    public const REFRESH_TTL = 2592000; // 30 days
    public const CODE_TTL = 60;
    public const USED_CODE_TTL = 600;
    public const REST_BASE = 'oauth';
    public const AUTHORIZE_PAGE = 'afara-authorize';

    public static function enabledSetting(): bool
    {
        return get_option(self::OPTION_ENABLED, '0') === '1';
    }

    /**
     * Why OAuth can't be used right now, as a short code, or null when it can.
     * Order matches what the admin should fix first.
     */
    public static function unavailableReason(): ?string
    {
        $gate = new PermissionGate();
        if (!$gate->isEnabled()) {
            return 'afara_disabled';
        }
        if (!$gate->isDomainMatched()) {
            return 'afara_domain_mismatch';
        }
        if (!self::enabledSetting()) {
            return 'oauth_disabled';
        }
        if ((string) get_option('permalink_structure', '') === '') {
            return 'oauth_needs_permalinks';
        }
        if (!is_ssl()) {
            return 'afara_https_required';
        }
        return null;
    }

    public static function available(): bool
    {
        return self::unavailableReason() === null;
    }

    public static function issuer(): string
    {
        return rtrim(rest_url(Server::REST_NAMESPACE . '/' . self::REST_BASE), '/');
    }

    /** The canonical URI of Afara's MCP server: the audience every token is bound to. */
    public static function resource(): string
    {
        return rtrim(Server::endpoint(), '/');
    }

    public static function endpoint(string $name): string
    {
        return rest_url(Server::REST_NAMESPACE . '/' . self::REST_BASE . '/' . $name);
    }

    public static function authorizeUrl(): string
    {
        return admin_url('admin.php?page=' . self::AUTHORIZE_PAGE);
    }

    /** RFC 9728 path-inserted location, e.g. /.well-known/oauth-protected-resource/wp-json/afara/v1/mcp */
    public static function protectedResourceMetadataUrl(): string
    {
        return self::wellKnown('oauth-protected-resource', self::resource());
    }

    /** RFC 8414 path-inserted location for the issuer. */
    public static function authorizationServerMetadataUrl(): string
    {
        return self::wellKnown('oauth-authorization-server', self::issuer());
    }

    /** Same resource, ignoring case of scheme/host and a trailing slash (RFC 8707 robustness). */
    public static function sameResource(string $a, string $b): bool
    {
        $norm = static function (string $uri): string {
            $p = parse_url(trim($uri));
            if (!is_array($p) || !isset($p['scheme'], $p['host']) || isset($p['fragment'])) {
                return '';
            }
            $port = isset($p['port']) ? ':' . $p['port'] : '';
            $query = isset($p['query']) ? '?' . $p['query'] : '';
            return strtolower($p['scheme']) . '://' . strtolower($p['host']) . $port . rtrim($p['path'] ?? '', '/') . $query;
        };
        $na = $norm($a);
        return $na !== '' && hash_equals($na, $norm($b));
    }

    /** @return array<string, mixed> RFC 8414 Authorization Server Metadata */
    public static function authorizationServerMetadata(): array
    {
        return [
            'issuer' => self::issuer(),
            'authorization_endpoint' => self::authorizeUrl(),
            'token_endpoint' => self::endpoint('token'),
            'registration_endpoint' => self::endpoint('register'),
            'revocation_endpoint' => self::endpoint('revoke'),
            'device_authorization_endpoint' => self::endpoint('device'),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token', DeviceFlow::GRANT],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none'],
            'revocation_endpoint_auth_methods_supported' => ['none'],
            'scopes_supported' => [self::SCOPE],
            'authorization_response_iss_parameter_supported' => true,
            'client_id_metadata_document_supported' => false,
        ];
    }

    /** @return array<string, mixed> RFC 9728 Protected Resource Metadata */
    public static function protectedResourceMetadata(): array
    {
        return [
            'resource' => self::resource(),
            'authorization_servers' => [self::issuer()],
            'scopes_supported' => [self::SCOPE],
            'bearer_methods_supported' => ['header'],
            'resource_name' => 'Afara',
        ];
    }

    private static function wellKnown(string $suffix, string $uri): string
    {
        $p = parse_url($uri);
        $origin = strtolower((string) ($p['scheme'] ?? 'https')) . '://' . strtolower((string) ($p['host'] ?? '')) . (isset($p['port']) ? ':' . $p['port'] : '');
        $path = rtrim((string) ($p['path'] ?? ''), '/');
        return $origin . '/.well-known/' . $suffix . $path;
    }
}
