<?php
declare(strict_types=1);

namespace Afara\Mcp;

use Afara\Audit\ActivityLog;
use Afara\Security\PermissionGate;
use WP\MCP\Core\McpAdapter;
use WP\MCP\Transport\HttpTransport;

/** Uses the separately activated official adapter; never boots a bundled copy. */
final class Server
{
    public const MIN_ADAPTER_VERSION = '0.7.1';
    public const ID = 'afara';
    public const REST_NAMESPACE = 'afara/v1';
    public const REST_ROUTE = 'mcp';
    public const ABILITIES = ['afara/site-context', 'afara/read-file', 'afara/list-directory'];

    /** One refusal entry per HTTP request, however many times the adapter re-checks. */
    private static bool $refusalRecorded = false;

    public function __construct(private readonly PermissionGate $gate) {}

    public function register(): void
    {
        add_action('mcp_adapter_init', [$this, 'create']);
        // Core fires these while authenticating API requests, before routing.
        add_action('application_password_did_authenticate', [$this, 'connectionAuthenticated'], 10, 2);
        add_action('application_password_failed_authentication', [$this, 'connectionFailed'], 10, 1);
    }

    /** Is the current HTTP request addressed to Afara's MCP route? Read-only check of the URL. */
    public static function isAfaraRequest(): bool
    {
        $route = '/' . self::REST_NAMESPACE . '/' . self::REST_ROUTE;
        // phpcs:ignore WordPress.Security.NonceVerification -- routing check only, no data changes.
        $restRoute = isset($_GET['rest_route']) && is_string($_GET['rest_route']) ? $_GET['rest_route'] : '';
        if ($restRoute !== '') {
            return $restRoute === $route || str_starts_with($restRoute, $route . '/');
        }
        $uri = isset($_SERVER['REQUEST_URI']) && is_string($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $path = (string) wp_parse_url($uri, PHP_URL_PATH);
        $prefix = '/' . trim(function_exists('rest_get_url_prefix') ? rest_get_url_prefix() : 'wp-json', '/');
        $needle = $prefix . $route;
        return str_contains($path, $needle . '/') || str_ends_with(rtrim($path, '/'), $needle);
    }

    /** @param mixed $user @param mixed $item Core's Application Password record. */
    public function connectionAuthenticated($user, $item): void
    {
        if (self::isAfaraRequest() && is_array($item)) {
            ActivityLog::useConnection((string) ($item['name'] ?? ''), (string) ($item['uuid'] ?? ''));
        }
    }

    /** Wrong, revoked or unusable Application Password on Afara's route. Only the error code is kept. */
    public function connectionFailed($error): void
    {
        if (!self::isAfaraRequest() || self::$refusalRecorded) {
            return;
        }
        $code = is_object($error) && method_exists($error, 'get_error_code') ? (string) $error->get_error_code() : '';
        self::$refusalRecorded = true;
        ActivityLog::refused($code !== '' ? $code : 'afara_sign_in_failed');
    }

    /** Test hook: start a fresh simulated request. */
    public static function resetRequestState(): void
    {
        self::$refusalRecorded = false;
        ActivityLog::resetConnection();
    }

    public static function adapterAvailable(): bool
    {
        return defined('WP_MCP_VERSION')
            && version_compare(WP_MCP_VERSION, self::MIN_ADAPTER_VERSION, '>=')
            && class_exists(McpAdapter::class)
            && class_exists(HttpTransport::class);
    }

    public static function abilitiesAvailable(): bool
    {
        if (!function_exists('wp_get_ability')) {
            return false;
        }
        foreach (self::ABILITIES as $name) {
            if (wp_get_ability($name) === null) {
                return false;
            }
        }
        return true;
    }

    public static function endpoint(): string
    {
        return rest_url(self::REST_NAMESPACE . '/' . self::REST_ROUTE);
    }

    public function create(McpAdapter $adapter): void
    {
        if (!self::adapterAvailable() || !self::abilitiesAvailable()) {
            return;
        }

        // Registration must not depend on the current user: REST authentication can
        // happen later. Re-evaluate authorization on every request and tool call.
        $result = $adapter->create_server(
            self::ID,
            self::REST_NAMESPACE,
            self::REST_ROUTE,
            'Afara',
            'Administrator-only, read-only WordPress source inspection.',
            AFARA_VERSION,
            [HttpTransport::class],
            null, // Official null handlers avoid logging source or credentials.
            null,
            self::ABILITIES,
            [],
            [],
            [$this, 'authorize']
        );
        if (is_wp_error($result)) {
            // Expose a failure hook without persisting exception details or secrets.
            do_action('afara_mcp_registration_failed', $result->get_error_code());
        }
    }

    public function authorize(): bool
    {
        $reason = $this->denialReason();
        if ($reason === null) {
            return true;
        }
        if (!self::$refusalRecorded) {
            self::$refusalRecorded = true;
            ActivityLog::refused($reason);
        }
        return false;
    }

    private function denialReason(): ?string
    {
        if (!is_ssl()) {
            return 'afara_https_required';
        }
        if (!is_user_logged_in()) {
            return 'afara_not_signed_in';
        }
        return $this->gate->readDenialReason();
    }
}
