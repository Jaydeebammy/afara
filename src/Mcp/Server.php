<?php
declare(strict_types=1);

namespace Afara\Mcp;

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

    public function __construct(private readonly PermissionGate $gate) {}

    public function register(): void
    {
        add_action('mcp_adapter_init', [$this, 'create']);
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
        return is_ssl() && is_user_logged_in() && $this->gate->canRead();
    }
}
