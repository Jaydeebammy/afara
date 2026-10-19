<?php
declare(strict_types=1);

namespace Afara\Abilities;

use Afara\Security\PermissionGate;
use Afara\Audit\AuditCallback;

final class SiteContext
{
    public function __construct(private readonly PermissionGate $gate)
    {
    }

    public function register(): void
    {
        wp_register_ability('afara/site-context', [
            'label' => __('Site context', 'afara'),
            'description' => __('Read basic environment information about this WordPress installation.', 'afara'),
            'category' => 'afara',
            'input_schema' => ['type' => 'object', 'properties' => new \stdClass()],
            'output_schema' => [
                'type' => 'object',
                'properties' => [
                    'wordpress_version' => ['type' => 'string'],
                    'php_version' => ['type' => 'string'],
                    'theme' => ['type' => 'string'],
                ],
            ],
            'permission_callback' => fn (): bool => $this->gate->canRead(),
            'execute_callback' => AuditCallback::wrap(static function (): array {
                global $wp_version;
                $theme = wp_get_theme();
                return [
                    'wordpress_version' => (string) $wp_version,
                    'php_version' => PHP_VERSION,
                    'theme' => $theme->get('Name'),
                ];
            }, 'afara/site-context'),
            // Explicit custom-server registration; do not expose via default-server meta-tools.
            'meta' => ['show_in_rest' => false, 'mcp' => ['public' => false], 'annotations' => ['readonly' => true, 'destructive' => false]],
        ]);
    }
}
