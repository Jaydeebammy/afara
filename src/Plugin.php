<?php
declare(strict_types=1);

namespace Afara;

use Afara\Admin\SettingsPage;
use Afara\Security\PermissionGate;
use Afara\Abilities\SiteContext;

final class Plugin
{
    public function boot(): void
    {
        (new SettingsPage())->register();

        add_action('wp_abilities_api_init', static function (): void {
            if (!function_exists('wp_register_ability')) {
                return;
            }
            if (function_exists('wp_register_ability_category')) {
                wp_register_ability_category('afara', [
                    'label' => __('Afara', 'afara'),
                    'description' => __('Afara site abilities.', 'afara'),
                ]);
            }
            (new SiteContext(new PermissionGate()))->register();
        });
    }
}
