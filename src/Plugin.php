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
            (new SiteContext(new PermissionGate()))->register();
        });
    }
}
