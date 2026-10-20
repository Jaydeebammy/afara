<?php
declare(strict_types=1);

namespace Afara;

use Afara\Admin\SettingsPage;
use Afara\Admin\ConnectPage;
use Afara\Admin\Connections;
use Afara\Admin\QuietMode;
use Afara\Admin\AuthorizePage;
use Afara\Admin\DevicePage;
use Afara\OAuth\Http as OAuthHttp;
use Afara\Admin\AbilitiesPage;
use Afara\Admin\ActivityLogPage;
use Afara\Admin\SandboxPage;
use Afara\Sandbox\SandboxState;
use Afara\Security\PermissionGate;
use Afara\Abilities\SiteContext;
use Afara\Abilities\Elementor;
use Afara\Abilities\ReadFile;
use Afara\Abilities\ListDirectory;
use Afara\Mcp\Server;

final class Plugin
{
    public function boot(): void
    {
        (new Server(new PermissionGate()))->register();
        (new SettingsPage())->register();
        (new ConnectPage())->register();
        (new Connections())->register();
        (new QuietMode())->register();
        (new AuthorizePage())->register();
        (new DevicePage())->register();
        (new OAuthHttp())->register();
        (new AbilitiesPage())->register();
        (new ActivityLogPage())->register();
        (new SandboxPage())->register();
        add_action('admin_init', static function (): void {
            if (current_user_can('manage_options') && get_option('afara_sandbox_initialized', '0') !== '1') {
                if (SandboxState::prepare()) {
                    update_option('afara_sandbox_initialized', '1', false);
                }
            }
        });
        add_action('admin_enqueue_scripts', static function (string $hook): void {
            if (str_contains($hook, 'afara')) {
                wp_enqueue_style('afara-admin', plugins_url('assets/admin.css', AFARA_PLUGIN_FILE), [], AFARA_VERSION);
            }
        });

        add_action('wp_abilities_api_categories_init', static function (): void {
            if (function_exists('wp_register_ability_category')) {
                wp_register_ability_category('afara', [
                    'label' => __('Afara', 'afara'),
                    'description' => __('Afara site abilities.', 'afara'),
                ]);
            }
        });

        add_action('wp_abilities_api_init', static function (): void {
            if (!function_exists('wp_register_ability')) {
                return;
            }
            $gate = new PermissionGate();
            (new SiteContext($gate))->register();
            (new ReadFile($gate))->register();
            (new ListDirectory($gate))->register();
            (new Elementor($gate))->register();
        });
    }
}
