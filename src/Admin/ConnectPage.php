<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Security\PermissionGate;

final class ConnectPage
{
    public function register(): void
    {
        add_action('admin_menu', [$this, 'menu']);
    }

    public function menu(): void
    {
        add_submenu_page('afara', __('Connect', 'afara'), __('Connect', 'afara'), 'manage_options', 'afara-connect', [$this, 'render']);
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'));
        }
        $gate = new PermissionGate();
        ?>
        <div class="wrap afara-admin">
          <h1><?php esc_html_e('Connect an AI agent', 'afara'); ?></h1>
          <div class="afara-card">
            <h2><?php esc_html_e('Connection status', 'afara'); ?></h2>
            <p><strong><?php echo esc_html($gate->canRead() ? __('Local permission gate ready', 'afara') : __('Disabled', 'afara')); ?></strong></p>
            <p><?php esc_html_e('MCP server integration is not yet enabled. Install and configure the official MCP Adapter separately after the integration milestone is validated.', 'afara'); ?></p>
            <p><a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=afara')); ?>"><?php esc_html_e('Configure settings', 'afara'); ?></a></p>
          </div>
          <div class="afara-card">
            <h2><?php esc_html_e('Application Passwords', 'afara'); ?></h2>
            <p><?php esc_html_e('WordPress manages Application Passwords under Users → Profile. Do not create or share a password for Afara until the MCP connection has been validated over HTTPS.', 'afara'); ?></p>
          </div>
        </div>
        <?php
    }
}
