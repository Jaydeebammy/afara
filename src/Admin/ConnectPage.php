<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Security\PermissionGate;
use Afara\Mcp\Server;

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

    private function status(PermissionGate $gate, string $endpoint): string
    {
        if (!Server::adapterAvailable()) {
            return __('Official MCP Adapter missing, inactive or older than 0.7.1', 'afara');
        }
        if (!Server::abilitiesAvailable()) {
            return __('Required WordPress abilities unavailable', 'afara');
        }
        if (!$gate->isEnabled()) {
            return __('Disabled — enable Afara in Settings', 'afara');
        }
        if (!$gate->isDomainMatched()) {
            return __('Blocked — domain lock does not match', 'afara');
        }
        if (!is_ssl() || wp_parse_url($endpoint, PHP_URL_SCHEME) !== 'https') {
            return __('Blocked — HTTPS is required', 'afara');
        }
        if (!wp_is_application_passwords_available_for_user(wp_get_current_user())) {
            return __('Application Passwords unavailable for this account or site', 'afara');
        }
        return __('Configured locally — remote connection not verified', 'afara');
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'));
        }
        $gate = new PermissionGate();
        $endpoint = Server::endpoint();
        $status = $this->status($gate, $endpoint);
        ?>
        <div class="wrap afara-admin">
          <h1><?php esc_html_e('Connect an AI agent', 'afara'); ?></h1>
          <div class="afara-card">
            <h2><?php esc_html_e('Connection status', 'afara'); ?></h2>
            <p><strong><?php echo esc_html($status); ?></strong></p>
            <p><?php esc_html_e('This page checks local prerequisites only. It does not verify a remote connection. Use a disposable staging site, enable Afara, and set the exact site hostname in Settings.', 'afara'); ?></p>
            <p><a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=afara')); ?>"><?php esc_html_e('Configure settings', 'afara'); ?></a></p>
          </div>
          <div class="afara-card">
            <h2><?php esc_html_e('Connect over HTTPS', 'afara'); ?></h2>
            <p><?php esc_html_e('Install and activate the official WordPress MCP Adapter plugin, version 0.7.1 or newer. Afara requires WordPress 6.9+ and PHP 8.1+. It does not bundle or activate the adapter.', 'afara'); ?></p>
            <p><?php esc_html_e('MCP endpoint (HTTP transport; GET/SSE streaming is not supported):', 'afara'); ?></p>
            <p><code><?php echo esc_html($endpoint); ?></code></p>
            <p><?php esc_html_e('In Users → Profile, create a dedicated, revocable Application Password for an account with manage_options (normally an administrator). Configure your MCP client with this endpoint and HTTP Basic authentication using the WordPress username and Application Password. Always use HTTPS. Never use your normal account password or put credentials in a URL.', 'afara'); ?></p>
            <p><?php esc_html_e('For clients that launch an STDIO process, use the official @automattic/mcp-wordpress-remote bridge with these environment variables on your own machine. Store the password in your client’s secure credential settings; do not paste it into Afara or logs.', 'afara'); ?></p>
            <pre><code><?php echo esc_html('WP_API_URL=' . $endpoint . "\nWP_API_USERNAME=your-wordpress-username\nWP_API_PASSWORD=<application-password>"); ?></code></pre>
            <p><code>npx -y @automattic/mcp-wordpress-remote@latest</code></p>
            <p><?php esc_html_e('The client must initialize MCP and preserve negotiated protocol headers and any Mcp-Session-Id returned by the adapter. Discovery should return only afara-site-context, afara-read-file and afara-list-directory. Revoking the Application Password, disabling Afara, or changing the domain lock denies subsequent requests. Read-only mode never enables file writes or PHP execution.', 'afara'); ?></p>
          </div>
        </div>
        <?php
    }
}
