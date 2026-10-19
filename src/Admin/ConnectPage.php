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

    /**
     * One status, in words, with what to do next. Uses the same panel styles as Settings.
     *
     * @return array{state: string, icon: string, title: string, detail: string, action: ?array{label: string, url: string}}
     */
    private function status(PermissionGate $gate, string $endpoint): array
    {
        $settings = ['label' => __('Open Afara settings', 'afara'), 'url' => admin_url('admin.php?page=afara')];
        $blocked = static fn (string $title, string $detail, ?array $action): array => [
            'state' => 'action-needed', 'icon' => 'warning', 'title' => $title, 'detail' => $detail, 'action' => $action,
        ];
        if (!Server::adapterAvailable()) {
            return $blocked(
                __('Official MCP Adapter missing, inactive or older than 0.7.1', 'afara'),
                __('Install and activate the MCP Adapter plugin (0.7.1 or newer). Agents can’t connect without it.', 'afara'),
                ['label' => __('Go to Plugins', 'afara'), 'url' => admin_url('plugins.php')]
            );
        }
        if (!Server::abilitiesAvailable()) {
            return $blocked(
                __('Required WordPress abilities unavailable', 'afara'),
                __('Afara’s read-only abilities didn’t register. Check that WordPress is 6.9 or newer.', 'afara'),
                null
            );
        }
        if (!$gate->isEnabled()) {
            return [
                'state' => 'off', 'icon' => 'lock',
                'title' => __('Disabled — enable Afara in Settings', 'afara'),
                'detail' => __('No agent can connect while Afara is off.', 'afara'),
                'action' => $settings,
            ];
        }
        if (!$gate->isDomainMatched()) {
            return $blocked(
                __('Blocked — domain lock does not match', 'afara'),
                __('The domain lock in Settings must match this site’s address exactly.', 'afara'),
                $settings
            );
        }
        if (!is_ssl() || wp_parse_url($endpoint, PHP_URL_SCHEME) !== 'https') {
            return $blocked(
                __('Blocked — HTTPS is required', 'afara'),
                __('Serve this site over HTTPS. Afara refuses every request over plain HTTP.', 'afara'),
                null
            );
        }
        if (!wp_is_application_passwords_available_for_user(wp_get_current_user())) {
            return $blocked(
                __('Application Passwords unavailable for this account or site', 'afara'),
                __('A security plugin or the site configuration may have turned them off.', 'afara'),
                ['label' => __('Open your profile', 'afara'), 'url' => admin_url('profile.php#application-passwords-section')]
            );
        }
        return [
            'state' => 'ready', 'icon' => 'yes',
            'title' => __('Configured locally — remote connection not verified', 'afara'),
            'detail' => __('Everything on this site is ready. Afara can’t see whether an agent has connected yet: after your first request, check the Activity log.', 'afara'),
            'action' => ['label' => __('Open Activity log', 'afara'), 'url' => admin_url('admin.php?page=afara-activity')],
        ];
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
          <h2><?php esc_html_e('Connection status', 'afara'); ?></h2>
          <div id="afara-status" class="afara-status afara-status--<?php echo esc_attr($status['state']); ?>" aria-labelledby="afara-status-title" aria-describedby="afara-status-detail">
            <span class="dashicons dashicons-<?php echo esc_attr($status['icon']); ?>" aria-hidden="true"></span>
            <div>
              <p id="afara-status-title" class="afara-status__title"><span class="screen-reader-text"><?php esc_html_e('Status:', 'afara'); ?> </span><strong><?php echo esc_html($status['title']); ?></strong></p>
              <p id="afara-status-detail" class="afara-status__detail"><?php echo esc_html($status['detail']); ?></p>
              <?php if ($status['action'] !== null) : ?>
                <p class="afara-status__action"><a class="button button-secondary" href="<?php echo esc_url($status['action']['url']); ?>"><?php echo esc_html($status['action']['label']); ?></a></p>
              <?php endif; ?>
            </div>
          </div>
          <p class="description"><?php esc_html_e('This page checks local prerequisites only. It does not verify a remote connection. Use a disposable staging site.', 'afara'); ?></p>
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
