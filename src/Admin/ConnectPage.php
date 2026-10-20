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
                __('Afara’s abilities didn’t register. Check that WordPress is 6.9 or newer.', 'afara'),
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

    private static function when(?int $stamp): string
    {
        if ($stamp === null || $stamp <= 0) {
            return __('Never', 'afara');
        }
        return function_exists('wp_date') ? (string) wp_date('Y-m-d H:i', $stamp) : gmdate('Y-m-d H:i', $stamp) . ' UTC';
    }

    /** Connections list, revoke confirmation and the result of a revoke. */
    private function renderConnections(): void
    {
        $rows = Connections::all();
        $profile = admin_url('profile.php#application-passwords-section');
        // Display-only parameters; changing data needs the nonce-checked POST below.
        $result = isset($_GET['afara_revoked']) && is_string($_GET['afara_revoked']) ? $_GET['afara_revoked'] : '';
        $confirmUser = isset($_GET['revoke_user']) ? (int) $_GET['revoke_user'] : 0;
        $confirmUuid = isset($_GET['revoke']) && is_string($_GET['revoke']) ? strtolower($_GET['revoke']) : '';
        $confirm = null;
        foreach ($rows as $row) {
            if ($row['user_id'] === $confirmUser && hash_equals($row['uuid'], $confirmUuid) && $row['can_revoke']) {
                $confirm = $row;
            }
        }
        $notices = [
            'ok' => ['success', 'status', __('Connection revoked. The agent using it is refused from its next request.', 'afara')],
            'failed' => ['error', 'alert', __('That connection couldn’t be revoked. Try again, or remove it from the user’s profile.', 'afara')],
            'missing' => ['warning', 'alert', __('That connection no longer exists, or you can’t edit that account.', 'afara')],
        ];
        $base = admin_url('admin.php?page=afara-connect');
        ?>
          <h2 id="afara-connections"><?php esc_html_e('Connections', 'afara'); ?></h2>
          <?php if (isset($notices[$result])) : [$type, $role, $message] = $notices[$result]; ?>
            <div id="afara-connections-notice" class="notice notice-<?php echo esc_attr($type); ?> inline afara-save-notice" role="<?php echo esc_attr($role); ?>" tabindex="-1"><p><strong><?php echo esc_html($message); ?></strong></p></div>
            <script>document.getElementById('afara-connections-notice')?.focus();</script>
          <?php endif; ?>
          <p><?php esc_html_e('Each connection is an administrator’s Application Password. Any of them can sign an agent in to Afara. Revoke one you don’t recognise or no longer use.', 'afara'); ?></p>

          <?php if ($confirm !== null) : ?>
            <div id="afara-revoke-confirm" class="afara-status afara-status--action-needed" role="region" aria-labelledby="afara-revoke-title" aria-describedby="afara-revoke-detail" tabindex="-1">
              <span class="dashicons dashicons-warning" aria-hidden="true"></span>
              <div>
                <p id="afara-revoke-title" class="afara-status__title"><strong><?php echo esc_html(sprintf(__('Revoke “%1$s” for %2$s?', 'afara'), $confirm['name'], $confirm['user_login'])); ?></strong></p>
                <p id="afara-revoke-detail" class="afara-status__detail"><?php echo esc_html(($confirm['type'] ?? '') === 'oauth'
                    ? __('The app is signed out straight away and all its tokens stop working. It can ask for approval again later.', 'afara')
                    : __('Any agent using it is refused straight away. This can’t be undone, but you can create a new Application Password later.', 'afara')); ?></p>
                <form class="afara-status__action" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                  <input type="hidden" name="action" value="<?php echo esc_attr(Connections::ACTION); ?>">
                  <input type="hidden" name="user_id" value="<?php echo esc_attr((string) $confirm['user_id']); ?>">
                  <input type="hidden" name="uuid" value="<?php echo esc_attr($confirm['uuid']); ?>">
                  <?php wp_nonce_field(Connections::nonceAction($confirm['user_id'], $confirm['uuid'])); ?>
                  <button type="submit" class="button button-primary afara-button-danger"><?php esc_html_e('Revoke connection', 'afara'); ?></button>
                  <a class="button button-secondary" href="<?php echo esc_url($base . '#afara-connections'); ?>"><?php esc_html_e('Cancel', 'afara'); ?></a>
                </form>
              </div>
            </div>
            <script>document.getElementById('afara-revoke-confirm')?.focus();</script>
          <?php endif; ?>

          <table class="widefat striped afara-connections">
            <caption class="screen-reader-text"><?php esc_html_e('Connections that can sign in to Afara, most recently used first', 'afara'); ?></caption>
            <thead><tr>
              <th scope="col"><?php esc_html_e('Connection', 'afara'); ?></th>
              <th scope="col"><?php esc_html_e('Account', 'afara'); ?></th>
              <th scope="col"><?php esc_html_e('Created', 'afara'); ?></th>
              <th scope="col"><?php esc_html_e('Last used anywhere', 'afara'); ?></th>
              <th scope="col"><?php esc_html_e('Last Afara activity', 'afara'); ?></th>
              <th scope="col"><span class="screen-reader-text"><?php esc_html_e('Actions', 'afara'); ?></span></th>
            </tr></thead>
            <tbody>
            <?php if ($rows === []) : ?>
              <tr><td colspan="6"><?php esc_html_e('No connections yet. Create an Application Password to connect your first agent.', 'afara'); ?> <a href="<?php echo esc_url($profile); ?>"><?php esc_html_e('Create one in your profile', 'afara'); ?></a></td></tr>
            <?php else : ?>
              <?php foreach ($rows as $row) : $afara = $row['afara']; ?>
              <tr<?php echo $confirm !== null && $confirm['uuid'] === $row['uuid'] ? ' class="afara-connections__row--confirming"' : ''; ?>>
                <th scope="row"><?php echo esc_html($row['name'] !== '' ? $row['name'] : __('(unnamed)', 'afara')); ?><br><span class="description"><?php echo esc_html(($row['type'] ?? '') === 'oauth' ? __('OAuth app', 'afara') : __('Application Password', 'afara')); ?></span></th>
                <td><?php echo esc_html($row['user_login']); ?><?php echo $row['user_id'] === get_current_user_id() ? ' <span class="afara-badge">' . esc_html__('You', 'afara') . '</span>' : ''; ?></td>
                <td><?php echo esc_html(self::when($row['created'])); ?></td>
                <td><?php echo esc_html(self::when($row['last_used'])); ?></td>
                <td><?php
                    if ($afara === null) {
                        echo '<span class="description">' . esc_html__('None recorded', 'afara') . '</span>';
                    } else {
                        $labels = ['success' => __('Allowed', 'afara'), 'refused' => __('Refused', 'afara'), 'error' => __('Error', 'afara')];
                        $stamp = strtotime((string) $afara['time']) ?: null;
                        echo esc_html(self::when($stamp)) . ' · <span class="afara-result afara-result--' . esc_attr((string) $afara['result']) . '">' . esc_html($labels[$afara['result']] ?? (string) $afara['result']) . '</span>';
                    }
                ?></td>
                <td><?php if ($row['can_revoke']) : ?>
                  <a class="button button-secondary" href="<?php echo esc_url(add_query_arg(['revoke' => $row['uuid'], 'revoke_user' => $row['user_id']], $base) . '#afara-revoke-confirm'); ?>"><?php esc_html_e('Revoke', 'afara'); ?><span class="screen-reader-text"> <?php echo esc_html($row['name']); ?></span></a>
                <?php else : ?>
                  <span class="description"><?php esc_html_e('Only that user can revoke', 'afara'); ?></span>
                <?php endif; ?></td>
              </tr>
              <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
          </table>
          <p><a href="<?php echo esc_url($profile); ?>"><?php esc_html_e('Create a new connection in your profile', 'afara'); ?></a></p>
        <?php
    }

    /** OAuth: one URL to paste into apps that sign in with OAuth. */
    private function renderOAuth(string $endpoint): void
    {
        $reason = \Afara\OAuth\Config::unavailableReason();
        ?>
          <div class="afara-card" id="afara-oauth">
            <h2><?php esc_html_e('Connect with OAuth', 'afara'); ?></h2>
            <?php if ($reason === null) : ?>
              <p><?php esc_html_e('For apps that sign in with OAuth (for example, a custom connector in Claude). Paste this server URL into the app. It will open an approval page here; nothing is shared until you click Allow.', 'afara'); ?></p>
              <p><code><?php echo esc_html($endpoint); ?></code></p>
              <p class="description"><?php esc_html_e('Read-only access. Tokens last an hour and renew automatically; revoke the app below to sign it out.', 'afara'); ?></p>
              <p><?php esc_html_e('Agents without a browser (terminal tools, chat bots) can use device sign-in: they show a short code, and you enter it here:', 'afara'); ?> <a href="<?php echo esc_url(\Afara\OAuth\DeviceFlow::verificationUri()); ?>"><?php esc_html_e('Device sign-in', 'afara'); ?></a></p>
            <?php else : ?>
              <p><?php echo esc_html(sprintf(__('Not available: %s.', 'afara'), \Afara\Admin\ActivityLogPage::reason($reason))); ?></p>
              <?php if (in_array($reason, ['oauth_disabled', 'afara_disabled', 'afara_domain_mismatch'], true)) : ?>
                <p><a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=afara')); ?>"><?php esc_html_e('Open Afara settings', 'afara'); ?></a></p>
              <?php elseif ($reason === 'oauth_needs_permalinks') : ?>
                <p><a class="button button-secondary" href="<?php echo esc_url(admin_url('options-permalink.php')); ?>"><?php esc_html_e('Open Permalink settings', 'afara'); ?></a></p>
              <?php endif; ?>
            <?php endif; ?>
          </div>
        <?php
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
          <?php Layout::navigation('afara-connect'); ?>
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
          <?php $this->renderConnections(); ?>
          <?php $this->renderOAuth($endpoint); ?>
          <div class="afara-card">
            <h2><?php esc_html_e('Connect over HTTPS', 'afara'); ?></h2>
            <p><?php esc_html_e('Install and activate the official WordPress MCP Adapter plugin, version 0.7.1 or newer. Afara requires WordPress 6.9+ and PHP 8.1+. It does not bundle or activate the adapter.', 'afara'); ?></p>
            <p><?php esc_html_e('MCP endpoint (HTTP transport; GET/SSE streaming is not supported):', 'afara'); ?></p>
            <p><code><?php echo esc_html($endpoint); ?></code></p>
            <p><?php esc_html_e('In Users → Profile, create a dedicated, revocable Application Password for an account with manage_options (normally an administrator). Configure your MCP client with this endpoint and HTTP Basic authentication using the WordPress username and Application Password. Always use HTTPS. Never use your normal account password or put credentials in a URL.', 'afara'); ?></p>
            <p><?php esc_html_e('For clients that launch an STDIO process, use the official @automattic/mcp-wordpress-remote bridge with these environment variables on your own machine. Store the password in your client’s secure credential settings; do not paste it into Afara or logs.', 'afara'); ?></p>
            <pre><code><?php echo esc_html('WP_API_URL=' . $endpoint . "\nWP_API_USERNAME=your-wordpress-username\nWP_API_PASSWORD=<application-password>"); ?></code></pre>
            <p><code>npx -y @automattic/mcp-wordpress-remote@latest</code></p>
            <p><?php esc_html_e('The client must initialize MCP and preserve negotiated protocol headers and any Mcp-Session-Id returned by the adapter. Discovery returns afara-site-context, afara-read-file, afara-list-directory, afara-elementor-document, afara-elementor-update-text and afara-elementor-update-image. Elementor edits are draft-only, require staging, write mode and safe mode off; OAuth tokens remain read-only. Revoking the Application Password, disabling Afara, or changing the domain lock denies subsequent requests. Read-only mode never enables file writes or PHP execution.', 'afara'); ?></p>
          </div>
        </div>
        <?php
    }
}
