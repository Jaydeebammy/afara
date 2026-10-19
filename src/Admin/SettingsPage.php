<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Security\PermissionGate;

final class SettingsPage
{
    public const STATE_ON = 'on';
    public const STATE_OFF = 'off';
    public const STATE_ACTION_NEEDED = 'action-needed';

    public function register(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_init', [$this, 'settings']);
    }

    public function menu(): void
    {
        add_menu_page('Afara', 'Afara', 'manage_options', 'afara', [$this, 'render'], 'dashicons-admin-generic', 81);
    }

    public function settings(): void
    {
        register_setting('afara_settings', 'afara_enabled', [
            'type' => 'string', 'default' => '0',
            'sanitize_callback' => static fn ($value): string => $value === '1' ? '1' : '0',
        ]);
        register_setting('afara_settings', 'afara_read_only', [
            'type' => 'string', 'default' => '1',
            'sanitize_callback' => static fn ($value): string => $value === '0' ? '0' : '1',
        ]);
        register_setting('afara_settings', 'afara_domain_lock', [
            'type' => 'string', 'default' => '',
            'sanitize_callback' => static function ($value): string {
                $value = strtolower(trim((string) $value));
                return preg_match('/^(?=.{1,253}$)[a-z0-9.-]+$/', $value) ? $value : '';
            },
        ]);
    }

    /**
     * The one status the page reports, in words, so colour is never the only signal.
     *
     * @return array{state: string, icon: string, title: string, detail: string}
     */
    public static function status(PermissionGate $gate, string $hostname): array
    {
        if (!$gate->isEnabled()) {
            return [
                'state' => self::STATE_OFF,
                'icon' => 'lock',
                'title' => __('Off — no agent can connect', 'afara'),
                'detail' => __('Tick “Enable Afara” below and save to turn it on.', 'afara'),
            ];
        }
        if (!$gate->isDomainMatched()) {
            $locked = (string) get_option('afara_domain_lock', '');
            $detail = $locked === ''
                ? sprintf(__('Enter this site’s address (%s) in Domain lock and save.', 'afara'), $hostname)
                : sprintf(__('Domain lock is %1$s but this site is %2$s. Update it and save.', 'afara'), $locked, $hostname);
            return [
                'state' => self::STATE_ACTION_NEEDED,
                'icon' => 'warning',
                'title' => __('Action needed — domain lock doesn’t match', 'afara'),
                'detail' => $detail,
            ];
        }
        return [
            'state' => self::STATE_ON,
            'icon' => 'yes-alt',
            'title' => __('On — agents can connect', 'afara'),
            'detail' => sprintf(__('Administrators can connect an AI agent. Locked to %s.', 'afara'), $hostname),
        ];
    }

    /**
     * Confirmation shown once after saving. It names the resulting state, not just "saved".
     *
     * @return array{type: string, role: string, message: string}
     */
    public static function savedNotice(string $state): array
    {
        return match ($state) {
            self::STATE_ON => [
                'type' => 'success', 'role' => 'status',
                'message' => __('Settings saved. Afara is on for administrators.', 'afara'),
            ],
            self::STATE_ACTION_NEEDED => [
                'type' => 'error', 'role' => 'alert',
                'message' => __('Settings saved, but Afara isn’t working: the domain lock doesn’t match this site.', 'afara'),
            ],
            default => [
                'type' => 'info', 'role' => 'status',
                'message' => __('Settings saved. Afara is off.', 'afara'),
            ],
        };
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'));
        }
        $gate = new PermissionGate();
        $hostname = (string) wp_parse_url(home_url(), PHP_URL_HOST);
        $status = self::status($gate, $hostname);
        // Display-only flag set by options.php after a successful save; it changes no data.
        $justSaved = isset($_GET['settings-updated']) && $_GET['settings-updated'] === 'true';
        $locked = (string) get_option('afara_domain_lock', '');
        ?>
        <div class="wrap afara-admin">
          <h1>Afara</h1>
          <?php if ($justSaved) : $notice = self::savedNotice($status['state']); ?>
            <div id="afara-save-notice" class="notice notice-<?php echo esc_attr($notice['type']); ?> is-dismissible afara-save-notice" role="<?php echo esc_attr($notice['role']); ?>" tabindex="-1">
              <p><strong><?php echo esc_html($notice['message']); ?></strong></p>
            </div>
          <?php endif; ?>
          <p>An AI agent, working inside WordPress.</p>
          <div class="notice notice-warning inline"><p><strong>Development software:</strong> Use a disposable staging site. The official MCP Adapter provides authenticated read-only access when configured. Arbitrary PHP execution and file mutations are unavailable.</p></div>
          <h2>Connection settings</h2>
          <div id="afara-status" class="afara-status afara-status--<?php echo esc_attr($status['state']); ?><?php echo $justSaved ? ' afara-status--changed' : ''; ?>" aria-labelledby="afara-status-title" aria-describedby="afara-status-detail">
            <span class="dashicons dashicons-<?php echo esc_attr($status['icon']); ?>" aria-hidden="true"></span>
            <div>
              <p id="afara-status-title" class="afara-status__title"><span class="screen-reader-text"><?php esc_html_e('Status:', 'afara'); ?> </span><strong><?php echo esc_html($status['title']); ?></strong></p>
              <p id="afara-status-detail" class="afara-status__detail"><?php echo esc_html($status['detail']); ?></p>
            </div>
          </div>
          <form method="post" action="options.php">
            <?php settings_fields('afara_settings'); ?>
            <table class="form-table" role="presentation">
              <tr><th scope="row">AI access</th><td><label><input type="hidden" name="afara_enabled" value="0"><input type="checkbox" name="afara_enabled" value="1" aria-describedby="afara-status-title" <?php checked(get_option('afara_enabled', '0'), '1'); ?>> Enable Afara (off by default)</label></td></tr>
              <tr><th scope="row">Read-only mode</th><td><label><input type="hidden" name="afara_read_only" value="0"><input type="checkbox" name="afara_read_only" value="1" <?php checked(get_option('afara_read_only', '1'), '1'); ?>> Restrict changes</label><p class="description">This option will govern future write abilities. Leave it enabled.</p></td></tr>
              <tr><th scope="row"><label for="afara_domain_lock">Domain lock</label></th><td><input id="afara_domain_lock" class="regular-text" type="text" name="afara_domain_lock" value="<?php echo esc_attr($locked !== '' ? $locked : $hostname); ?>" aria-describedby="afara-domain-lock-help"><p id="afara-domain-lock-help" class="description"><?php echo $locked === '' ? esc_html__('Pre-filled with this site’s address. Save to lock Afara to it.', 'afara') . ' ' : ''; ?>Enter the site's hostname (without https:// or path). Changing domains disables access until updated.</p></td></tr>
            </table>
            <?php submit_button('Save settings'); ?>
          </form>
          <?php if ($justSaved) : ?>
            <script>document.getElementById('afara-save-notice')?.focus();</script>
          <?php endif; ?>
        </div>
        <?php
    }
}
