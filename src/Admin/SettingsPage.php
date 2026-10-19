<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Security\PermissionGate;

final class SettingsPage
{
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

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'));
        }
        $gate = new PermissionGate();
        $hostname = (string) wp_parse_url(home_url(), PHP_URL_HOST);
        ?>
        <div class="wrap afara-admin">
          <h1>Afara</h1>
          <p>An AI agent, working inside WordPress.</p>
          <div class="notice notice-warning inline"><p><strong>Development software:</strong> Do not enable on a production site. No remote MCP server or PHP execution is included in this foundation build.</p></div>
          <h2>Connection settings</h2>
          <p>Status: <strong><?php echo esc_html($gate->canRead() ? 'Enabled for administrators' : 'Disabled or domain mismatch'); ?></strong></p>
          <form method="post" action="options.php">
            <?php settings_fields('afara_settings'); ?>
            <table class="form-table" role="presentation">
              <tr><th scope="row">AI access</th><td><label><input type="checkbox" name="afara_enabled" value="1" <?php checked(get_option('afara_enabled', '0'), '1'); ?>> Enable Afara (off by default)</label></td></tr>
              <tr><th scope="row">Read-only mode</th><td><label><input type="checkbox" name="afara_read_only" value="1" <?php checked(get_option('afara_read_only', '1'), '1'); ?>> Restrict changes</label><p class="description">This option will govern future write abilities. Leave it enabled.</p></td></tr>
              <tr><th scope="row"><label for="afara_domain_lock">Domain lock</label></th><td><input id="afara_domain_lock" class="regular-text" type="text" name="afara_domain_lock" value="<?php echo esc_attr((string) get_option('afara_domain_lock', '')); ?>" placeholder="<?php echo esc_attr($hostname); ?>"><p class="description">Enter the site's hostname (without https:// or path). Changing domains disables access until updated.</p></td></tr>
            </table>
            <?php submit_button('Save settings'); ?>
          </form>
        </div>
        <?php
    }
}
