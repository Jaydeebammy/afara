<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Sandbox\SandboxState;

final class SandboxPage
{
    public function register(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_post_afara_sandbox_mode', [$this, 'changeMode']);
    }

    public function menu(): void
    {
        add_submenu_page('afara', __('Sandbox', 'afara'), __('Sandbox', 'afara'), 'manage_options', 'afara-sandbox', [$this, 'render']);
    }

    public function changeMode(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'), '', ['response' => 403]);
        }
        check_admin_referer('afara_sandbox_mode');
        $mode = isset($_POST['afara_mode']) && is_string($_POST['afara_mode'])
            ? sanitize_key(wp_unslash($_POST['afara_mode'])) : '';
        if ($mode === 'enter') {
            SandboxState::enterSafeMode();
        } elseif ($mode === 'leave') {
            SandboxState::leaveSafeMode();
        } else {
            wp_die(esc_html__('Invalid mode.', 'afara'), '', ['response' => 400]);
        }
        wp_safe_redirect(admin_url('admin.php?page=afara-sandbox&updated=1'));
        exit;
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'), '', ['response' => 403]);
        }
        $safe = SandboxState::isSafeMode();
        $exists = is_dir(SandboxState::path()) && !is_link(SandboxState::path());
        ?>
        <div class="wrap afara-admin">
          <?php Layout::navigation('afara-sandbox'); ?>
          <h1><?php esc_html_e('Sandbox', 'afara'); ?></h1>
          <p><?php esc_html_e('Inspect the current sandbox state. Agent-written PHP loading is not implemented or enabled.', 'afara'); ?></p>
          <div class="afara-card">
            <h2><?php esc_html_e('Safe mode', 'afara'); ?></h2>
            <p><strong><?php echo esc_html($safe ? __('On', 'afara') : __('Off (executor remains disabled)', 'afara')); ?></strong></p>
            <p><?php esc_html_e('Safe mode is on by default and blocks Elementor edits. Leaving it allows draft edits only when Afara write mode and staging/development requirements also pass. This switch does not permit PHP execution or file writes. Future releases will require a separate reviewed execution gate.', 'afara'); ?></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
              <input type="hidden" name="action" value="afara_sandbox_mode">
              <input type="hidden" name="afara_mode" value="<?php echo esc_attr($safe ? 'leave' : 'enter'); ?>">
              <?php wp_nonce_field('afara_sandbox_mode'); ?>
              <?php submit_button($safe ? __('Leave safe mode (no executor)', 'afara') : __('Enter safe mode', 'afara'), 'secondary', 'submit', false); ?>
            </form>
          </div>
          <div class="afara-card">
            <h2><?php esc_html_e('Sandbox directory', 'afara'); ?></h2>
            <p><code><?php echo esc_html(SandboxState::path()); ?></code></p>
            <p><?php echo esc_html($exists ? __('Directory exists', 'afara') : __('Directory not prepared', 'afara')); ?></p>
            <p><?php esc_html_e('This directory is inert: Afara does not load executable files from it. HTTP access protection must be verified for the chosen web server before any future executor is enabled.', 'afara'); ?></p>
          </div>
        </div>
        <?php
    }
}
