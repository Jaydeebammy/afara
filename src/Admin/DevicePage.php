<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\OAuth\Config;
use Afara\OAuth\DeviceFlow;

/**
 * Device sign-in page (RFC 8628 verification URI).
 *
 * An administrator types the code an agent shows, checks the app, then
 * allows or denies. A link that carries the code only fills in the box:
 * approval always takes a deliberate click, because "someone sent you a
 * code to approve" is the classic device-flow phishing attack.
 */
final class DevicePage
{
    public function register(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_menu', [$this, 'hideFromMenu'], 999);
    }

    public function menu(): void
    {
        $hook = add_submenu_page('afara', __('Device sign-in', 'afara'), __('Device sign-in', 'afara'), 'manage_options', DeviceFlow::PAGE, [$this, 'render']);
        if (is_string($hook) && $hook !== '') {
            add_action('load-' . $hook, [$this, 'handle']);
        }
    }

    public function hideFromMenu(): void
    {
        remove_submenu_page('afara', DeviceFlow::PAGE);
    }

    public static function nonceAction(string $userCode): string
    {
        return 'afara_device_decision|' . DeviceFlow::normalize($userCode);
    }

    /** POST: record the decision, then redirect (so a refresh can't resubmit). */
    public function handle(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !current_user_can('manage_options') || !Config::available()) {
            return;
        }
        $code = isset($_POST['user_code']) && is_string($_POST['user_code']) ? wp_unslash($_POST['user_code']) : '';
        check_admin_referer(self::nonceAction($code));
        $allow = isset($_POST['afara_decision']) && $_POST['afara_decision'] === 'allow';
        $ok = DeviceFlow::decide($code, $allow, (int) get_current_user_id());
        $result = !$ok ? 'expired' : ($allow ? 'approved' : 'denied');
        wp_safe_redirect(add_query_arg('afara_device', $result, DeviceFlow::verificationUri()));
        exit;
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Only administrators can approve devices for Afara.', 'afara'), '', ['response' => 403]);
        }
        echo '<div class="wrap afara-admin"><h1>' . esc_html__('Device sign-in', 'afara') . '</h1>';
        $reason = Config::unavailableReason();
        if ($reason !== null) {
            $this->panel('action-needed', 'warning', __('OAuth sign-in isn’t available on this site right now', 'afara'), ActivityLogPage::reason($reason), 'alert');
            echo '</div>';
            return;
        }
        // Display-only parameters.
        $result = isset($_GET['afara_device']) && is_string($_GET['afara_device']) ? $_GET['afara_device'] : '';
        $results = [
            'approved' => ['on', 'yes-alt', __('Device approved', 'afara'), __('Go back to your app. It will finish signing in within a few seconds.', 'afara'), 'status'],
            'denied' => ['off', 'dismiss', __('Device denied', 'afara'), __('The app was told no. Nothing was shared.', 'afara'), 'status'],
            'expired' => ['action-needed', 'warning', __('That code is no longer waiting', 'afara'), __('It expired, was already used, or was never issued. Start again from your app to get a new code.', 'afara'), 'alert'],
        ];
        if (isset($results[$result])) {
            [$state, $icon, $title, $detail, $role] = $results[$result];
            $this->panel($state, $icon, $title, $detail, $role, true);
            echo '</div>';
            return;
        }
        $typed = isset($_GET['user_code']) && is_string($_GET['user_code']) ? wp_unslash($_GET['user_code']) : '';
        $found = $typed !== '' ? DeviceFlow::lookup($typed) : null;
        if ($found === null) {
            if ($typed !== '') {
                $this->panel('action-needed', 'warning', __('Code not found', 'afara'), __('Check the code and try again. Codes expire after 10 minutes.', 'afara'), 'alert', true);
            }
            $this->codeForm($typed);
            echo '</div>';
            return;
        }
        $client = $found['client'];
        $user = wp_get_current_user();
        ?>
          <div class="afara-card afara-consent">
            <h2 id="afara-device-title"><?php echo esc_html(sprintf(__('“%s” wants to read this site through Afara', 'afara'), (string) $client['client_name'])); ?></h2>
            <p class="description"><?php esc_html_e('The app chose this name itself. Afara can’t verify it.', 'afara'); ?></p>
            <div class="afara-status afara-status--action-needed" role="note">
              <span class="dashicons dashicons-shield" aria-hidden="true"></span>
              <div>
                <p class="afara-status__title"><strong><?php esc_html_e('Only approve a code you started yourself, just now', 'afara'); ?></strong></p>
                <p class="afara-status__detail"><?php esc_html_e('If someone sent you this code or link, click Deny. Approving gives whoever holds the device read access to this site.', 'afara'); ?></p>
              </div>
            </div>
            <dl class="afara-consent__facts">
              <dt><?php esc_html_e('Code', 'afara'); ?></dt>
              <dd><strong class="afara-device-code"><?php echo esc_html(DeviceFlow::format($found['user_code'])); ?></strong> <span class="description"><?php esc_html_e('— check it matches your app', 'afara'); ?></span></dd>
              <dt><?php esc_html_e('It will be able to', 'afara'); ?></dt>
              <dd><?php esc_html_e('Read site details, and theme and plugin source files. It can’t change anything.', 'afara'); ?></dd>
              <dt><?php esc_html_e('It will act as', 'afara'); ?></dt>
              <dd><?php echo esc_html((string) $user->user_login); ?> <span class="description"><?php esc_html_e('(you, an administrator)', 'afara'); ?></span></dd>
              <dt><?php esc_html_e('For how long', 'afara'); ?></dt>
              <dd><?php esc_html_e('Until you revoke it in Afara → Connect.', 'afara'); ?></dd>
            </dl>
            <form method="post" action="<?php echo esc_url(DeviceFlow::verificationUri()); ?>" aria-labelledby="afara-device-title">
              <input type="hidden" name="user_code" value="<?php echo esc_attr($found['user_code']); ?>">
              <?php wp_nonce_field(self::nonceAction($found['user_code'])); ?>
              <p class="afara-consent__actions">
                <button type="submit" name="afara_decision" value="allow" class="button button-primary"><?php esc_html_e('Allow', 'afara'); ?></button>
                <button type="submit" name="afara_decision" value="deny" class="button button-secondary"><?php esc_html_e('Deny', 'afara'); ?></button>
              </p>
            </form>
          </div>
        </div>
        <?php
    }

    private function codeForm(string $typed): void
    {
        ?>
          <div class="afara-card afara-consent">
            <form method="get" action="<?php echo esc_url(admin_url('admin.php')); ?>">
              <input type="hidden" name="page" value="<?php echo esc_attr(DeviceFlow::PAGE); ?>">
              <p><label for="afara-user-code"><strong><?php esc_html_e('Enter the code your app is showing', 'afara'); ?></strong></label></p>
              <p><input id="afara-user-code" class="regular-text afara-device-code" type="text" name="user_code" value="<?php echo esc_attr($typed); ?>" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="BCDF-GHJK" aria-describedby="afara-user-code-help"></p>
              <p id="afara-user-code-help" class="description"><?php esc_html_e('Eight letters, like BCDF-GHJK. You’ll see the app’s details before anything is approved.', 'afara'); ?></p>
              <p><button type="submit" class="button button-primary"><?php esc_html_e('Continue', 'afara'); ?></button></p>
            </form>
          </div>
        <?php
    }

    private function panel(string $state, string $icon, string $title, string $detail, string $role, bool $focus = false): void
    {
        ?>
          <div id="afara-device-result" class="afara-status afara-status--<?php echo esc_attr($state); ?>" role="<?php echo esc_attr($role); ?>"<?php echo $focus ? ' tabindex="-1"' : ''; ?>>
            <span class="dashicons dashicons-<?php echo esc_attr($icon); ?>" aria-hidden="true"></span>
            <div>
              <p class="afara-status__title"><strong><?php echo esc_html($title); ?></strong></p>
              <p class="afara-status__detail"><?php echo esc_html($detail); ?></p>
            </div>
          </div>
          <?php if ($focus) : ?><script>document.getElementById('afara-device-result')?.focus();</script><?php endif; ?>
        <?php
    }
}
