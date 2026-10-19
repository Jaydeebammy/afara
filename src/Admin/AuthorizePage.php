<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\OAuth\AuthorizationServer;
use Afara\OAuth\Clients;
use Afara\OAuth\Config;

/**
 * The OAuth consent screen (authorization endpoint).
 *
 * Lives in wp-admin, so WordPress handles sign-in and sends the browser back
 * here afterwards. Only administrators can approve. Redirects back to the app
 * happen before any output; the app's return address must match exactly what
 * it registered, or Afara shows the problem here instead of redirecting.
 */
final class AuthorizePage
{
    public function register(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_menu', [$this, 'hideFromMenu'], 999);
    }

    public function menu(): void
    {
        $hook = add_submenu_page('afara', __('Approve app', 'afara'), __('Approve app', 'afara'), 'manage_options', Config::AUTHORIZE_PAGE, [$this, 'render']);
        if (is_string($hook) && $hook !== '') {
            add_action('load-' . $hook, [$this, 'handle']);
        }
    }

    /** Reachable by URL only, never listed in the menu. */
    public function hideFromMenu(): void
    {
        remove_submenu_page('afara', Config::AUTHORIZE_PAGE);
    }

    public static function nonceAction(array $params): string
    {
        return 'afara_oauth_consent|' . $params['client_id'] . '|' . $params['code_challenge'];
    }

    /** Runs before output: answer the form, or bounce protocol errors back to the app. */
    public function handle(): void
    {
        if (!current_user_can('manage_options') || !Config::available()) {
            return;
        }
        $isPost = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST';
        $input = wp_unslash($isPost ? $_POST : $_GET);
        $check = AuthorizationServer::checkAuthorizeRequest(is_array($input) ? $input : []);
        if (!$check['ok']) {
            if ($check['redirect'] !== null) {
                $this->leave($check['redirect']);
            }
            return; // Untrusted client or return address: render() explains, no redirect.
        }
        if (!$isPost) {
            return;
        }
        check_admin_referer(self::nonceAction($check['params']));
        $decision = isset($_POST['afara_decision']) && is_string($_POST['afara_decision']) ? $_POST['afara_decision'] : '';
        $this->leave($decision === 'allow'
            ? AuthorizationServer::approve($check['params'], (int) get_current_user_id())
            : AuthorizationServer::deny($check['params']));
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Only administrators can approve apps for Afara.', 'afara'), '', ['response' => 403]);
        }
        echo '<div class="wrap afara-admin">';
        echo '<h1>' . esc_html__('Connect an app to Afara', 'afara') . '</h1>';
        $reason = Config::unavailableReason();
        if ($reason !== null) {
            $this->problem(__('OAuth sign-in isn’t available on this site right now', 'afara'), ActivityLogPage::reason($reason), true);
            echo '</div>';
            return;
        }
        $input = wp_unslash($_GET);
        $check = AuthorizationServer::checkAuthorizeRequest(is_array($input) ? $input : []);
        if (!$check['ok']) {
            $this->problem(__('Afara can’t continue with this request', 'afara'), $check['message'], false);
            echo '</div>';
            return;
        }
        $client = $check['client'];
        $params = $check['params'];
        $host = (string) wp_parse_url($params['redirect_uri'], PHP_URL_HOST);
        $user = wp_get_current_user();
        ?>
          <div class="afara-card afara-consent">
            <h2 id="afara-consent-title"><?php echo esc_html(sprintf(__('“%s” wants to read this site through Afara', 'afara'), (string) $client['client_name'])); ?></h2>
            <p class="description"><?php esc_html_e('The app chose this name itself. Afara can’t verify it, so check the details below.', 'afara'); ?></p>

            <?php if (Clients::localhostOnly($client)) : ?>
            <div class="afara-status afara-status--action-needed" role="note">
              <span class="dashicons dashicons-warning" aria-hidden="true"></span>
              <div>
                <p class="afara-status__title"><strong><?php esc_html_e('This app returns to your own computer (localhost)', 'afara'); ?></strong></p>
                <p class="afara-status__detail"><?php esc_html_e('Any program on your computer could use this name. Only allow it if you started this connection yourself just now.', 'afara'); ?></p>
              </div>
            </div>
            <?php endif; ?>

            <dl class="afara-consent__facts">
              <dt><?php esc_html_e('You’ll be sent back to', 'afara'); ?></dt>
              <dd><strong><?php echo esc_html($host); ?></strong><br><code><?php echo esc_html($params['redirect_uri']); ?></code></dd>
              <dt><?php esc_html_e('It will be able to', 'afara'); ?></dt>
              <dd><?php esc_html_e('Read site details, and theme and plugin source files. It can’t change anything.', 'afara'); ?></dd>
              <dt><?php esc_html_e('It will act as', 'afara'); ?></dt>
              <dd><?php echo esc_html((string) $user->user_login); ?> <span class="description"><?php esc_html_e('(you, an administrator)', 'afara'); ?></span></dd>
              <dt><?php esc_html_e('For how long', 'afara'); ?></dt>
              <dd><?php esc_html_e('Until you revoke it in Afara → Connect. Its access key renews every hour; turning Afara off stops it straight away.', 'afara'); ?></dd>
            </dl>

            <form method="post" action="<?php echo esc_url(add_query_arg('page', Config::AUTHORIZE_PAGE, admin_url('admin.php'))); ?>" aria-labelledby="afara-consent-title">
              <?php foreach (['client_id', 'redirect_uri', 'code_challenge', 'state', 'scope', 'resource'] as $field) : ?>
                <input type="hidden" name="<?php echo esc_attr($field); ?>" value="<?php echo esc_attr($params[$field]); ?>">
              <?php endforeach; ?>
              <input type="hidden" name="response_type" value="code">
              <input type="hidden" name="code_challenge_method" value="S256">
              <?php wp_nonce_field(self::nonceAction($params)); ?>
              <p class="afara-consent__actions">
                <button type="submit" name="afara_decision" value="allow" class="button button-primary"><?php esc_html_e('Allow', 'afara'); ?></button>
                <button type="submit" name="afara_decision" value="deny" class="button button-secondary"><?php esc_html_e('Deny', 'afara'); ?></button>
              </p>
            </form>
          </div>
        </div>
        <?php
    }

    private function problem(string $title, string $detail, bool $settingsLink): void
    {
        ?>
          <div class="afara-status afara-status--action-needed" role="alert">
            <span class="dashicons dashicons-warning" aria-hidden="true"></span>
            <div>
              <p class="afara-status__title"><strong><?php echo esc_html($title); ?></strong></p>
              <p class="afara-status__detail"><?php echo esc_html($detail); ?></p>
              <?php if ($settingsLink) : ?>
                <p class="afara-status__action"><a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=afara')); ?>"><?php esc_html_e('Open Afara settings', 'afara'); ?></a></p>
              <?php endif; ?>
            </div>
          </div>
        <?php
    }

    /** The URL has been checked against the app's registered return address. */
    private function leave(string $url): void
    {
        wp_redirect($url); // phpcs:ignore WordPress.Security.SafeRedirect -- exact match to a registered redirect_uri.
        exit;
    }
}
