<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Audit\ActivityLog;

final class ActivityLogPage
{
    public const VIEWS = ['all', 'refused', 'error'];

    public function register(): void
    {
        add_action('admin_menu', [$this, 'menu']);
    }

    public function menu(): void
    {
        add_submenu_page('afara', __('Activity log', 'afara'), __('Activity log', 'afara'), 'manage_options', 'afara-activity', [$this, 'render']);
    }

    /** Plain-language reason for a stored code. Unknown codes are shown as the code itself. */
    public static function reason(string $code): string
    {
        $reasons = [
            'afara_disabled' => __('Afara was switched off', 'afara'),
            'afara_domain_mismatch' => __('Domain lock didn’t match this site', 'afara'),
            'afara_https_required' => __('Request wasn’t sent over HTTPS', 'afara'),
            'afara_not_signed_in' => __('No sign-in details were sent', 'afara'),
            'afara_not_admin' => __('Account isn’t an administrator', 'afara'),
            'afara_sign_in_failed' => __('Sign-in failed', 'afara'),
            'incorrect_password' => __('Wrong or revoked Application Password', 'afara'),
            'invalid_username' => __('Unknown username', 'afara'),
            'invalid_email' => __('Unknown username', 'afara'),
            'application_passwords_disabled' => __('Application Passwords are turned off on this site', 'afara'),
            'application_passwords_disabled_for_user' => __('Application Passwords are turned off for this account', 'afara'),
            'afara_path_denied' => __('Path not allowed (protected, or outside themes and plugins)', 'afara'),
            'afara_file_limit' => __('File too large to read', 'afara'),
            'afara_offset_invalid' => __('Invalid read position', 'afara'),
            'afara_read_failed' => __('File couldn’t be read', 'afara'),
            'afara_binary_or_partial_utf8' => __('Not a text file', 'afara'),
            'afara_unexpected_error' => __('Unexpected error', 'afara'),
            'unknown' => __('Unrecognised reason', 'afara'),
        ];
        return $reasons[$code] ?? $code;
    }

    /** @return array{label: string, icon: string} */
    private static function result(string $result): array
    {
        return match ($result) {
            ActivityLog::RESULT_SUCCESS => ['label' => __('Allowed', 'afara'), 'icon' => 'yes-alt'],
            ActivityLog::RESULT_REFUSED => ['label' => __('Refused', 'afara'), 'icon' => 'shield'],
            default => ['label' => __('Error', 'afara'), 'icon' => 'warning'],
        };
    }

    private static function time(string $iso): string
    {
        $stamp = strtotime($iso);
        if ($stamp === false) {
            return $iso;
        }
        return function_exists('wp_date') ? (string) wp_date('Y-m-d H:i:s', $stamp) : gmdate('Y-m-d H:i:s', $stamp) . ' UTC';
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'));
        }
        // Display-only filter; it changes no data.
        $view = isset($_GET['view']) && is_string($_GET['view']) && in_array($_GET['view'], self::VIEWS, true) ? $_GET['view'] : 'all';
        $all = ActivityLog::recent();
        $entries = $view === 'all' ? $all : array_values(array_filter($all, static fn (array $e): bool => $e['result'] === $view));
        $refusedToday = ActivityLog::refusedSince(DAY_IN_SECONDS);
        $counts = ['all' => count($all), 'refused' => 0, 'error' => 0];
        foreach ($all as $entry) {
            if (isset($counts[$entry['result']])) {
                $counts[$entry['result']]++;
            }
        }
        $labels = ['all' => __('All', 'afara'), 'refused' => __('Refused', 'afara'), 'error' => __('Errors', 'afara')];
        $base = admin_url('admin.php?page=afara-activity');
        ?>
        <div class="wrap afara-admin">
            <h1><?php esc_html_e('Activity log', 'afara'); ?></h1>
            <p><?php esc_html_e('What agents did through Afara, and every request Afara refused. Inputs, file contents, passwords and IP addresses are never stored.', 'afara'); ?></p>

            <?php if ($refusedToday > 0) : ?>
            <div class="afara-status afara-status--action-needed" aria-labelledby="afara-log-summary">
                <span class="dashicons dashicons-shield" aria-hidden="true"></span>
                <div>
                    <p id="afara-log-summary" class="afara-status__title"><strong><?php
                        echo esc_html(sprintf(
                            /* translators: %d: number of refused requests */
                            _n('%d refused request in the last 24 hours', '%d refused requests in the last 24 hours', $refusedToday, 'afara'),
                            $refusedToday
                        ));
                    ?></strong></p>
                    <p class="afara-status__detail"><?php esc_html_e('Afara blocked these. If you don’t recognise one, revoke that Application Password in your profile.', 'afara'); ?></p>
                    <p class="afara-status__action"><a class="button button-secondary" href="<?php echo esc_url($base . '&view=refused'); ?>"><?php esc_html_e('Show refused requests', 'afara'); ?></a>
                    <a class="button button-secondary" href="<?php echo esc_url(admin_url('profile.php#application-passwords-section')); ?>"><?php esc_html_e('Manage Application Passwords', 'afara'); ?></a></p>
                </div>
            </div>
            <?php else : ?>
            <div class="afara-status afara-status--on" aria-labelledby="afara-log-summary">
                <span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
                <div><p id="afara-log-summary" class="afara-status__title"><strong><?php esc_html_e('No refused requests in the last 24 hours', 'afara'); ?></strong></p></div>
            </div>
            <?php endif; ?>

            <ul class="subsubsub">
                <?php foreach (self::VIEWS as $i => $key) : ?>
                <li><a href="<?php echo esc_url($key === 'all' ? $base : $base . '&view=' . $key); ?>"<?php echo $view === $key ? ' class="current" aria-current="page"' : ''; ?>><?php echo esc_html($labels[$key]); ?> <span class="count">(<?php echo esc_html((string) $counts[$key]); ?>)</span></a><?php echo $i < count(self::VIEWS) - 1 ? ' |' : ''; ?></li>
                <?php endforeach; ?>
            </ul>

            <table class="widefat striped afara-log">
                <caption class="screen-reader-text"><?php echo esc_html(sprintf(__('Activity log, %s entries, newest first', 'afara'), $labels[$view])); ?></caption>
                <thead><tr>
                    <th scope="col"><?php esc_html_e('Time', 'afara'); ?></th>
                    <th scope="col"><?php esc_html_e('Who', 'afara'); ?></th>
                    <th scope="col"><?php esc_html_e('Connection', 'afara'); ?></th>
                    <th scope="col"><?php esc_html_e('Request', 'afara'); ?></th>
                    <th scope="col"><?php esc_html_e('Result', 'afara'); ?></th>
                    <th scope="col"><?php esc_html_e('Reason', 'afara'); ?></th>
                </tr></thead>
                <tbody>
                <?php if ($entries === []) : ?>
                    <tr><td colspan="6"><?php echo $view === 'all' ? esc_html__('Nothing recorded yet.', 'afara') : esc_html__('Nothing in this view.', 'afara'); ?></td></tr>
                <?php else : ?>
                    <?php foreach ($entries as $entry) : $result = self::result($entry['result']); ?>
                        <tr class="afara-log__row afara-log__row--<?php echo esc_attr($entry['result']); ?>">
                            <td><?php echo esc_html(self::time($entry['time'])); ?></td>
                            <td><?php
                                if ($entry['user_id'] > 0) {
                                    echo esc_html($entry['user_login'] !== '' ? $entry['user_login'] : sprintf(__('User #%d', 'afara'), $entry['user_id']));
                                } else {
                                    echo '<span class="description">' . esc_html__('Not signed in', 'afara') . '</span>';
                                }
                            ?></td>
                            <td><?php echo $entry['connection'] !== '' ? esc_html($entry['connection']) : '<span class="description">—</span>'; ?></td>
                            <td><?php echo $entry['ability'] !== '' ? '<code>' . esc_html($entry['ability']) . '</code>' : esc_html__('Connect to Afara', 'afara'); ?></td>
                            <td><span class="afara-result afara-result--<?php echo esc_attr($entry['result']); ?>"><span class="dashicons dashicons-<?php echo esc_attr($result['icon']); ?>" aria-hidden="true"></span><?php echo esc_html($result['label']); ?></span><?php
                                if ($entry['count'] > 1) {
                                    echo ' <span class="afara-log__repeat">' . esc_html(sprintf(__('× %d', 'afara'), $entry['count'])) . '<span class="screen-reader-text"> ' . esc_html__('times, latest shown', 'afara') . '</span></span>';
                                }
                            ?></td>
                            <td><?php echo $entry['reason'] !== '' ? esc_html(self::reason($entry['reason'])) : '<span class="description">—</span>'; ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
            <p class="description"><?php echo esc_html(sprintf(__('Keeps the latest %d entries. Repeated identical refusals within 10 minutes are counted on one row.', 'afara'), ActivityLog::LIMIT)); ?></p>
        </div>
        <?php
    }
}
