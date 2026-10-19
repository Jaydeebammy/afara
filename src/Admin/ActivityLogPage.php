<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Audit\ActivityLog;

final class ActivityLogPage
{
    public function register(): void
    {
        add_action('admin_menu', [$this, 'menu']);
    }

    public function menu(): void
    {
        add_submenu_page('afara', __('Activity log', 'afara'), __('Activity log', 'afara'), 'manage_options', 'afara-activity', [$this, 'render']);
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'));
        }
        ?>
        <div class="wrap afara-admin">
            <h1><?php esc_html_e('Activity log', 'afara'); ?></h1>
            <p><?php esc_html_e('Recent Afara read-only ability executions. Inputs, output data and credentials are never stored in this log.', 'afara'); ?></p>
            <div class="notice notice-info inline"><p><?php esc_html_e('This initial audit log records executed abilities only. Authentication denials, adapter discovery, and other MCP transport requests are not yet included.', 'afara'); ?></p></div>
            <table class="widefat striped">
                <thead><tr>
                    <th scope="col"><?php esc_html_e('Time (UTC)', 'afara'); ?></th>
                    <th scope="col"><?php esc_html_e('User ID', 'afara'); ?></th>
                    <th scope="col"><?php esc_html_e('Ability', 'afara'); ?></th>
                    <th scope="col"><?php esc_html_e('Result', 'afara'); ?></th>
                </tr></thead>
                <tbody>
                <?php $entries = ActivityLog::recent(); ?>
                <?php if (empty($entries)) : ?>
                    <tr><td colspan="4"><?php esc_html_e('No recorded ability executions yet.', 'afara'); ?></td></tr>
                <?php else : ?>
                    <?php foreach ($entries as $entry) : ?>
                        <tr>
                            <td><?php echo esc_html((string) ($entry['time'] ?? '')); ?></td>
                            <td><?php echo esc_html((string) ($entry['user_id'] ?? '')); ?></td>
                            <td><code><?php echo esc_html((string) ($entry['ability'] ?? '')); ?></code></td>
                            <td><?php echo esc_html((string) ($entry['result'] ?? '')); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }
}
