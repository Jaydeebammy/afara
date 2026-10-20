<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Security\PermissionGate;

final class AbilitiesPage
{
    public function register(): void
    {
        add_action('admin_menu', [$this, 'menu']);
    }

    public function menu(): void
    {
        add_submenu_page('afara', __('Abilities', 'afara'), __('Abilities', 'afara'), 'manage_options', 'afara-abilities', [$this, 'render']);
    }

    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'));
        }
        $gate = new PermissionGate();
        $abilities = [
            ['afara/site-context', 'Read WordPress and PHP environment', 'Read', 'Administrator + domain lock', true],
            ['afara/execute-php', 'Run arbitrary PHP', 'Write', 'Not implemented', false],
            ['afara/read-file', 'Read limited theme and plugin source files', 'Read', 'Administrator + domain lock', true],
            ['afara/list-directory', 'List limited theme and plugin directories', 'Read', 'Administrator + domain lock', true],
            ['afara/elementor-document', 'Read an Elementor document and checksum', 'Read', 'Administrator + edit_post + domain lock', true],
            ['afara/elementor-update-text', 'Edit draft heading, text or button content', 'Write', 'Write mode + safe mode off + staging + edit_post', true],
            ['afara/elementor-update-image', 'Replace draft image with a media attachment', 'Write', 'Write mode + safe mode off + staging + edit_post', true],
            ['afara/write-file', 'Write a file', 'Write', 'Not implemented', false],
            ['afara/edit-file', 'Edit a file', 'Write', 'Not implemented', false],
            ['afara/delete-file', 'Delete a file', 'Write', 'Not implemented', false],
        ];
        ?>
        <div class="wrap afara-admin">
          <?php Layout::navigation('afara-abilities'); ?>
            <h1><?php esc_html_e('Abilities', 'afara'); ?></h1>
            <p><?php esc_html_e('Abilities available to AI agents. Planned abilities stay unavailable until securely implemented.', 'afara'); ?></p>
            <?php if (!$gate->canRead()) : ?>
                <div class="notice notice-warning inline"><p><?php esc_html_e('Afara is currently disabled for this account or the domain lock does not match.', 'afara'); ?></p></div>
            <?php endif; ?>
            <table class="widefat striped">
                <thead><tr><th scope="col"><?php esc_html_e('Status', 'afara'); ?></th><th scope="col"><?php esc_html_e('Ability', 'afara'); ?></th><th scope="col"><?php esc_html_e('Access', 'afara'); ?></th><th scope="col"><?php esc_html_e('Guard', 'afara'); ?></th></tr></thead>
                <tbody>
                <?php foreach ($abilities as [$name, $description, $access, $guard, $implemented]) : ?>
                    <tr>
                        <td><?php echo esc_html($implemented && ($access === 'Write' ? ($gate->canWrite() && !\Afara\Sandbox\SandboxState::isSafeMode() && in_array(wp_get_environment_type(), ['local', 'development', 'staging'], true)) : $gate->canRead()) ? 'Available locally' : ($implemented ? 'Disabled' : 'Planned')); ?></td>
                        <td><strong><code><?php echo esc_html($name); ?></code></strong><br><span class="description"><?php echo esc_html($description); ?></span></td>
                        <td><?php echo esc_html($access); ?></td>
                        <td><?php echo esc_html($guard); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <p class="description"><?php esc_html_e('The dedicated Afara MCP server exposes inspection and controlled Elementor draft editing abilities. Elementor must be activated for its tools to run. See Connect for adapter requirements, HTTPS authentication and connection setup. Availability here does not verify a remote connection.', 'afara'); ?></p>
        </div>
        <?php
    }
}
