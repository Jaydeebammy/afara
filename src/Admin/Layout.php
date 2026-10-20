<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Security\PermissionGate;

/** Shared WordPress-native navigation; no scripts or external assets required. */
final class Layout
{
    public static function navigation(string $active): void
    {
        $enabled = (new PermissionGate())->canRead();
        $tabs = ['afara' => 'Overview & settings', 'afara-connect' => 'Connect', 'afara-abilities' => 'Abilities',
            'afara-activity' => 'Activity', 'afara-sandbox' => 'Sandbox'];
        ?>
        <div class="afara-brandbar">
          <div class="afara-brand"><span class="afara-mark" aria-hidden="true">a</span><span>Afara<small><?php esc_html_e('Your WordPress agent workspace', 'afara'); ?></small></span></div>
          <span class="afara-connection-pill"><span class="dashicons <?php echo $enabled ? 'dashicons-yes-alt' : 'dashicons-lock'; ?>" aria-hidden="true"></span><?php echo esc_html($enabled ? __('Access enabled', 'afara') : __('Access paused', 'afara')); ?></span>
        </div>
        <nav class="afara-nav" aria-label="<?php echo esc_attr(__('Afara navigation', 'afara')); ?>">
          <?php foreach ($tabs as $slug => $label) : ?>
            <a href="<?php echo esc_attr('admin.php?page=' . $slug); ?>" <?php if ($slug === $active) : ?>aria-current="page"<?php endif; ?>><?php echo esc_html__($label, 'afara'); ?></a>
          <?php endforeach; ?>
        </nav>
        <?php
    }
}
