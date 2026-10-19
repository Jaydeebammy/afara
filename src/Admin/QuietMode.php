<?php
declare(strict_types=1);

namespace Afara\Admin;

/**
 * Quiet mode: hide Afara's screens from administrators who aren't on a chosen list.
 *
 * It changes what those administrators see, never what they can do. A hidden
 * administrator can still open Afara's pages by URL, see it in WP-CLI and Site
 * Health, read its files, and connect an agent. It is a tidy dashboard for a
 * client's team, not a security control, and the client should be told Afara
 * is installed.
 *
 * Way back in: define('AFARA_QUIET_MODE_OFF', true); in wp-config.php.
 */
final class QuietMode
{
    public const OPTION_ENABLED = 'afara_quiet_mode';
    public const OPTION_USERS = 'afara_quiet_users';
    public const OFF_CONSTANT = 'AFARA_QUIET_MODE_OFF';
    private const MENU_SLUG = 'afara';

    public function register(): void
    {
        add_action('admin_menu', [$this, 'hideMenu'], PHP_INT_MAX);
        add_filter('all_plugins', [$this, 'hidePluginRow']);
        add_filter('site_transient_update_plugins', [$this, 'hideUpdateRow']);
    }

    /** True when wp-config.php has switched quiet mode off. */
    public static function forcedOff(): bool
    {
        return defined(self::OFF_CONSTANT) && constant(self::OFF_CONSTANT) === true;
    }

    /** @return list<int> */
    public static function listedUsers(): array
    {
        $ids = get_option(self::OPTION_USERS, []);
        if (!is_array($ids)) {
            return [];
        }
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static fn (int $id): bool => $id > 0)));
        sort($ids);
        return $ids;
    }

    /**
     * On, not overridden, and at least one listed account is still an administrator.
     * The last part means losing every listed account can't hide Afara from everyone.
     */
    public static function isActive(): bool
    {
        if (self::forcedOff() || get_option(self::OPTION_ENABLED, '0') !== '1') {
            return false;
        }
        foreach (self::listedUsers() as $id) {
            if (user_can($id, 'manage_options')) {
                return true;
            }
        }
        return false;
    }

    /** Should Afara be hidden from this user? Never for users on the list. */
    public static function hiddenFrom(int $userId): bool
    {
        return $userId > 0 && self::isActive() && !in_array($userId, self::listedUsers(), true);
    }

    /** One check for every Afara screen, menu or notice. */
    public static function visibleToCurrentUser(): bool
    {
        return !self::hiddenFrom((int) get_current_user_id());
    }

    public function hideMenu(): void
    {
        if (!self::visibleToCurrentUser()) {
            remove_menu_page(self::MENU_SLUG);
        }
    }

    /**
     * @param array<string, mixed> $plugins
     * @return array<string, mixed>
     */
    public function hidePluginRow($plugins)
    {
        if (is_array($plugins) && !self::visibleToCurrentUser()) {
            unset($plugins[self::basename()]);
        }
        return $plugins;
    }

    /** Only changes what this request reads; the stored update data is untouched. */
    public function hideUpdateRow($transient)
    {
        if (!is_object($transient) || self::visibleToCurrentUser()) {
            return $transient;
        }
        $copy = clone $transient;
        foreach (['response', 'no_update'] as $key) {
            if (isset($copy->{$key}) && is_array($copy->{$key})) {
                $list = $copy->{$key};
                unset($list[self::basename()]);
                $copy->{$key} = $list;
            }
        }
        return $copy;
    }

    /** Saving: keep only administrators, and always include the person saving. */
    public static function sanitizeUsers($value): array
    {
        $current = (int) get_current_user_id();
        if (self::hiddenFrom($current)) {
            return self::listedUsers(); // A hidden admin can't rewrite the list.
        }
        $ids = is_array($value) ? array_map('intval', $value) : [];
        if ($current > 0) {
            $ids[] = $current;
        }
        $ids = array_values(array_unique(array_filter($ids, static fn (int $id): bool => $id > 0 && user_can($id, 'manage_options'))));
        sort($ids);
        return $ids;
    }

    public static function sanitizeEnabled($value): string
    {
        if (self::hiddenFrom((int) get_current_user_id())) {
            return (string) get_option(self::OPTION_ENABLED, '0');
        }
        return $value === '1' ? '1' : '0';
    }

    private static function basename(): string
    {
        return function_exists('plugin_basename') && defined('AFARA_PLUGIN_FILE') ? plugin_basename(AFARA_PLUGIN_FILE) : 'afara/afara.php';
    }
}
