<?php
declare(strict_types=1);

namespace Afara\Admin;

use Afara\Audit\ActivityLog;

/**
 * The agents that can reach Afara: every Application Password belonging to an
 * administrator (only administrators pass Afara's permission gate).
 *
 * Revoking deletes that Application Password through WordPress core, so the
 * agent using it is refused on its very next request.
 */
final class Connections
{
    public const ACTION = 'afara_revoke_connection';
    public const MAX_USERS = 100;

    public function register(): void
    {
        add_action('admin_post_' . self::ACTION, [$this, 'handleRevoke']);
    }

    /**
     * @return list<array{user_id: int, user_login: string, uuid: string, name: string, created: int, last_used: ?int, afara: ?array<string, mixed>, can_revoke: bool}>
     */
    public static function all(): array
    {
        if (!class_exists(\WP_Application_Passwords::class) || !function_exists('get_users')) {
            return [];
        }
        $users = get_users(['capability' => 'manage_options', 'fields' => ['ID', 'user_login'], 'number' => self::MAX_USERS]);
        $rows = [];
        foreach ($users as $user) {
            $userId = (int) $user->ID;
            foreach (\WP_Application_Passwords::get_user_application_passwords($userId) as $item) {
                $uuid = (string) ($item['uuid'] ?? '');
                if ($uuid === '') {
                    continue;
                }
                // Only the fields shown below leave this method. The password hash never does.
                $rows[] = [
                    'user_id' => $userId,
                    'user_login' => (string) $user->user_login,
                    'uuid' => $uuid,
                    'name' => (string) ($item['name'] ?? ''),
                    'created' => (int) ($item['created'] ?? 0),
                    'last_used' => isset($item['last_used']) && $item['last_used'] !== null ? (int) $item['last_used'] : null,
                    'afara' => ActivityLog::lastForConnection($userId, $uuid),
                    'can_revoke' => current_user_can('edit_user', $userId),
                ];
            }
        }
        // Most recently used with Afara first, then most recently used anywhere, then newest.
        usort($rows, static function (array $a, array $b): int {
            $aa = $a['afara'] !== null ? (strtotime((string) $a['afara']['time']) ?: 0) : 0;
            $ba = $b['afara'] !== null ? (strtotime((string) $b['afara']['time']) ?: 0) : 0;
            return [$ba, $b['last_used'] ?? 0, $b['created']] <=> [$aa, $a['last_used'] ?? 0, $a['created']];
        });
        return $rows;
    }

    /** Find one connection by user and UUID, or null. */
    public static function find(int $userId, string $uuid): ?array
    {
        foreach (self::all() as $row) {
            if ($row['user_id'] === $userId && hash_equals($row['uuid'], $uuid)) {
                return $row;
            }
        }
        return null;
    }

    public static function nonceAction(int $userId, string $uuid): string
    {
        return self::ACTION . '_' . $userId . '_' . $uuid;
    }

    /** admin-post.php handler. POST only, nonce-checked, and the account must be editable by you. */
    public function handleRevoke(): void
    {
        $back = admin_url('admin.php?page=afara-connect');
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not permitted.', 'afara'), '', ['response' => 403]);
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            wp_safe_redirect($back);
            exit;
        }
        $userId = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
        $uuid = isset($_POST['uuid']) && is_string($_POST['uuid']) ? strtolower(sanitize_text_field(wp_unslash($_POST['uuid']))) : '';
        check_admin_referer(self::nonceAction($userId, $uuid));

        $row = self::find($userId, $uuid);
        if ($row === null || !$row['can_revoke']) {
            wp_safe_redirect(add_query_arg('afara_revoked', 'missing', $back));
            exit;
        }
        $deleted = \WP_Application_Passwords::delete_application_password($userId, $uuid);
        wp_safe_redirect(add_query_arg('afara_revoked', $deleted === true ? 'ok' : 'failed', $back));
        exit;
    }
}
