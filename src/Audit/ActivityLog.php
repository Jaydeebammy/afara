<?php
declare(strict_types=1);

namespace Afara\Audit;

/**
 * Bounded audit trail for Afara ability executions.
 *
 * Never records arguments, response content, passwords, or file paths.
 * Intended for staging. A dedicated database table is preferable for
 * high-volume sites, where concurrent option updates can lose entries.
 */
final class ActivityLog
{
    public const OPTION = 'afara_activity_log';
    public const LIMIT = 200;

    public static function record(string $ability, bool $success): void
    {
        $allowed = ['afara/site-context', 'afara/read-file', 'afara/list-directory'];
        if (!in_array($ability, $allowed, true)) {
            return;
        }
        $entries = get_option(self::OPTION, []);
        if (!is_array($entries)) {
            $entries = [];
        }
        $entries[] = [
            'time' => gmdate('Y-m-d\TH:i:s\Z'),
            'user_id' => get_current_user_id(),
            'ability' => $ability,
            'result' => $success ? 'success' : 'error',
        ];
        update_option(self::OPTION, array_slice($entries, -self::LIMIT), false);
    }

    /** @return array<int, array<string, mixed>> */
    public static function recent(): array
    {
        $entries = get_option(self::OPTION, []);
        return is_array($entries) ? array_reverse(array_slice($entries, -self::LIMIT)) : [];
    }
}
