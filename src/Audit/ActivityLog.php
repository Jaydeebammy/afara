<?php
declare(strict_types=1);

namespace Afara\Audit;

/**
 * Bounded audit trail for Afara: ability executions and refused MCP requests.
 *
 * Stores who (user ID and login), which connection (the Application Password's
 * label), what (ability name), the result and a short reason code. Never stores
 * arguments, response content, passwords, attempted usernames, file paths or IPs.
 *
 * Repeated identical refusals within COLLAPSE_SECONDS are counted on one entry,
 * so a burst of bad requests can't push real activity out of the log.
 *
 * Intended for staging. A dedicated database table is preferable for
 * high-volume sites, where concurrent option updates can lose entries.
 */
final class ActivityLog
{
    public const OPTION = 'afara_activity_log';
    public const LIMIT = 200;
    public const COLLAPSE_SECONDS = 600;

    public const RESULT_SUCCESS = 'success';
    public const RESULT_ERROR = 'error';
    public const RESULT_REFUSED = 'refused';

    /** Abilities that may appear in the log. A transport refusal has ability ''. */
    private const ABILITIES = ['afara/site-context', 'afara/read-file', 'afara/list-directory',
        'afara/elementor-document', 'afara/elementor-update-text', 'afara/elementor-update-image'];

    /** Fields every entry has, in order. Nothing else is ever stored. */
    public const FIELDS = ['time', 'user_id', 'user_login', 'connection', 'connection_id', 'ability', 'result', 'reason', 'count'];

    /** @var array{name: string, uuid: string}|null Set once per request when an Application Password authenticates. */
    private static ?array $connection = null;

    public static function record(string $ability, bool $success, string $reason = ''): void
    {
        if (!in_array($ability, self::ABILITIES, true)) {
            return;
        }
        self::append($ability, $success ? self::RESULT_SUCCESS : self::RESULT_ERROR, $success ? '' : $reason);
    }

    /** Record a request Afara turned away before any ability ran. */
    public static function refused(string $reason, string $ability = ''): void
    {
        if ($ability !== '' && !in_array($ability, self::ABILITIES, true)) {
            return;
        }
        self::append($ability, self::RESULT_REFUSED, $reason);
    }

    /** Remember which Application Password signed this request in (label only). */
    public static function useConnection(string $name, string $uuid): void
    {
        self::$connection = ['name' => self::label($name), 'uuid' => self::uuid($uuid)];
    }

    public static function resetConnection(): void
    {
        self::$connection = null;
    }

    /** @return array<int, array<string, mixed>> Newest first. */
    public static function recent(): array
    {
        $entries = get_option(self::OPTION, []);
        if (!is_array($entries)) {
            return [];
        }
        $normalised = [];
        foreach (array_slice($entries, -self::LIMIT) as $entry) {
            if (is_array($entry)) {
                $normalised[] = self::normalise($entry);
            }
        }
        return array_reverse($normalised);
    }

    /** Count refusals (including collapsed repeats) newer than $seconds ago. */
    public static function refusedSince(int $seconds, ?int $now = null): int
    {
        $cutoff = ($now ?? time()) - $seconds;
        $total = 0;
        foreach (self::recent() as $entry) {
            if ($entry['result'] === self::RESULT_REFUSED && (strtotime((string) $entry['time']) ?: 0) >= $cutoff) {
                $total += (int) $entry['count'];
            }
        }
        return $total;
    }

    private static function append(string $ability, string $result, string $reason): void
    {
        $entries = get_option(self::OPTION, []);
        if (!is_array($entries)) {
            $entries = [];
        }
        $userId = (int) get_current_user_id();
        $login = '';
        if ($userId > 0 && function_exists('get_userdata')) {
            $user = get_userdata($userId);
            $login = is_object($user) && isset($user->user_login) ? self::label((string) $user->user_login) : '';
        }
        $entry = [
            'time' => gmdate('Y-m-d\TH:i:s\Z'),
            'user_id' => $userId,
            'user_login' => $login,
            'connection' => self::$connection['name'] ?? '',
            'connection_id' => self::$connection['uuid'] ?? '',
            'ability' => $ability,
            'result' => $result,
            'reason' => self::code($reason),
            'count' => 1,
        ];

        $last = $entries === [] ? null : end($entries);
        if ($result === self::RESULT_REFUSED && is_array($last) && self::sameRefusal(self::normalise($last), $entry)) {
            $entry['count'] = (int) ($last['count'] ?? 1) + 1;
            $entries[array_key_last($entries)] = $entry;
        } else {
            $entries[] = $entry;
        }
        update_option(self::OPTION, array_values(array_slice($entries, -self::LIMIT)), false);
    }

    /** @param array<string, mixed> $last @param array<string, mixed> $next */
    private static function sameRefusal(array $last, array $next): bool
    {
        if ($last['result'] !== self::RESULT_REFUSED) {
            return false;
        }
        foreach (['user_id', 'connection', 'connection_id', 'ability', 'reason'] as $field) {
            if ($last[$field] !== $next[$field]) {
                return false;
            }
        }
        $age = (strtotime((string) $next['time']) ?: 0) - (strtotime((string) $last['time']) ?: 0);
        return $age >= 0 && $age <= self::COLLAPSE_SECONDS;
    }

    /**
     * Older entries (before refusals were logged) lack the newer fields.
     *
     * @param array<string, mixed> $entry
     * @return array<string, mixed>
     */
    private static function normalise(array $entry): array
    {
        $result = (string) ($entry['result'] ?? '');
        return [
            'time' => (string) ($entry['time'] ?? ''),
            'user_id' => (int) ($entry['user_id'] ?? 0),
            'user_login' => (string) ($entry['user_login'] ?? ''),
            'connection' => (string) ($entry['connection'] ?? ''),
            'connection_id' => self::uuid((string) ($entry['connection_id'] ?? '')),
            'ability' => (string) ($entry['ability'] ?? ''),
            'result' => in_array($result, [self::RESULT_SUCCESS, self::RESULT_ERROR, self::RESULT_REFUSED], true) ? $result : self::RESULT_ERROR,
            'reason' => self::code((string) ($entry['reason'] ?? '')),
            'count' => max(1, (int) ($entry['count'] ?? 1)),
        ];
    }

    /**
     * Newest entry made with a given Application Password, or null.
     *
     * @return array<string, mixed>|null
     */
    public static function lastForConnection(int $userId, string $uuid): ?array
    {
        $uuid = self::uuid($uuid);
        if ($uuid === '') {
            return null;
        }
        foreach (self::recent() as $entry) {
            if ($entry['user_id'] === $userId && $entry['connection_id'] === $uuid) {
                return $entry;
            }
        }
        return null;
    }

    /** Application Password IDs are UUIDs; anything else is dropped. */
    private static function uuid(string $value): string
    {
        $value = strtolower($value);
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $value) === 1 ? $value : '';
    }

    /** Reason codes are short machine codes only, never free text. */
    private static function code(string $reason): string
    {
        return preg_match('/^[a-z0-9_]{1,64}$/', $reason) === 1 ? $reason : ($reason === '' ? '' : 'unknown');
    }

    /** Labels are user-chosen; keep them short and printable. */
    private static function label(string $value): string
    {
        $value = trim((string) preg_replace('/[^\P{C}]+/u', '', $value));
        return function_exists('mb_substr') ? mb_substr($value, 0, 60) : substr($value, 0, 60);
    }
}
