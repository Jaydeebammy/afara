<?php
declare(strict_types=1);

namespace Afara\OAuth;

/**
 * A grant is one approval: this app, for this administrator, for this scope.
 *
 * Every access and refresh token points at a grant, and a token is only valid
 * while its grant exists. Revoking the grant therefore kills all of its tokens
 * at once. Grant IDs are UUIDs so the Activity log can match them like
 * Application Passwords.
 */
final class Grants
{
    public const OPTION = 'afara_oauth_grants';
    public const MAX_GRANTS = 200;
    private const TOUCH_EVERY = 60;

    /** @return array<string, array<string, mixed>> */
    public static function all(): array
    {
        $grants = get_option(self::OPTION, []);
        return is_array($grants) ? $grants : [];
    }

    /** @return array<string, mixed>|null */
    public static function find(string $grantId): ?array
    {
        $grants = self::all();
        return isset($grants[$grantId]) && is_array($grants[$grantId]) ? $grants[$grantId] : null;
    }

    public static function create(string $clientId, string $clientName, int $userId, string $scope, string $resource, ?int $now = null): string
    {
        $now ??= time();
        $grants = self::all();
        if (count($grants) >= self::MAX_GRANTS) {
            // Drop the least recently used grant rather than refuse a new approval.
            uasort($grants, static fn (array $a, array $b): int => ($a['last_used'] ?? $a['created']) <=> ($b['last_used'] ?? $b['created']));
            array_shift($grants);
        }
        $id = Store::uuid();
        $grants[$id] = [
            'client_id' => $clientId,
            'client_name' => $clientName,
            'user_id' => $userId,
            'scope' => $scope,
            'resource' => $resource,
            'created' => $now,
            'last_used' => null,
        ];
        update_option(self::OPTION, $grants, false);
        return $id;
    }

    /** Record use, at most once a minute so busy agents don't write on every request. */
    public static function touch(string $grantId, ?int $now = null): void
    {
        $now ??= time();
        $grants = self::all();
        if (!isset($grants[$grantId])) {
            return;
        }
        $last = $grants[$grantId]['last_used'] ?? null;
        if ($last === null || $now - (int) $last >= self::TOUCH_EVERY) {
            $grants[$grantId]['last_used'] = $now;
            update_option(self::OPTION, $grants, false);
        }
    }

    public static function revoke(string $grantId): bool
    {
        $grants = self::all();
        if (!isset($grants[$grantId])) {
            return false;
        }
        unset($grants[$grantId]);
        update_option(self::OPTION, $grants, false);
        return true;
    }

    /** Revoke every grant for one app (used when an app's refresh token is replayed, and on removal). */
    public static function revokeClient(string $clientId): int
    {
        $grants = self::all();
        $before = count($grants);
        $grants = array_filter($grants, static fn (array $g): bool => ($g['client_id'] ?? '') !== $clientId);
        update_option(self::OPTION, $grants, false);
        return $before - count($grants);
    }
}
