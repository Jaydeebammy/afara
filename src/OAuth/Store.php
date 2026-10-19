<?php
declare(strict_types=1);

namespace Afara\OAuth;

/**
 * Short-lived OAuth records (codes, tokens, tombstones) kept in wp_options.
 *
 * Secrets are never stored: each record is keyed by the SHA-256 of the secret,
 * so a database dump can't be replayed. Every record carries its own expiry.
 * claim() reads and deletes in one step and only one caller can win, which is
 * what makes codes and refresh tokens single-use.
 */
final class Store
{
    public const KIND_CODE = 'c';
    public const KIND_ACCESS = 'a';
    public const KIND_REFRESH = 'r';
    public const KIND_USED_CODE = 'x';
    public const KIND_USED_REFRESH = 'y';
    public const KIND_DEVICE = 'd';
    public const KIND_USER_CODE = 'u';

    private const PREFIX = 'afara_oauth_r_';

    /** A random, URL-safe secret with $bytes of entropy. */
    public static function secret(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    public static function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /** @param array<string, mixed> $data */
    public static function put(string $kind, string $secret, array $data, int $ttl, ?int $now = null): void
    {
        $record = ['exp' => ($now ?? time()) + $ttl, 'data' => $data];
        $name = self::name($kind, $secret);
        if (!add_option($name, $record, '', false)) {
            update_option($name, $record, false);
        }
    }

    /** @return array<string, mixed>|null */
    public static function get(string $kind, string $secret, ?int $now = null): ?array
    {
        if ($secret === '') {
            return null;
        }
        $name = self::name($kind, $secret);
        $record = get_option($name, null);
        if (!is_array($record) || !isset($record['exp'], $record['data']) || !is_array($record['data'])) {
            return null;
        }
        if ((int) $record['exp'] < ($now ?? time())) {
            delete_option($name);
            return null;
        }
        return $record['data'];
    }

    /** Read and delete. Returns null unless this caller was the one that deleted it. */
    public static function claim(string $kind, string $secret, ?int $now = null): ?array
    {
        $data = self::get($kind, $secret, $now);
        if ($data === null) {
            return null;
        }
        return delete_option(self::name($kind, $secret)) ? $data : null;
    }

    public static function delete(string $kind, string $secret): void
    {
        if ($secret !== '') {
            delete_option(self::name($kind, $secret));
        }
    }

    /** Remove expired records. Runs from a daily cron event. */
    public static function purgeExpired(): int
    {
        global $wpdb;
        if (!isset($wpdb)) {
            return 0;
        }
        $like = $wpdb->esc_like(self::PREFIX) . '%';
        $names = $wpdb->get_col($wpdb->prepare("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 1000", $like));
        $removed = 0;
        foreach ((array) $names as $name) {
            $record = get_option((string) $name, null);
            if (!is_array($record) || (int) ($record['exp'] ?? 0) < time()) {
                delete_option((string) $name);
                $removed++;
            }
        }
        return $removed;
    }

    private static function name(string $kind, string $secret): string
    {
        return self::PREFIX . $kind . '_' . hash('sha256', $secret);
    }
}
