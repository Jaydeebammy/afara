<?php
declare(strict_types=1);

namespace Afara\OAuth;

/**
 * Device Authorization Grant (RFC 8628) for agents without a browser:
 * terminal tools and chat bots.
 *
 * The agent gets a device_code (secret, kept by the agent) and a short
 * user_code (typed by the administrator on Afara's device page). The agent
 * polls the token endpoint until an administrator approves or denies.
 *
 * Storage: the device_code is only stored as a hash and points at the
 * user_code record, which holds the request's state. Approval always needs a
 * signed-in administrator to confirm on the page; a link alone never approves.
 */
final class DeviceFlow
{
    public const GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
    public const TTL = 600;
    public const INTERVAL = 5;
    public const MAX_PENDING = 20;
    public const PENDING_OPTION = 'afara_oauth_device_pending';
    /** No vowels (no accidental words) and no look-alikes like 0/O or 1/I (RFC 8628 §6.1). */
    private const ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

    /**
     * Device authorization endpoint.
     *
     * @param array<string, mixed> $body
     * @return array{status: int, body: array<string, mixed>}
     */
    public static function start(array $body, ?int $now = null): array
    {
        $now ??= time();
        $str = static fn (string $k): string => isset($body[$k]) && is_string($body[$k]) ? $body[$k] : '';
        $clientId = $str('client_id');
        $client = Clients::find($clientId);
        if ($client === null) {
            return self::error('invalid_client', 'Unknown client_id.');
        }
        if (!Clients::allowsGrant($client, self::GRANT)) {
            return self::error('unauthorized_client', 'This client did not register for the device_code grant.');
        }
        $scope = trim($str('scope'));
        if ($scope !== '' && array_diff(array_filter(explode(' ', $scope)), [Config::SCOPE]) !== []) {
            return self::error('invalid_scope', 'The only scope Afara offers is ' . Config::SCOPE . '.');
        }
        $resource = $str('resource');
        if ($resource !== '' && !Config::sameResource($resource, Config::resource())) {
            return self::error('invalid_target', 'Tokens can only be issued for this site’s Afara MCP server.');
        }
        $pending = self::pending($now);
        if (count($pending) >= self::MAX_PENDING) {
            return ['status' => 429, 'body' => ['error' => 'slow_down', 'error_description' => 'Too many device sign-ins waiting for approval. Try again in a few minutes.']];
        }
        $pending[] = $now + self::TTL;
        update_option(self::PENDING_OPTION, $pending, false);

        $deviceCode = Store::secret();
        $userCode = self::newUserCode();
        Store::put(Store::KIND_USER_CODE, $userCode, [
            'device_hash' => hash('sha256', $deviceCode),
            'client_id' => $clientId,
            'scope' => Config::SCOPE,
            'resource' => Config::resource(),
            'status' => 'pending',
            'user_id' => 0,
            'created' => $now,
        ], self::TTL, $now);
        Store::put(Store::KIND_DEVICE, $deviceCode, [
            'user_code' => $userCode,
            'client_id' => $clientId,
            'interval' => self::INTERVAL,
            'last_poll' => 0,
        ], self::TTL, $now);

        $verify = self::verificationUri();
        return ['status' => 200, 'body' => [
            'device_code' => $deviceCode,
            'user_code' => self::format($userCode),
            'verification_uri' => $verify,
            'verification_uri_complete' => $verify . '&user_code=' . rawurlencode(self::format($userCode)),
            'expires_in' => self::TTL,
            'interval' => self::INTERVAL,
        ]];
    }

    /**
     * What the device page shows for a typed code, or null if it's unknown or expired.
     *
     * @return array{user_code: string, client: array<string, mixed>, state: array<string, mixed>}|null
     */
    public static function lookup(string $typed): ?array
    {
        $code = self::normalize($typed);
        if ($code === '') {
            return null;
        }
        $state = Store::get(Store::KIND_USER_CODE, $code);
        if ($state === null || $state['status'] !== 'pending') {
            return null;
        }
        $client = Clients::find((string) $state['client_id']);
        return $client === null ? null : ['user_code' => $code, 'client' => $client, 'state' => $state];
    }

    /** The administrator's decision. Returns false if the code is no longer waiting. */
    public static function decide(string $typed, bool $allow, int $userId): bool
    {
        $found = self::lookup($typed);
        if ($found === null) {
            return false;
        }
        $state = $found['state'];
        $state['status'] = $allow ? 'approved' : 'denied';
        $state['user_id'] = $allow ? $userId : 0;
        $remaining = max(1, (int) $state['created'] + self::TTL - time());
        Store::put(Store::KIND_USER_CODE, $found['user_code'], $state, $remaining);
        if ($allow) {
            Clients::approve((string) $state['client_id']);
        }
        return true;
    }

    /**
     * Token endpoint, device_code grant: the agent's polling request.
     *
     * @return array{status: int, body: array<string, mixed>}
     */
    public static function poll(string $clientId, string $deviceCode, ?int $now = null): array
    {
        $now ??= time();
        $device = Store::get(Store::KIND_DEVICE, $deviceCode, $now);
        if ($device === null) {
            return self::error('expired_token', 'The device code has expired or was already used. Start again.');
        }
        if (!hash_equals((string) $device['client_id'], $clientId)) {
            return self::error('invalid_grant', 'The device code was issued to a different client.');
        }
        $state = Store::get(Store::KIND_USER_CODE, (string) $device['user_code'], $now);
        if ($state === null || !hash_equals((string) $state['device_hash'], hash('sha256', $deviceCode))) {
            Store::delete(Store::KIND_DEVICE, $deviceCode);
            return self::error('expired_token', 'The device code has expired. Start again.');
        }
        if ($state['status'] === 'denied') {
            Store::delete(Store::KIND_DEVICE, $deviceCode);
            Store::delete(Store::KIND_USER_CODE, (string) $device['user_code']);
            return self::error('access_denied', 'The site administrator declined.');
        }
        if ($state['status'] === 'pending') {
            $interval = (int) $device['interval'];
            if ($device['last_poll'] > 0 && $now - (int) $device['last_poll'] < $interval) {
                $device['interval'] = $interval + 5; // RFC 8628 §3.5: back off by 5 seconds.
                $device['last_poll'] = $now;
                Store::put(Store::KIND_DEVICE, $deviceCode, $device, max(1, (int) $state['created'] + self::TTL - $now), $now);
                return self::error('slow_down', 'Polling too fast; wait ' . $device['interval'] . ' seconds between requests.');
            }
            $device['last_poll'] = $now;
            Store::put(Store::KIND_DEVICE, $deviceCode, $device, max(1, (int) $state['created'] + self::TTL - $now), $now);
            return self::error('authorization_pending', 'Waiting for an administrator to approve this code.');
        }
        // Approved: exactly one poll can win the tokens.
        if (Store::claim(Store::KIND_DEVICE, $deviceCode, $now) === null) {
            return self::error('expired_token', 'The device code was already used.');
        }
        Store::delete(Store::KIND_USER_CODE, (string) $device['user_code']);
        $userId = (int) $state['user_id'];
        if (!user_can($userId, 'manage_options')) {
            return self::error('access_denied', 'The approving account is no longer an administrator.');
        }
        $client = Clients::find($clientId) ?? [];
        $grantId = Grants::create($clientId, (string) ($client['client_name'] ?? ''), $userId, (string) $state['scope'], (string) $state['resource']);
        return AuthorizationServer::issueFor($grantId);
    }

    public static function verificationUri(): string
    {
        return admin_url('admin.php?page=' . self::PAGE);
    }

    public const PAGE = 'afara-device';

    /** Upper-case, keep only alphabet letters: "bcdf-ghjk" and "BCDF GHJK" both work. */
    public static function normalize(string $typed): string
    {
        $code = (string) preg_replace('/[^' . self::ALPHABET . ']/', '', strtoupper($typed));
        return strlen($code) === 8 ? $code : '';
    }

    public static function format(string $code): string
    {
        return substr($code, 0, 4) . '-' . substr($code, 4);
    }

    private static function newUserCode(): string
    {
        $code = '';
        for ($i = 0; $i < 8; $i++) {
            $code .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
        }
        return $code;
    }

    /** @return list<int> expiry times of device sign-ins still waiting */
    private static function pending(int $now): array
    {
        $list = get_option(self::PENDING_OPTION, []);
        return array_values(array_filter(is_array($list) ? array_map('intval', $list) : [], static fn (int $exp): bool => $exp > $now));
    }

    /** @return array{status: int, body: array<string, string>} */
    private static function error(string $code, string $description, int $status = 400): array
    {
        return ['status' => $status, 'body' => ['error' => $code, 'error_description' => $description]];
    }
}
