<?php
declare(strict_types=1);

namespace WP\MCP\Core {
    // Contract double only. The HTTP integration suite uses the real plugin.
    final class McpAdapter {
        public array $calls = [];
        public bool $fail = false;
        public function create_server(...$args) {
            $this->calls[] = $args;
            return $this->fail ? new \WP_Error() : $this;
        }
    }
}
namespace WP\MCP\Transport { final class HttpTransport {} }
namespace {
    $mode = $argv[1] ?? 'supported';
    if ($mode !== 'missing') {
        define('WP_MCP_VERSION', $mode === 'old' ? '0.7.0' : '0.7.1');
    }
    define('AFARA_VERSION', '0.1.0');
    $options = [];
    $admin = false;
    $loggedIn = false;
    $ssl = true;
    $abilities = [];
    $hooks = [];
    $events = [];
    class WP_Error { public function get_error_code(): string { return 'test_failure'; } }
    function is_wp_error($value): bool { return $value instanceof WP_Error; }
    function get_option($name, $default = false) { global $options; return $options[$name] ?? $default; }
    function update_option($name, $value, $autoload = null): bool { global $options; $options[$name] = $value; return true; }
    $userId = 0;
    function get_current_user_id(): int { global $userId; return $userId; }
    function get_userdata($id) { return $id === 1 ? (object) ['user_login' => 'admin'] : false; }
    function home_url(): string { return 'https://staging.example.test'; }
    function wp_parse_url($url, $component) { return parse_url($url, $component); }
    $editable = [];
    function current_user_can($capability, ...$args): bool {
        global $admin, $editable;
        if ($capability === 'edit_user') { return $admin && in_array((int) ($args[0] ?? 0), $editable, true); }
        return $capability === 'manage_options' && $admin;
    }
    function is_user_logged_in(): bool { global $loggedIn; return $loggedIn; }
    function is_ssl(): bool { global $ssl; return $ssl; }
    function wp_get_ability($name) { global $abilities; return $abilities[$name] ?? null; }
    function wp_register_ability($name, $args): void { global $abilities; $abilities[$name] = $args; }
    function __($text, $domain): string { return $text; }
    function add_action($name, $callback): void { global $hooks; $hooks[$name][] = $callback; }
    function do_action($name, ...$args): void { global $events; $events[] = [$name, $args]; }
    function rest_url($path): string { return 'https://staging.example.test/?rest_route=/' . $path; }
    function check(bool $ok, string $label): void {
        if (!$ok) { throw new RuntimeException($label); }
    }
    require dirname(__DIR__) . '/src/Security/PermissionGate.php';
    require dirname(__DIR__) . '/src/Mcp/Server.php';
    require dirname(__DIR__) . '/src/Audit/ActivityLog.php';
    require dirname(__DIR__) . '/src/Audit/AuditCallback.php';
    require dirname(__DIR__) . '/src/Abilities/SiteContext.php';
    require dirname(__DIR__) . '/src/Abilities/ReadFile.php';
    require dirname(__DIR__) . '/src/Abilities/ListDirectory.php';

    $gate = new \Afara\Security\PermissionGate();
    $server = new \Afara\Mcp\Server($gate);
    $adapter = new \WP\MCP\Core\McpAdapter();
    $server->register();
    check(isset($hooks['mcp_adapter_init']), 'register on official lifecycle hook');
    foreach ([\Afara\Abilities\SiteContext::class, \Afara\Abilities\ReadFile::class, \Afara\Abilities\ListDirectory::class] as $class) {
        (new $class($gate))->register();
    }
    foreach ($abilities as $name => $definition) {
        check($definition['meta']['mcp']['public'] === false, "$name excluded from default server");
        check($definition['meta']['show_in_rest'] === false, "$name excluded from REST abilities");
        check($definition['meta']['annotations']['readonly'] === true, "$name read-only annotation");
        check(!$definition['permission_callback'](), "$name disabled by default");
    }
    $hooks['mcp_adapter_init'][0]($adapter);
    if ($mode !== 'supported') {
        check($adapter->calls === [], 'missing/old adapter must not register');
        echo "MCP dependency test ($mode) passed\n";
        exit(0);
    }
    check(count($adapter->calls) === 1, 'register even before authentication and while disabled');
    $args = $adapter->calls[0];
    check(array_slice($args, 0, 3) === ['afara', 'afara/v1', 'mcp'], 'dedicated identity and route');
    check($args[6] === [\WP\MCP\Transport\HttpTransport::class], 'only official HTTP transport');
    check($args[9] === array_keys($abilities), 'exact three ability allowlist');
    check($args[10] === [] && $args[11] === [], 'no resources or prompts');
    check(str_contains($server::endpoint(), '?rest_route=/afara/v1/mcp'), 'supports non-pretty permalinks');
    $authorize = $args[12];
    check(!$authorize(), 'anonymous disabled denied');
    $options = ['afara_enabled' => '1', 'afara_domain_lock' => 'staging.example.test'];
    $admin = true;
    check(!$authorize(), 'explicit authenticated identity required');
    $loggedIn = true;
    check($authorize(), 'authenticated administrator on locked site permitted');
    foreach ($abilities as $name => $definition) {
        check($definition['permission_callback'](), "$name permitted for administrator");
    }
    $ssl = false;
    check(!$authorize(), 'plaintext transport denied');
    $ssl = true;
    $admin = false;
    check(!$authorize(), 'non-administrator denied');
    foreach ($abilities as $name => $definition) {
        check(!$definition['permission_callback'](), "$name non-administrator denied");
    }
    $admin = true;
    foreach (['', 'other.test'] as $domain) {
        $options['afara_domain_lock'] = $domain;
        check(!$authorize(), 'empty/mismatched domain denied on existing callback');
        foreach ($abilities as $definition) { check(!$definition['permission_callback'](), 'ability domain check'); }
    }
    $options['afara_domain_lock'] = 'staging.example.test';
    $options['afara_enabled'] = '0';
    check(!$authorize(), 'disable denies existing server immediately');
    foreach ($abilities as $definition) { check(!$definition['permission_callback'](), 'ability disable check'); }

    // Refused requests are logged once per request, with a reason and no secrets.
    $log = static function () use (&$options): array { return \Afara\Audit\ActivityLog::recent(); };
    $attempt = static function () use ($authorize): bool { \Afara\Mcp\Server::resetRequestState(); return $authorize(); };
    $options = ['afara_enabled' => '1', 'afara_domain_lock' => 'staging.example.test'];
    $ssl = true; $loggedIn = false; $admin = false; $userId = 0;
    check(!$attempt(), 'anonymous refused');
    check(!$authorize() && !$authorize(), 'adapter re-checks in the same request');
    $entries = $log();
    check(count($entries) === 1 && $entries[0]['reason'] === 'afara_not_signed_in' && $entries[0]['count'] === 1, 'one refusal row per request');
    $loggedIn = true; $userId = 2;
    check(!$attempt(), 'editor refused');
    check($log()[0]['reason'] === 'afara_not_admin' && $log()[0]['user_id'] === 2, 'non-admin refusal names the user');
    $admin = true; $userId = 1;
    $options['afara_domain_lock'] = 'other.test';
    check(!$attempt(), 'mismatch refused');
    check($log()[0]['reason'] === 'afara_domain_mismatch' && $log()[0]['user_login'] === 'admin', 'domain mismatch reason');
    $options['afara_enabled'] = '0';
    check(!$attempt() && $log()[0]['reason'] === 'afara_disabled', 'disabled reason');
    $options['afara_enabled'] = '1'; $options['afara_domain_lock'] = 'staging.example.test';
    $ssl = false;
    check(!$attempt() && $log()[0]['reason'] === 'afara_https_required', 'https reason');
    $ssl = true;
    $before = count($log());
    check($attempt(), 'allowed request');
    check(count($log()) === $before, 'allowed transport checks add no rows');

    // Application Password outcomes, only on Afara's route.
    check(isset($hooks['application_password_failed_authentication'], $hooks['application_password_did_authenticate']), 'auth hooks registered');
    $fail = new class { public function get_error_code(): string { return 'incorrect_password'; } };
    $_GET = []; $_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
    \Afara\Mcp\Server::resetRequestState();
    $server->connectionFailed($fail);
    check($log()[0]['reason'] !== 'incorrect_password', 'other routes are not logged');
    $_SERVER['REQUEST_URI'] = '/wp-json/afara/v1/mcp';
    \Afara\Mcp\Server::resetRequestState();
    $server->connectionFailed($fail);
    check($log()[0]['reason'] === 'incorrect_password' && $log()[0]['result'] === 'refused', 'revoked password refusal logged');
    $_SERVER['REQUEST_URI'] = '/index.php';
    $_GET = ['rest_route' => '/afara/v1/mcp'];
    check(\Afara\Mcp\Server::isAfaraRequest(), 'plain-permalink route detected');
    $_GET = ['rest_route' => '/afara/v1/mcpx'];
    check(!\Afara\Mcp\Server::isAfaraRequest(), 'look-alike route ignored');
    $_GET = ['rest_route' => '/afara/v1/mcp'];
    \Afara\Mcp\Server::resetRequestState();
    $server->connectionAuthenticated((object) [], ['name' => 'Antigravity', 'uuid' => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', 'password' => 'hash-must-not-leak']);
    \Afara\Audit\ActivityLog::record('afara/site-context', true);
    check($log()[0]['connection'] === 'Antigravity', 'connection label recorded');
    check(!str_contains(json_encode($options['afara_activity_log']), 'hash-must-not-leak'), 'password hash never stored');
    $_GET = []; unset($_SERVER['REQUEST_URI']);
    \Afara\Mcp\Server::resetRequestState();

    unset($abilities['afara/read-file']);
    $server->create($adapter);
    check(count($adapter->calls) === 1, 'missing ability prevents incomplete server registration');
    $abilities['afara/read-file'] = [];
    $adapter->fail = true;
    $server->create($adapter);
    check($events === [['afara_mcp_registration_failed', ['test_failure']]], 'registration error handled without secrets');
    echo "MCP server and ability authorization tests passed\n";
}
