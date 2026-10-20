<?php
declare(strict_types=1);

namespace Afara\OAuth;

use Afara\Audit\ActivityLog;
use Afara\Mcp\Server;

/**
 * WordPress plumbing for OAuth: REST endpoints, well-known discovery, bearer
 * sign-in on Afara's MCP route, the 401 challenge header, and cleanup.
 *
 * Bearer tokens are only ever read on Afara's own MCP route. Everywhere else
 * in WordPress an Afara token signs nobody in.
 */
final class Http
{
    public const CRON_HOOK = 'afara_oauth_purge';

    /** Set when a bearer token was presented on Afara's route but didn't verify. */
    private static bool $invalidToken = false;
    private static bool $bearerAuthenticated = false;

    public function register(): void
    {
        add_action('rest_api_init', [$this, 'routes']);
        add_action('init', [$this, 'wellKnown'], 1);
        add_filter('determine_current_user', [$this, 'authenticate'], 30);
        add_filter('rest_authentication_errors', [$this, 'authenticationErrors'], 30);
        add_filter('rest_post_dispatch', [$this, 'challenge'], 10, 3);
        add_action(self::CRON_HOOK, [Store::class, 'purgeExpired']);
        add_action('init', static function (): void {
            if (function_exists('wp_next_scheduled') && !wp_next_scheduled(self::CRON_HOOK)) {
                wp_schedule_event(time() + 3600, 'daily', self::CRON_HOOK);
            }
        });
    }

    public function routes(): void
    {
        $ns = Server::REST_NAMESPACE;
        $base = Config::REST_BASE;
        $open = ['permission_callback' => '__return_true'];
        register_rest_route($ns, "/$base/metadata", $open + ['methods' => 'GET', 'callback' => fn () => $this->json(static fn () => Config::authorizationServerMetadata())]);
        register_rest_route($ns, "/$base/.well-known/openid-configuration", $open + ['methods' => 'GET', 'callback' => fn () => $this->json(static fn () => Config::authorizationServerMetadata())]);
        register_rest_route($ns, "/$base/protected-resource", $open + ['methods' => 'GET', 'callback' => fn () => $this->json(static fn () => Config::protectedResourceMetadata())]);
        register_rest_route($ns, "/$base/register", $open + ['methods' => 'POST', 'callback' => fn (\WP_REST_Request $r) => $this->result(fn () => Clients::register($this->params($r, true)))]);
        register_rest_route($ns, "/$base/token", $open + ['methods' => 'POST', 'callback' => fn (\WP_REST_Request $r) => $this->result(fn () => AuthorizationServer::token($this->params($r)))]);
        register_rest_route($ns, "/$base/device", $open + ['methods' => 'POST', 'callback' => fn (\WP_REST_Request $r) => $this->result(fn () => DeviceFlow::start($this->params($r)))]);
        register_rest_route($ns, "/$base/revoke", $open + ['methods' => 'POST', 'callback' => fn (\WP_REST_Request $r) => $this->result(fn () => AuthorizationServer::revoke($this->params($r)))]);
    }

    /**
     * Serve the root-level well-known documents (RFC 8414 / RFC 9728 path insertion).
     * They live outside /wp-json, so they're answered before WordPress routes the request.
     */
    public function wellKnown(): void
    {
        $path = (string) wp_parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
        if (!str_starts_with($path, '/.well-known/')) {
            return;
        }
        $documents = [
            (string) wp_parse_url(Config::protectedResourceMetadataUrl(), PHP_URL_PATH) => 'resource',
            (string) wp_parse_url(Config::authorizationServerMetadataUrl(), PHP_URL_PATH) => 'server',
            (string) wp_parse_url(str_replace('/oauth-authorization-server/', '/openid-configuration/', Config::authorizationServerMetadataUrl()), PHP_URL_PATH) => 'server',
        ];
        $which = $documents[rtrim($path, '/')] ?? null;
        if ($which === null || !Config::available()) {
            return; // Let WordPress 404 as usual.
        }
        $body = $which === 'resource' ? Config::protectedResourceMetadata() : Config::authorizationServerMetadata();
        status_header(200);
        header('Content-Type: application/json; charset=utf-8');
        header('Access-Control-Allow-Origin: *');
        header('Cache-Control: public, max-age=300');
        echo wp_json_encode($body);
        exit;
    }

    /** Sign in from a bearer token, on Afara's MCP route only. */
    public function authenticate($userId)
    {
        if (!empty($userId) || !Server::isAfaraRequest() || self::bearer() === null) {
            return $userId;
        }
        if (!Config::available()) {
            self::$invalidToken = true;
            return $userId;
        }
        $verified = AuthorizationServer::verifyAccessToken((string) self::bearer());
        if ($verified === null) {
            self::$invalidToken = true;
            return $userId;
        }
        self::$bearerAuthenticated = true;
        ActivityLog::useConnection($verified['client_name'], $verified['grant_id']);
        Grants::touch($verified['grant_id']);
        return $verified['user_id'];
    }

    /** A bad bearer token is a 401, not an anonymous request. */
    public function authenticationErrors($result)
    {
        if ($result !== null || !self::$invalidToken || !Server::isAfaraRequest()) {
            return $result;
        }
        Server::recordRefusal('afara_invalid_token');
        return new \WP_Error('afara_invalid_token', 'The access token is invalid, expired or revoked.', ['status' => 401]);
    }

    /** Tell clients where to sign in when Afara's MCP route answers 401 (RFC 9728 §5.1). */
    public function challenge($response, $server, $request)
    {
        if (!$response instanceof \WP_REST_Response || $response->get_status() !== 401 || !Config::available()) {
            return $response;
        }
        $route = '/' . Server::REST_NAMESPACE . '/' . Server::REST_ROUTE;
        if (!is_object($request) || !method_exists($request, 'get_route') || rtrim((string) $request->get_route(), '/') !== $route) {
            return $response;
        }
        $parts = ['resource_metadata="' . Config::protectedResourceMetadataUrl() . '"', 'scope="' . Config::SCOPE . '"'];
        if (self::$invalidToken) {
            array_unshift($parts, 'error="invalid_token"');
        }
        $response->header('WWW-Authenticate', 'Bearer ' . implode(', ', $parts));
        return $response;
    }

    /** Existing afara:read grants never authorize Elementor mutations. */
    public static function isBearerAuthenticated(): bool
    {
        return self::$bearerAuthenticated;
    }

    public static function resetRequestState(): void
    {
        self::$invalidToken = false;
        self::$bearerAuthenticated = false;
    }

    private static function bearer(): ?string
    {
        $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
        if ($header === '' && function_exists('getallheaders')) {
            foreach ((array) getallheaders() as $name => $value) {
                if (strtolower((string) $name) === 'authorization') {
                    $header = (string) $value;
                }
            }
        }
        return preg_match('/^Bearer\s+([A-Za-z0-9\-._~+\/]+=*)\s*$/', $header, $m) === 1 ? $m[1] : null;
    }

    /** @return array<string, mixed> */
    private function params(\WP_REST_Request $request, bool $json = false): array
    {
        $params = $json ? (array) $request->get_json_params() : (array) $request->get_body_params();
        return $params !== [] ? $params : (array) $request->get_params();
    }

    /** Run an endpoint only when OAuth is available, and never cache its answer. */
    private function result(callable $endpoint): \WP_REST_Response
    {
        if (!Config::available()) {
            return $this->unavailable();
        }
        $result = $endpoint();
        $response = new \WP_REST_Response((object) $result['body'], $result['status']);
        $response->header('Cache-Control', 'no-store');
        $response->header('Pragma', 'no-cache');
        return $response;
    }

    private function json(callable $document): \WP_REST_Response
    {
        if (!Config::available()) {
            return $this->unavailable();
        }
        $response = new \WP_REST_Response($document(), 200);
        $response->header('Access-Control-Allow-Origin', '*');
        return $response;
    }

    private function unavailable(): \WP_REST_Response
    {
        return new \WP_REST_Response(['error' => 'not_found', 'error_description' => 'OAuth sign-in is not enabled on this site.'], 404);
    }
}
