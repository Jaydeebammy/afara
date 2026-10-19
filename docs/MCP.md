# Official MCP Adapter integration

Afara requires WordPress 6.9+, PHP 8.1+, and the separately installed and activated
[official WordPress MCP Adapter](https://github.com/WordPress/mcp-adapter), version
**0.7.1 or newer**. Version 0.7.1 is the tested adapter baseline. Do not bundle a
second adapter, call its initializer manually, or install the old REST transports.

## API research

The integration follows the official **v0.7.1** release APIs, reviewed on 2026-10-19:

- [Custom server registration](https://github.com/WordPress/mcp-adapter/blob/v0.7.1/includes/Core/McpAdapter.php):
  hook `mcp_adapter_init`, use the supplied `WP\MCP\Core\McpAdapter` and its
  `create_server()` method. The last argument is the transport permission callback.
- [HTTP transport](https://github.com/WordPress/mcp-adapter/blob/v0.7.1/includes/Transport/HttpTransport.php):
  `WP\MCP\Transport\HttpTransport` handles protocol requests and sessions, using
  WordPress REST authentication. POST is supported; GET/SSE is not implemented.
  DELETE terminates an MCP session, not a WordPress file or content item.
- [Explicit tool registration](https://github.com/WordPress/mcp-adapter/blob/v0.7.1/includes/Core/McpComponentRegistry.php):
  a custom server accepts an exact list of ability names, independent of default
  server public discovery. Conversion and execution stay inside the adapter and
  WordPress Abilities API; Afara does not implement its own MCP protocol.
- [Public exposure](https://github.com/WordPress/mcp-adapter/blob/v0.7.1/includes/Abilities/McpAbilityExposure.php):
  `meta.mcp.public = false` excludes Afara from the default server's meta-tools.
  `show_in_rest = false` continues to exclude the generic REST abilities endpoint.
- [Client bridge](https://github.com/WordPress/mcp-adapter/blob/v0.7.1/docs/guides/cli-usage.md):
  `@automattic/mcp-wordpress-remote` translates a client's local STDIO connection
  to authenticated HTTP. WordPress Application Passwords are the supported
  credential; Afara adds no custom password or token store and no OAuth server.

## Connect

1. Use a disposable staging WordPress site served through HTTPS. Install and
   activate the official adapter plugin and Afara. The adapter is optional for
   Afara's admin screens and local ability registration, but required for MCP.
2. In Afara Settings, enter the exact `home_url()` hostname and enable AI access.
   Keep read-only mode enabled. Unchecking read-only mode adds no write abilities.
3. On an administrator account (`manage_options`), create a dedicated Application
   Password in Users → Profile. Treat it as an administrator credential and revoke
   it when finished. Never use your regular account password.
4. Copy the endpoint displayed by Connect. With pretty permalinks it is usually
   `https://your-site.example/wp-json/afara/v1/mcp`; the implementation uses
   `rest_url()` so plain permalinks and subdirectory sites also work.
5. Configure an HTTP-capable MCP client with that endpoint and HTTP Basic
   authentication (WordPress username and Application Password), or use the
   official bridge on your own machine:

   ```json
   {
     "mcpServers": {
       "afara": {
         "command": "npx",
         "args": ["-y", "@automattic/mcp-wordpress-remote@latest"],
         "env": {
           "WP_API_URL": "https://your-site.example/wp-json/afara/v1/mcp",
           "WP_API_USERNAME": "your-wordpress-username",
           "WP_API_PASSWORD": "<application-password>"
         }
       }
     }
   }
   ```

   These are placeholders. Use the client's secure credential storage where
   available. Do not commit real credentials or include them in URLs or logs.
6. Let the client perform `initialize` and `notifications/initialized`, preserve
   the negotiated protocol headers and any `Mcp-Session-Id`, then request
   `tools/list`. MCP tool names are `afara-site-context`, `afara-read-file` and
   `afara-list-directory`; the adapter replaces the abilities' slash with a hyphen.

The server ID is `afara`, REST namespace `afara/v1`, route `mcp`. There are no
resources, prompts, generic execute-ability meta-tools, file mutations or arbitrary
PHP execution on this server. The Connect page reports local prerequisites,
**not** a successful remote connection or an endpoint probe.

## Deployment checks

WordPress must recognize the request as HTTPS (`is_ssl()`). For TLS termination,
configure WordPress and the trusted reverse proxy correctly; do not blindly trust
client-supplied forwarded headers. The web server must forward Authorization to
PHP. Afara delegates Basic authentication, credential validation and revocation
to WordPress, retaining core's cookie/nonce REST protections.

Server registration is independent of the current user because authentication may
occur later. Every HTTP request requires HTTPS, an authenticated user,
`manage_options`, the enabled switch and a matching domain. Every ability also
rechecks the existing permission gate. Existing sessions confer no lasting access
once the switch/domain/credentials change. Other plugins can explicitly register
abilities on their own servers; trusted administrator-installed PHP remains within
the WordPress trust boundary.

See [TESTING.md](TESTING.md) for automated coverage and real deployment validation.
