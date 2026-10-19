# Afara validation

Use a disposable local/staging installation; never production.

## Isolated tests

PHP 8.1+ is required. Run `bash tests/run.sh` from the checkout. This runs syntax
checks and every `tests/*Test.php`, including the existing permission, traversal,
symlink, readable scope and sensitive-source policy tests. New contract tests cover
server registration, dependency failures, the exact tool allowlist, HTTPS and
identity requirements, per-request/per-ability authorization and Connect output.
They use test doubles and do not prove WordPress runtime compatibility.

## Real WordPress HTTP integration

GitHub Actions also installs disposable WordPress 6.9/PHP 8.1 and latest
WordPress/PHP 8.3 with MySQL and the official **MCP Adapter v0.7.1** release. It
activates both plugins and runs `tests/integration/http_test.py` against real
WordPress REST HTTP requests. The test creates and revokes temporary Application
Passwords without printing their values. It checks:

- Anonymous, invalid-password and editor denial; administrator authentication.
- Off-by-default behavior, exact domain lock, live disable/domain changes.
- MCP initialization/session handling and discovery of exactly three tools.
- Site-context, file reading and directory listing through the real adapter.
- Schema validation, sensitive files, traversal, symlinks and unknown tools.
- Default-server discovery/execution exclusion, credential revocation and no SSE.

The runner expects a **fresh disposable** WordPress with username `admin`, the
adapter and Afara activated, site URL `https://localhost:8080`, database running,
`WP_ENVIRONMENT_TYPE=local`, and WP-CLI on PATH. It changes Afara options and
creates/removes fixtures, a test editor and test credentials; do not run it against
an existing site. Set `AFARA_WP_PATH` to its installation directory, then:

```bash
php -S 127.0.0.1:8080 -t "$AFARA_WP_PATH" tests/integration/router.php
# In another shell, with the same environment:
python3 tests/integration/http_test.py
```

The loopback-only test router simulates trusted TLS termination by setting the
WordPress HTTPS server variable. It exercises real Application Password/REST
authentication and MCP, **not** a TLS handshake or real proxy configuration.
Never deploy the router or tests to a live site. Test cleanup leaves Afara disabled.

## Required real deployment validation

On a disposable HTTPS staging installation with the actual web server and client:

1. Verify activation and graceful missing/inactive/old-adapter status; off-by-default
   and read-only defaults; incorrect/empty hostname denial.
2. Verify Connect's HTTPS/Application Password prerequisite messages and escaped
   endpoint, including plain permalinks and subdirectory installations.
3. Configure a real MCP client or official remote bridge using [MCP.md](MCP.md).
   Confirm initialization, discovery and representative calls for all three tools.
4. Confirm anonymous/editor/invalid/revoked-password denial. Test switch and domain
   changes during an existing session and verify plaintext requests are denied.
5. Verify the real TLS certificate chain, reverse-proxy HTTPS detection,
   Authorization forwarding, core cookie/nonce protections and credential redaction
   in infrastructure/client logs. Never disable TLS verification to make this pass.
6. Confirm default-server meta-tools do not expose Afara abilities, the generic
   REST abilities endpoint remains unavailable for these abilities, and path/source
   policies still deny sensitive filenames, hidden entries, traversal and symlinks.
7. Confirm the Connect page never labels local prerequisites as verified remote
   connectivity and no write/PHP-execution tools appear.

These deployment checks require a real installation and are not implied by the
loopback suite or isolated tests passing.
