# Security policy

Afara is experimental development software. Use only disposable local or staging
WordPress installations; do not deploy this milestone to production.

AI access is off by default. Remote MCP requests require HTTPS, WordPress
authentication, `manage_options` (normally an administrator), and an exact matching
hostname lock. Ability execution also checks the existing permission gate.
Application Passwords carry the account's privileges: create a dedicated revocable
credential, keep it in the client's secure settings and never put it in URLs,
source control or logs. Afara does not store connection credentials.

The official WordPress MCP Adapter provides the HTTP transport. Afara's dedicated
server exposes source inspection and guarded Elementor draft-editing abilities.
Elementor writes additionally require safe mode off, write mode, staging/development,
per-post edit permission and a current checksum; OAuth grants remain read-only.
Writes create a WordPress revision backup before using the Elementor document API. They opt out of default-server
public meta-tools and generic REST ability exposure. File reads/listings retain
narrow source scope, size/range limits and traversal/symlink/sensitive-name guards.
Source-name filtering is defense in depth, not a secret scanner: administrators
must not place secrets in otherwise readable source files.

Read-only mode defaults to on and does not implement a PHP sandbox. **No arbitrary
PHP execution, file writes, edits or deletions are implemented.** Future dangerous
abilities require separate authorization and review of isolation, recovery,
cross-site request risks and audit/credential handling.

Trusted administrator-installed PHP can register additional servers or abilities;
Afara cannot isolate other WordPress plugins. Configure trusted TLS termination
and Authorization forwarding correctly. Never trust arbitrary forwarded headers.
See [docs/MCP.md](docs/MCP.md) and [docs/TESTING.md](docs/TESTING.md).

Report vulnerabilities privately to the repository owner through GitHub private
vulnerability reporting if enabled. Do not publish active exploits.

## Quiet mode is not a security control

Quiet mode hides Afara's menu and its rows on the Plugins and Updates screens from administrators who aren't on the chosen list. It never blocks them: a hidden administrator can still open Afara's pages by URL, see Afara in WP-CLI and Site Health, read its files, and connect an agent. Tell the site owner Afara is installed. If no listed account is still an administrator, quiet mode turns itself off, and `define('AFARA_QUIET_MODE_OFF', true);` in `wp-config.php` turns it off at any time.

## OAuth sign-in

OAuth is off by default (Settings → OAuth sign-in) and needs HTTPS and pretty permalinks.

- **Discovery:** Afara's 401 carries `WWW-Authenticate: Bearer resource_metadata="…", scope="afara:read"` (RFC 9728). Metadata is also served at the RFC 9728 and RFC 8414 well-known URLs.
- **Clients:** Dynamic Client Registration (RFC 7591), public clients only. Redirect URIs must be HTTPS or loopback and are matched exactly. Unapproved registrations expire after a day, and the registry is capped.
- **Approval:** an administrator approves each app on a wp-admin consent screen. The screen shows the exact return host and warns when it is localhost-only, because any local program can claim any name. The consent nonce is bound to the request, so its PKCE challenge can't be swapped.
- **Codes:** PKCE S256 is required and `plain` is refused. Codes live for 60 seconds and are single-use. Replaying a code revokes the tokens it produced.
- **Tokens:** access tokens last one hour and are bound to Afara's MCP endpoint (RFC 8707 audience). Refresh tokens rotate on every use, and replaying an old one revokes the whole grant. Revocation follows RFC 7009.
- **Storage:** codes and tokens are stored only as SHA-256 hashes.
- **Scope of tokens:** they are read only on Afara's MCP route. On any other WordPress route an Afara token signs nobody in.
- **Turning it off:** revoke an app in Connect, turn OAuth off, or turn Afara off, and every token stops working on its next request. Tokens also stop if the approving account stops being an administrator.
- **Device sign-in (RFC 8628)** is for agents without a browser. The agent shows an 8-letter code with no vowels or look-alike characters, and an administrator types it on Afara's device page.
  - A link that carries the code only fills in the box. Approval always takes a click on a screen that warns: "If someone sent you this code or link, click Deny". This guards against device-code phishing.
  - Codes expire after 10 minutes. Device codes are stored only as hashes and are single-use.
  - Polling too fast gets `slow_down`, and no more than 20 sign-ins can wait for approval at once.
