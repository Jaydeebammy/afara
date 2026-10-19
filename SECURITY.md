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
server exposes only three read-only abilities. They opt out of default-server
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
