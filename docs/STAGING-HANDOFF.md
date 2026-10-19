# Afara: staging test handoff

**Do not install on a production WordPress site.** Afara remains in draft stacked PRs. Do not merge solely because automated tests pass.

## What can be tested now

- WordPress 6.9+ / PHP 8.1+ plugin activation, admin permissions and settings
- Official MCP Adapter 0.7.1+ dependency and the dedicated Afara HTTP endpoint
- Application Password authentication with a separate test administrator account
- The three read-only MCP abilities and their permission/domain/path restrictions
- Connect, Abilities, Activity Log and inert Sandbox screens
- Safe mode controls and read-only defaults

## What is NOT ready

- Remote file writes, delete, arbitrary PHP execution, automatic crash recovery, and Elementor editing are **not** registered or ready.
- `LocalAtomicWriter` and `RecoveryPlan` are isolated prototypes; they are not wired into WordPress or MCP.
- The repository's local HTTP integration harness simulates TLS termination; it cannot certify a production HTTPS deployment.
- Backups are only isolated when the caller supplies an actually private, off-webroot directory. Afara does not provision or verify that location.

## User setup: when requested

Use **LocalWP** or a disposable HTTPS staging installation; WordPress 6.9+ and PHP 8.1+ are required. Install the official WordPress MCP Adapter plugin version 0.7.1 or newer, then install Afara from the reviewed code/ZIP. Keep Afara off by default until you are ready to test. Never reuse production credentials.

If testing remote MCP from Codex, make the staging site reachable over valid HTTPS; a localhost-only LocalWP site generally cannot be reached from Codex cloud. Alternatively use a locally running MCP client and the official remote bridge, with a locally trusted certificate and no certificate-verification bypass.

## Acceptance checklist

1. Afara activates without fatal errors; admin screens load on desktop and mobile.
2. Without MCP Adapter, Connect clearly reports the dependency, and abilities remain unavailable remotely.
3. Enabled + exact hostname lock + read-only mode: only authenticated administrators can call the MCP server.
4. Invalid password, non-administrator, disabled switch, changed hostname, insecure HTTP and revoked password are denied.
5. Exactly three read-only tools appear to the MCP client; unknown and destructive abilities cannot be invoked.
6. Site-context, list-directory and read-file work for permitted fixtures and reject traversal, hidden files, secrets and symlinks.
7. Activity Log records ability executions and every refused MCP request (Afara off, domain mismatch, plain HTTP, not signed in, not an administrator, wrong or revoked Application Password), with the account, the Application Password label and a reason code. It never stores credentials, request content, file contents, paths or IP addresses. Repeated identical refusals within 10 minutes are counted on one row.
8. Connect → Connections lists every administrator's Application Password with created, last-used and last-Afara-activity times. Revoke asks for confirmation, then deletes that Application Password through WordPress core (POST, nonce-checked, only for accounts you can edit); the agent using it is refused from its next request.
9. Settings → Quiet mode hides Afara's menu and Plugins/Updates rows from administrators not ticked; the person saving is always included. A hidden administrator can still reach Afara by URL and connect an agent. `define('AFARA_QUIET_MODE_OFF', true);` in wp-config.php shows it to everyone again.
10. Sandbox defaults to safe mode; toggling does not enable arbitrary execution.
11. Check actual webserver TLS trust, Authorization forwarding, proxy HTTPS signaling, and direct browser access to sandbox controls.
12. Record WordPress/PHP/Adapter versions and attach screenshots plus sanitized logs to the relevant PRs.

**Stop testing and report** if a write/PHP execution tool unexpectedly appears, permission tests allow a non-administrator, credentials appear in logs, or a denied file becomes readable.

## Post-staging milestones

After the staging read-only gate passes, design a constrained staging-only edit workflow with explicit approval, a private backup root outside the document root, durable journals, robust filesystem isolation, rollback tests and separate security review. Do not enable remote mutations merely because the local writer tests pass.
