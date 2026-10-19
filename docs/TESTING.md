# Afara staging validation

Do not deploy this development build to production.

## Prerequisites

- WordPress 6.9 or newer and PHP 8.1 or newer
- A disposable local or staging WordPress site
- An administrator test account
- The official WordPress MCP Adapter installed separately for future integration tests

## Foundation checks

1. Activate Afara and verify its settings page appears in wp-admin.
2. Verify AI access is off by default and read-only mode is enabled by default.
3. Enter a domain lock that does not match the site and confirm permissions are denied.
4. Enter the site's exact hostname, enable Afara, and verify only an administrator has access.
5. Verify the Abilities page lists the implemented read-only abilities and distinguishes unimplemented write tools.
6. Confirm the Connect page does not claim an MCP endpoint is active before integration is tested.
7. Run the PHP syntax checks and all unit smoke tests defined by GitHub Actions.

## Future end-to-end integration tests

- Confirm authenticated MCP discovery with official adapter on local WordPress
- Confirm requests without authentication and from insufficient roles are denied
- Confirm access is denied when domain lock mismatches or enabled switch is off
- Verify source inspection rejects hidden files, traversal and symlinks
- Audit output content and authentication logs for accidental sensitive data

These are test instructions, not a claim that WordPress or MCP integration tests have passed.
