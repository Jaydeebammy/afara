# Architecture

Afara uses the WordPress 6.9+ Abilities API and the separately activated official
WordPress MCP Adapter 0.7.1+. It registers server `afara` on `mcp_adapter_init`,
using the adapter's `HttpTransport` at the `rest_url('afara/v1/mcp')` endpoint.
The plugin neither bundles the adapter nor implements a parallel MCP protocol.

## Request boundary

HTTPS → WordPress REST authentication (Application Passwords for remote clients)
→ server permission callback → authenticated administrator (`manage_options`)
→ off-by-default switch → exact `home_url()` hostname lock → ability permission
callback → read-only implementation and existing path/source guards.

The same gate is evaluated per request and per ability execution. Registration
must not depend on a current user at REST initialization. Disabling Afara or
changing the domain lock denies existing sessions as well as new connections.

The dedicated server explicitly allowlists `afara/site-context`, `afara/read-file`
and `afara/list-directory`, with no resources or prompts. These abilities opt out
of both the generic REST Abilities endpoint and the adapter default server's
public discovery/execution meta-tools. Source reads retain size/range limits,
UTF-8 validation, theme/plugin scope, sensitive-name exclusions and symlink and
traversal rejection. Read-only mode remains enabled by default; turning it off
does not add write abilities. There is no arbitrary PHP execution.

An absent or unsupported adapter leaves local registration and admin pages usable
without creating an Afara transport. Connect reports configuration prerequisites
without booting REST manually or claiming a live external connection. Afara uses
the adapter's null error/observability handlers to avoid logging credentials or
source content. Server creation errors emit a code-only
`afara_mcp_registration_failed` action for optional local monitoring.

[Integration choices and official API references](MCP.md).

## Future scope

Sandbox recovery, audit logs, optional OAuth, Elementor editing and file mutations
remain unimplemented. A folder boundary is not a PHP execution sandbox. No
security guarantees are claimed for those future features.
