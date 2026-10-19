# Architecture — foundation

Afara uses WordPress 6.9+ Abilities API and plans to integrate the separately installed official WordPress MCP Adapter.

## Current request boundary

Authenticated WordPress account → ability permission callback → disabled-by-default Afara switch → exact hostname lock → read-only restriction for future mutations → registered ability.

Only `afara/site-context` is currently registered. The ability deliberately opts out of the generic WordPress REST Abilities endpoint while opting in to MCP metadata. **No MCP transport has been configured by Afara yet**; a separately installed adapter may still expose opted-in abilities through its default server, subject to authentication and permissions.

## Planned

Dedicated transport selection, allow-listed file inspection, sandbox recovery, audit logs, optional OAuth and Elementor abilities are future milestones. Arbitrary PHP execution is not isolated by a folder boundary. No security guarantee is claimed for unimplemented features.

## UI

WordPress admin hosts the native navigation. The design reference is the Figma Afara Admin UI; Connect and Abilities are currently partial implementations.
