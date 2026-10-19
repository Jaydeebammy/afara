# Security policy

Afara is experimental software. Do not deploy to production or expose this foundation release as a remote MCP endpoint.

The settings gate is off by default and requires the WordPress `manage_options` capability and matching hostname. Read-only mode defaults to on. It is not a PHP sandbox.

**No arbitrary PHP execution, remote MCP endpoint, or agent file-write ability is included in this milestone.** A future release must assess authorization, cross-site request risks, symlink/path traversal, credential handling, audit events, and crash recovery before adding dangerous abilities.

Report vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting if enabled. Do not publish active exploits.
