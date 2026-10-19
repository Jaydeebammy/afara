# Controlled editing: preflight stage

The initial edit planner is **pure and non-executing**. It can calculate a proposed text replacement, exact replacement count and SHA-256 checksums without changing WordPress files.

## Deliberately disabled

No MCP `write-file`, `edit-file` or `delete-file` ability is registered. No editing endpoint or automatic file writes are available.

## Next safeguards before commit

- Restrict writes to an explicitly approved staging-only directory, not arbitrary plugins or themes.
- Recheck the original checksum when committing to prevent overwriting concurrent changes.
- Make a backup outside the webroot, use atomic replacement and verify rollback after simulated write failures.
- Deny symlinks and sensitive paths on both preflight and commit.
- Enforce an explicit administrator approval step and Afara's write-mode gate.
- Log results without storing file contents or credentials.
- Validate on a disposable WordPress installation before enabling any MCP mutations.

This milestone is only the safe planning primitive needed for that workflow.
