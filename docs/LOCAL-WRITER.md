# Local editing and external backups

The local editing prototype remains **unregistered**: no WordPress admin write endpoint or MCP write ability exists.

The caller must supply two **existing, separate directories** when constructing `LocalAtomicWriter($editRoot, $backupRoot)`. The backup directory must be provisioned **outside the webroot by the operator**; this library cannot infer a site's public document root. It rejects symlinked roots and backups nested inside the edit workspace (or vice versa). Backups are created in the separate directory with restrictive permissions and checked on restore.

Every write checks the expected SHA-256, preserves an original backup, stages changes in the edit directory, and uses a same-directory rename. Restore checks the current checksum before writing a previous backup as another version.

**Not production-ready:** The lock is advisory, filesystem TOCTOU races remain, crash durability and orphan cleanup need work, and backup storage is not automatically verified as outside the webroot. Only disposable, trusted local test folders should be used. Build an explicit deployment configuration and reliable recovery tests before any MCP mutation is introduced.
