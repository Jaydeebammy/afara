# Local atomic writer experiment

This is a **non-registered** local editing primitive. It is not an MCP ability, WordPress admin endpoint, or PHP executor.

The implementation is restricted to existing simple .txt filenames inside a caller-selected directory. It uses a before-checksum, advisory lock, local backup and temporary same-directory rename, plus an explicit restore operation. The backup remains in the workspace for review.

**Do not use on untrusted shared filesystems or production sites.** Advisory locks do not defend against other processes modifying the same paths. Backup files would need to move outside the webroot for an actual deployment. Crash durability, quota enforcement, directory symlink races, cleanup, ownership changes and file-permission policy remain to be designed.

Before enabling any remote editing, add explicit administrator approval, a dedicated safe workspace, storage outside the webroot, robust filesystem race protections, audit integration, and end-to-end WordPress tests. This milestone does not claim those properties.
