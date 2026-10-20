# Controlled Elementor editing

Afara supports classic Elementor heading, text-editor, button and image widgets on
existing draft WordPress posts/pages. The integration uses Elementor's document
manager and `Document::save(['elements' => ...])`; it never writes live Elementor
post metadata directly. The tested baseline is Elementor **3.35.0**. Atomic/V4
widgets, templates, global widgets and arbitrary controls are outside this scope.

## Setup and use

1. Install the packaged Afara ZIP, official MCP Adapter 0.7.1+, and Elementor on a
   disposable HTTPS staging site. Set `WP_ENVIRONMENT_TYPE` to `staging`,
   `development`, or `local` in the site's trusted configuration.
2. Enable Afara and set its exact domain lock. Authenticate with an administrator's
   dedicated Application Password. WordPress core handles credential revocation.
3. In Settings, turn off Read-only mode; in Sandbox, leave safe mode. These are
   administrator controls. Writes remain off by default. Existing OAuth grants
   have `afara:read` scope and cannot write, regardless of these switches.
4. Close the Elementor/WordPress editor for the draft. Call
   `afara/elementor-document` with `post_id` to obtain its element tree and SHA-256.
5. Call `afara/elementor-update-text` with `post_id`, `element_id`,
   `expected_sha256` and `text`, or `afara/elementor-update-image` with the same
   identity/checksum fields and an existing media-library `attachment_id`.
6. Re-read after each edit to obtain the next checksum. Preview and review the
   draft in Elementor. Publishing remains an explicit human action in WordPress.

The MCP adapter converts slashes in these ability names to hyphens. The read tool
also requires authenticated administrator and `edit_post` permissions. The two
write tools additionally require a draft post/page, write mode, safe mode off,
HTTPS, and a nonproduction environment. Images must be accessible JPEG, PNG, GIF,
WebP or AVIF attachments with HTTPS URLs. Text is plain UTF-8, bounded to 16384
bytes and escaped; shortcode brackets and dynamically bound fields are rejected.

Each change updates exactly one existing widget, preserving siblings, structure
and other controls. There is no insertion, deletion, publishing, arbitrary CSS,
HTML, URL input, file mutation or PHP execution API. The old file-writing primitive
remains local-only and is not exposed by these tools.

## Backup and failure behavior

WordPress revisions must be enabled. Before saving, Afara forces a revision and
stores/verifies its exact previous `_elementor_data` using the revision metadata
API (ordinary `update_post_meta` would redirect a revision to its parent). The
response includes `revision_id`. These private revision records contain content;
normal WordPress retention policies apply. Audit entries store only identity,
ability and result codes, never document text, images or credentials.

A checksum recheck and per-document Afara lock prevent stale sequential edits and
simultaneous Afara saves. Existing WordPress editor locks are respected. They do
not provide a transaction across all third-party hooks or editor integrations;
keep the document closed while the agent edits. A crashed request can leave an
Afara lock: an administrator must inspect the draft and backup, then remove the
specific `afara_elementor_lock_<post_id>` option before retrying. Never clear locks
while another edit is running.

Save/verification failures enable safe mode and retain the backup revision. Afara
does not blindly overwrite the document during automatic rollback. Inspect the
revision and restore/review through Elementor's history workflow or an authorized
site recovery procedure before re-enabling writes. Test recovery with your exact
Elementor version and add-ons on staging; this milestone is not a production
transaction/recovery guarantee.

## UI and deployment validation

The packaged plugin has shared navigation, responsive forms and explicit access
status. Exact Figma frame matching has not been verified: the supplied Figma URL
is inaccessible from the cloud environment. Screenshots or an accessible export
are required to finish visual comparison.

On your actual staging site test keyboard/mobile layouts, saving settings,
Application Password revocation, real TLS/proxy forwarding, Elementor preview,
revision recovery and all write-denial states before normal deployment.
