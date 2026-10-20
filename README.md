# Afara

Afara bridges AI agents and WordPress using the WordPress Abilities API and MCP.

> Early development. **Do not deploy to production.** The plugin is disabled by default; no arbitrary PHP execution is available in the foundation milestone.

Design reference: [Afara WordPress Admin UI](https://www.figma.com/design/ZdjhCnYHKNa3z9bsKvHMl3/Afara-%E2%80%94-WordPress-Admin-UI?node-id=15-274).

Development happens on feature branches and is proposed to `main` via pull requests.

## MCP integration

Requires WordPress 6.9+, PHP 8.1+, and the separately activated official WordPress
MCP Adapter 0.7.1+. Afara remains off by default. Its dedicated authenticated HTTPS
server exposes site/source inspection and guarded Elementor draft-editing abilities. No arbitrary PHP execution or file mutations are included.
See [Elementor setup and restrictions](docs/ELEMENTOR.md) for text/image editing.

See [connection setup and official API references](docs/MCP.md),
[architecture](docs/ARCHITECTURE.md) and [tests/staging checklist](docs/TESTING.md).
Run all isolated tests with `bash tests/run.sh`; GitHub Actions also runs real
WordPress HTTP integration checks with the official adapter.
