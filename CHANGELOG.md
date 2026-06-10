# Changelog

All notable changes to this project will be documented in this file.

The format is based on "Keep a Changelog" and this project adheres to Semantic Versioning.

## [v0.1.7] - 2026-06-10

### Added
- `client_secret_basic` support at `/token`: `client_id` is read from HTTP Basic auth with form fallback, matching what most OIDC client libraries send by default.
- `?aud=` query parameter on `/token/{email}` to mint ID tokens with an audience without a JSON body.
- `grant_types_supported` in the discovery document.
- Spec-deviation `[warn]` logs for missing/wrong `grant_type` and `response_type`, mismatched `client_id`, and PKCE `plain` usage — the flow always proceeds.

### Changed
- Mismatched `client_id` at `/token` now warns and proceeds instead of rejecting; the token's `aud` always comes from the validated `/authorize` request.
- Login form field renamed from `sub` to `email`; the old name is still accepted.
- Dev Container Feature reference moved from `ghcr.io/jonasbg/mocc/mocc:1` to `ghcr.io/jonasbg/mocc-feature/mocc:1`. Update `devcontainer.json` files accordingly; previously published versions remain resolvable at the old path.

### Fixed
- Issuer derivation now honors TLS and `X-Forwarded-Proto`/`X-Forwarded-Host` everywhere, so `iss` and the discovery document match what clients see behind an HTTPS proxy.
- `/token` errors are RFC 6749 JSON (`{"error":"invalid_grant",…}`) and `expires_in` is a number, fixing strict client parsers.
- Expired authorization codes are purged instead of accumulating for the lifetime of the process.
- Stopped the Dev Container Feature publish from clobbering the Docker image's `latest` tag. The feature now publishes under a dedicated namespace (`ghcr.io/jonasbg/mocc-feature/mocc`) so its `devcontainer-collection.json` artifact no longer overwrites `ghcr.io/jonasbg/mocc:latest`, which had been breaking `docker pull` / `docker compose pull`.

## [v0.1.6] - 2026-05-09

### Changed
- Refactored server internals into focused auth, assets, logging, middleware, and skills modules.
- Reduced duplicated token claim, user lookup, template rendering, PKCE, and static asset handling logic.
- Bumped the Dev Container Feature metadata to `1.0.3`.

### Fixed
- Avoided sharing the HTTP server startup error variable across goroutines.
- Handled authorization code entropy generation errors instead of ignoring them.
- Rejected static asset path traversal attempts.
  
## [v0.1.3] - 2025-10-20

TL;DR: Better visibility, richer logs, and a real /userinfo — smoother local OIDC dev all around.

### Added
- Version display with `--version` flag
- Improved startup banner formatting
- `/userinfo` endpoint for user claims retrieval

### Changed
- Enhanced request logging with color-coded output and detailed formatting

## [0.0.1] - 2025-10-17

This is the first release of a fast, easy OIDC mock server that makes development against OpenID Connect (OIDC) simple and friction-less. It is intended for local development and testing only — do not use this in production.

### Added
- 🚀 : *OIDC* OIDC mock server supporting the authorization code flow and issuing RS256-signed ID tokens for testing.
- 📖 : *Docs* README improvements — clearer instructions, configuration examples, and updated screenshots/images.
- 👥 : *Login UX* Dynamic login page with user selection, user initials display, and improved templates and styles.
- 🐳 : *Docker & CI* Docker image CI/CD workflow added for automated builds and pushes.
- 🎨 : *UI & Templates* Improved templates and static assets: layout refinements, CSS tweaks, and template rendering fixes.

### Notes
- 🔎 : See the repository commit history for more granular details and individual commit messages.

MOCC is a minimal OpenID Connect Core (OIDC) provider designed for local development and testing. It offers a simple, self-contained server with user management, OIDC endpoints, and easy configuration via flags or environment variables. MOCC helps developers simulate authentication flows and integrate OIDC in their applications without relying on external identity providers.
