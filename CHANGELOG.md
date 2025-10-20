# Changelog

All notable changes to this project will be documented in this file.

The format is based on "Keep a Changelog" and this project adheres to Semantic Versioning.

## [Unreleased]
- ...existing code...
  
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