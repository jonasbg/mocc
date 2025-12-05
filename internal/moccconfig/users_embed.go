package moccconfig

import _ "embed"

// defaultUsersYAML contains the embedded fallback users configuration.
// Keep this file in sync with the repository root users.yaml used for Docker.
//
//go:embed users_embed.yaml
var defaultUsersYAML []byte
