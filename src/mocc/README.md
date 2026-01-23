# MOCC (Minimal OpenID Connect Core)

A lightweight mock OpenID Connect provider for local development and testing.

## Usage

Add this feature to your `devcontainer.json`:

```json
{
    "features": {
        "ghcr.io/jonasbg/mocc/mocc:1": {}
    }
}
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `version` | string | `latest` | Version of MOCC to install (e.g., `latest`, `v1.0.0`) |
| `port` | string | `9999` | Port for MOCC to listen on |
| `autostart` | boolean | `false` | Automatically start MOCC when the container starts |
| `users` | string | `` | Path to custom users.yaml file (e.g., `/config/users.yaml`) |

### Example with options

```json
{
    "features": {
        "ghcr.io/jonasbg/mocc/mocc:1": {
            "version": "latest",
            "port": "9999",
            "autostart": true
        }
    }
}
```

### Custom users file

To use your own users configuration from your repository, point to it within the workspace:

```json
{
    "features": {
        "ghcr.io/jonasbg/mocc/mocc:1": {
            "users": "${containerWorkspaceFolder}/users.yaml",
            "autostart": true
        }
    }
}
```

Alternatively, set the `MOCC_USERS` environment variable via `containerEnv`:

```json
{
    "containerEnv": {
        "MOCC_USERS": "${containerWorkspaceFolder}/users.yaml"
    },
    "features": {
        "ghcr.io/jonasbg/mocc/mocc:1": {
            "autostart": true
        }
    }
}
```

## Running MOCC

After the feature is installed, you can run MOCC manually:

```bash
# Start with defaults (localhost:9999)
mocc

# Start on all interfaces (for access from host)
mocc --host 0.0.0.0 --port 9999

# Use custom users file
mocc --users /path/to/users.yaml
```

## Endpoints

Once running, MOCC exposes standard OIDC endpoints:

| Endpoint | Description |
|----------|-------------|
| `http://localhost:9999/` | Landing page |
| `http://localhost:9999/.well-known/openid-configuration` | OIDC Discovery |
| `http://localhost:9999/authorize` | Authorization endpoint |
| `http://localhost:9999/token` | Token endpoint |
| `http://localhost:9999/jwks.json` | JSON Web Key Set |
| `http://localhost:9999/userinfo` | User info endpoint |

## Quick Token Generation

For testing, you can generate tokens directly:

```bash
curl http://localhost:9999/token/alice.admin@test.local
```

## Port Forwarding

Remember to add port forwarding in your `devcontainer.json`:

```json
{
    "forwardPorts": [9999],
    "features": {
        "ghcr.io/jonasbg/mocc/mocc:1": {
            "autostart": true
        }
    }
}
```

## More Information

- [MOCC Repository](https://github.com/jonasbg/mocc)
- [DevContainer Features Documentation](https://containers.dev/implementors/features/)
