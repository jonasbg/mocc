## OS Support

This feature is tested on Debian-based containers (the most common devcontainer base).

## Dependencies

The install script will:
1. Try to download a pre-built binary from GitHub releases
2. Fall back to building from source if no binary is available (requires Go or will install it)

## Post-installation

After installation, the `mocc` binary is available at `/usr/local/bin/mocc`.

If `autostart` is enabled, MOCC will start automatically when you open a terminal in the container.
