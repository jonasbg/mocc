#!/bin/bash
set -e

# MOCC DevContainer Feature Install Script
# https://github.com/jonasbg/mocc

VERSION="${VERSION:-latest}"
PORT="${PORT:-9999}"
AUTOSTART="${AUTOSTART:-false}"
USERS="${USERS:-}"

echo "Installing MOCC (Minimal OpenID Connect Core)..."
echo "  Version: ${VERSION}"
echo "  Port: ${PORT}"
echo "  Autostart: ${AUTOSTART}"
echo "  Users: ${USERS:-<default>}"

# Detect architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo "Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "${OS}" in
    linux) OS="linux" ;;
    darwin) OS="darwin" ;;
    *)
        echo "Unsupported OS: ${OS}"
        exit 1
        ;;
esac

echo "Detected platform: ${OS}/${ARCH}"

# Determine download URL
REPO="jonasbg/mocc"
if [ "${VERSION}" = "latest" ]; then
    RELEASE_URL="https://api.github.com/repos/${REPO}/releases/latest"
    VERSION_TAG=$(curl -s "${RELEASE_URL}" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
    if [ -z "${VERSION_TAG}" ]; then
        echo "Failed to fetch latest version. Falling back to building from source..."
        VERSION_TAG="main"
    fi
else
    VERSION_TAG="${VERSION}"
fi

echo "Installing version: ${VERSION_TAG}"

# Try to download pre-built binary
BINARY_NAME="mocc-${OS}-${ARCH}"
if [ "${OS}" = "windows" ]; then
    BINARY_NAME="${BINARY_NAME}.exe"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION_TAG}/${BINARY_NAME}.tar.gz"

# Create install directory
INSTALL_DIR="/usr/local/bin"
mkdir -p "${INSTALL_DIR}"

# Try downloading release binary
echo "Attempting to download from: ${DOWNLOAD_URL}"
if curl -fsSL "${DOWNLOAD_URL}" -o /tmp/mocc.tar.gz 2>/dev/null; then
    echo "Extracting binary..."
    tar -xzf /tmp/mocc.tar.gz -C /tmp
    mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/mocc"
    chmod +x "${INSTALL_DIR}/mocc"
    rm -f /tmp/mocc.tar.gz
    echo "MOCC installed successfully from release binary."
else
    echo "Pre-built binary not available. Building from source..."

    # Check if Go is available
    if ! command -v go &> /dev/null; then
        echo "Go is not installed. Installing Go..."
        # Install Go if not present
        GO_VERSION="1.22.0"
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.${OS}-${ARCH}.tar.gz" -o /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        rm -f /tmp/go.tar.gz
    fi

    # Clone and build
    TEMP_DIR=$(mktemp -d)
    cd "${TEMP_DIR}"

    git clone --depth 1 --branch "${VERSION_TAG}" "https://github.com/${REPO}.git" mocc 2>/dev/null || \
    git clone --depth 1 "https://github.com/${REPO}.git" mocc

    cd mocc
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "${INSTALL_DIR}/mocc" ./cmd/mocc

    # Cleanup
    cd /
    rm -rf "${TEMP_DIR}"

    echo "MOCC built and installed successfully from source."
fi

# Verify installation
if command -v mocc &> /dev/null; then
    echo "MOCC installed at: $(which mocc)"
    mocc --help 2>/dev/null | head -5 || true
else
    echo "Warning: mocc not found in PATH after installation"
fi

# Setup autostart if enabled
if [ "${AUTOSTART}" = "true" ]; then
    echo "Setting up autostart..."

    # Create a startup script
    cat > /usr/local/bin/mocc-start.sh << 'STARTUP'
#!/bin/bash
MOCC_ARGS="--host 0.0.0.0 --port ${MOCC_PORT:-9999}"
if [ -n "${MOCC_USERS}" ]; then
    MOCC_ARGS="${MOCC_ARGS} --users ${MOCC_USERS}"
fi
nohup mocc ${MOCC_ARGS} > /tmp/mocc.log 2>&1 &
echo "MOCC started on port ${MOCC_PORT:-9999}"
STARTUP
    chmod +x /usr/local/bin/mocc-start.sh

    # Add to bashrc for interactive shells
    if [ -f /etc/bash.bashrc ]; then
        echo '# Auto-start MOCC' >> /etc/bash.bashrc
        echo 'if ! pgrep -x "mocc" > /dev/null; then /usr/local/bin/mocc-start.sh; fi' >> /etc/bash.bashrc
    fi

    echo "MOCC will auto-start when the container starts."
fi

echo ""
echo "Installation complete!"
echo "Run 'mocc --help' for usage information."
echo "Default endpoint: http://localhost:${PORT}"
