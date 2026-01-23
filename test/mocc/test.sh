#!/bin/bash
set -e

# Test that mocc is installed and runnable
echo "Testing MOCC installation..."

# Check binary exists
if ! command -v mocc &> /dev/null; then
    echo "FAIL: mocc command not found"
    exit 1
fi
echo "PASS: mocc binary found at $(which mocc)"

# Check help works
if ! mocc --help &> /dev/null; then
    echo "FAIL: mocc --help failed"
    exit 1
fi
echo "PASS: mocc --help works"

# Start mocc in background and test endpoints
mocc --host 127.0.0.1 --port 9998 &
MOCC_PID=$!
sleep 2

# Test OIDC discovery endpoint
if curl -sf http://127.0.0.1:9998/.well-known/openid-configuration > /dev/null; then
    echo "PASS: OIDC discovery endpoint works"
else
    echo "FAIL: OIDC discovery endpoint not responding"
    kill $MOCC_PID 2>/dev/null || true
    exit 1
fi

# Test JWKS endpoint
if curl -sf http://127.0.0.1:9998/jwks.json > /dev/null; then
    echo "PASS: JWKS endpoint works"
else
    echo "FAIL: JWKS endpoint not responding"
    kill $MOCC_PID 2>/dev/null || true
    exit 1
fi

# Cleanup
kill $MOCC_PID 2>/dev/null || true

echo ""
echo "All tests passed!"
