#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="${TMPDIR:-/tmp}/shuttle-test"
CONTAINER_NAME="shuttle-test-sshd"
SSH_PORT="${SHUTTLE_TEST_SSH_PORT:-0}"
TEST_PASSPHRASE="shuttle-test-passphrase"
IDENTITY_LABEL="test"

# Use podman if docker daemon is unavailable
if docker info >/dev/null 2>&1; then
    CTR=docker
elif podman info >/dev/null 2>&1; then
    CTR=podman
else
    echo "ERROR: neither docker nor podman is available"
    exit 1
fi

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR/shuttle"

echo "=== shuttle integration test setup ==="
echo "  runtime:   $CTR"
echo "  test dir:  $TEST_DIR"
echo "  container: $CONTAINER_NAME"
echo "  ssh port:  $SSH_PORT"

# ── Step 1: Build shuttle binaries ───────────────────────────────────────

echo ">>> building shuttle + shuttle-keygen..."
cd "$PROJECT_DIR"
cargo build --release --bin shuttle --bin shuttle-keygen -q 2>/dev/null

KEYGEN="$PROJECT_DIR/target/release/shuttle-keygen"

# ── Step 2: Generate test identity + derive SSH public key ───────────────

IDENTITY_FILE="$TEST_DIR/identity.key"

echo ">>> generating test styrene identity..."
PUBKEY=$(STYRENE_PASSPHRASE="$TEST_PASSPHRASE" "$KEYGEN" "$IDENTITY_FILE" "$IDENTITY_LABEL")
echo "  pubkey: $PUBKEY"

# ── Step 3: Build and start sshd container ───────────────────────────────

echo ">>> building sshd container..."
$CTR build -t shuttle-test-sshd -f "$SCRIPT_DIR/Dockerfile.sshd" "$SCRIPT_DIR" -q 2>/dev/null || \
$CTR build -t shuttle-test-sshd -f "$SCRIPT_DIR/Dockerfile.sshd" "$SCRIPT_DIR"

$CTR rm -f "$CONTAINER_NAME" 2>/dev/null || true

if [[ "$SSH_PORT" == "0" ]]; then
    SSH_PORT=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
fi

echo ">>> starting sshd container on port $SSH_PORT..."
$CTR run -d \
    --name "$CONTAINER_NAME" \
    -p "127.0.0.1:${SSH_PORT}:22" \
    shuttle-test-sshd > /dev/null

# Inject the HKDF-derived public key
$CTR exec "$CONTAINER_NAME" sh -c "
    mkdir -p /root/.ssh &&
    chmod 700 /root/.ssh &&
    echo '$PUBKEY' > /root/.ssh/authorized_keys &&
    chmod 600 /root/.ssh/authorized_keys
"

# Create test fixtures
$CTR exec "$CONTAINER_NAME" sh -c "
    echo 'hello from shuttle test' > /tmp/test-file.txt &&
    mkdir -p /tmp/test-dir &&
    echo 'file-a' > /tmp/test-dir/a.txt &&
    echo 'file-b' > /tmp/test-dir/b.txt
"

# Wait for sshd to accept TCP connections from the host.
echo ">>> waiting for sshd..."
ready=false
for _ in $(seq 1 40); do
    if python3 - "$SSH_PORT" <<'PY' >/dev/null 2>&1
import socket, sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.25):
    pass
PY
    then
        ready=true
        break
    fi
    sleep 0.25
done
if [[ "$ready" != "true" ]]; then
    echo "ERROR: sshd did not become reachable on 127.0.0.1:$SSH_PORT" >&2
    $CTR logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi

# ── Step 4: Write shuttle config ─────────────────────────────────────────

cat > "$TEST_DIR/shuttle/hosts.toml" << EOF
[test-local]
address = "127.0.0.1"
user = "root"
port = $SSH_PORT
identity_label = "$IDENTITY_LABEL"
trust_on_first_use = true
EOF

# ── Step 5: Write env file ───────────────────────────────────────────────

cat > "$TEST_DIR/test.env" << EOF
export SHUTTLE_TEST_DIR=$TEST_DIR
export SHUTTLE_SSH_PORT=$SSH_PORT
export SHUTTLE_HOSTS_FILE=$TEST_DIR/shuttle/hosts.toml
export SHUTTLE_KNOWN_HOSTS=$TEST_DIR/shuttle/known_hosts
export SHUTTLE_CONTAINER=$CONTAINER_NAME
export STYRENE_IDENTITY_PATH=$IDENTITY_FILE
export STYRENE_PASSPHRASE=$TEST_PASSPHRASE
EOF

echo ""
echo "=== setup complete ==="
echo "  source $TEST_DIR/test.env"
