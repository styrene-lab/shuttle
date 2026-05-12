#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${1:-shuttle-test-sshd}"

if docker info >/dev/null 2>&1; then
    CTR=docker
elif podman info >/dev/null 2>&1; then
    CTR=podman
else
    echo "no container runtime found"
    exit 0
fi

echo ">>> stopping container $CONTAINER_NAME..."
$CTR rm -f "$CONTAINER_NAME" 2>/dev/null || true
echo "done."
