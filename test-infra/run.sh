#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${TMPDIR:-/tmp}/shuttle-test/test.env"

cleanup() {
    "$SCRIPT_DIR/teardown.sh"
}
trap cleanup EXIT INT TERM

"$SCRIPT_DIR/setup.sh"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: integration setup did not create $ENV_FILE" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

cd "$PROJECT_DIR"
exec cargo test --test integration -- --test-threads=1
