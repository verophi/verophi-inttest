#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load .env
if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

# --- Common configuration ---

RENOVATE_IMAGE="${RENOVATE_IMAGE:-renovate/renovate:43.249.0}"
LOG_DIR="$ROOT_DIR/out/logs"

# --- Docker daemon check (timeout 30s) ---

docker info >/dev/null 2>&1 &
DOCKER_PID=$!

SECONDS=0
while kill -0 "$DOCKER_PID" 2>/dev/null; do
  if [ "$SECONDS" -ge 30 ]; then
    kill "$DOCKER_PID" 2>/dev/null || true
    wait "$DOCKER_PID" 2>/dev/null || true
    echo "ERROR: Docker daemon is not reachable (timed out after 30s)." >&2
    exit 1
  fi
  sleep 1
done

if ! wait "$DOCKER_PID"; then
  echo "ERROR: Docker daemon is not reachable." >&2
  exit 1
fi

# --- Mode-specific variables ---

MODE="${1:-}"
PLATFORM=""
ENV_ARGS=()

case "$MODE" in
  github)
    if [ -z "${RENOVATE_GITHUB_TOKEN:-}" ] && [ -z "${RENOVATE_GITHUB_APP_ID:-}" ]; then
      echo "ERROR: set RENOVATE_GITHUB_TOKEN or RENOVATE_GITHUB_APP_ID." >&2
      exit 1
    fi

    PLATFORM="github"
    ENV_ARGS+=(-e RENOVATE_REPOSITORIES="${RENOVATE_GITHUB_TEST_FIXTURE_REPO:-verophi/test-fixtures}")

    echo "==> Running Renovate against GitHub ($RENOVATE_IMAGE)..."
    echo "    Repository: ${RENOVATE_GITHUB_TEST_FIXTURE_REPO:-verophi/test-fixtures}"
    ;;

  gitlab)
    if [ -z "${RENOVATE_GITLAB_TOKEN:-}" ]; then
      echo "ERROR: RENOVATE_GITLAB_TOKEN is required for creating MRs." >&2
      exit 1
    fi

    GITLAB_URL="${RENOVATE_GITLAB_URL:-https://gitlab.com}"
    PLATFORM="gitlab"

    ENV_ARGS+=(-e RENOVATE_TOKEN="$RENOVATE_GITLAB_TOKEN")
    ENV_ARGS+=(-e RENOVATE_ENDPOINT="$GITLAB_URL/api/v4")
    ENV_ARGS+=(-e RENOVATE_REPOSITORIES="${RENOVATE_GITLAB_TEST_FIXTURE_REPO:-verophi/test-fixtures}")
    ENV_ARGS+=(-e RENOVATE_GIT_AUTHOR="verophi-bot <bot@verophi.dev>")

    if [ -n "${RENOVATE_GITHUB_COM_TOKEN:-}" ]; then
      ENV_ARGS+=(-e GITHUB_COM_TOKEN="$RENOVATE_GITHUB_COM_TOKEN")
    fi

    echo "==> Running Renovate against GitLab ($RENOVATE_IMAGE)..."
    echo "    Repository: ${RENOVATE_GITLAB_TEST_FIXTURE_REPO:-verophi/test-fixtures}"
    echo "    Endpoint:   $GITLAB_URL/api/v4"
    ;;

  *)
    echo "Usage: $0 {github|gitlab}" >&2
    exit 1
    ;;
esac

# --- GitHub App auth (github mode only) ---

if [ "$PLATFORM" = "github" ]; then
  if [ -n "${RENOVATE_GITHUB_TOKEN:-}" ]; then
    RENOVATE_TOKEN="$RENOVATE_GITHUB_TOKEN"
  else
    echo "    Generating GitHub App installation token..."
    RENOVATE_TOKEN="$(gh token generate \
      --app-id "${RENOVATE_GITHUB_APP_ID}" \
      --installation-id "${RENOVATE_GITHUB_APP_INSTALLATION_ID:-}" \
      --key "$ROOT_DIR/${RENOVATE_GITHUB_APP_KEY_FILE:-verophi-renovate.private-key.pem}" \
      --token-only)"
  fi

  if [ -z "$RENOVATE_TOKEN" ]; then
    echo "ERROR: Failed to obtain a GitHub token." >&2
    exit 1
  fi

  ENV_ARGS+=(-e RENOVATE_TOKEN="$RENOVATE_TOKEN")
  ENV_ARGS+=(-e GITHUB_COM_TOKEN="$RENOVATE_TOKEN")
fi

# --- Execute Renovate ---

LOG_FILE="$LOG_DIR/renovate-${MODE}.ndjson"

mkdir -p "$LOG_DIR"
rm -f "$LOG_FILE"
chmod 777 "$LOG_DIR"

docker run --rm \
  -v "$LOG_DIR:/tmp/renovate-logs" \
  -e RENOVATE_PLATFORM="$PLATFORM" \
  -e RENOVATE_EXECUTION_TIMEOUT="${RENOVATE_EXECUTION_TIMEOUT:-30}" \
  -e LOG_LEVEL=info \
  -e LOG_FILE="/tmp/renovate-logs/renovate-${MODE}.ndjson" \
  -e LOG_FILE_LEVEL=debug \
  -e LOG_FILE_FORMAT=json \
  ${ENV_ARGS[@]+"${ENV_ARGS[@]}"} \
  "$RENOVATE_IMAGE"

echo "==> Done. Log: $LOG_FILE"
