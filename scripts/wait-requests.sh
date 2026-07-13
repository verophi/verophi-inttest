#!/usr/bin/env bash
# wait-requests.sh polls the fixture repo until the number of open Renovate
# change requests stabilizes, so the full cycle never runs verophi against a
# half-created MR/PR set. Renovate creates requests asynchronously; this script
# treats the count as settled once it stays constant across several consecutive
# polls (and meets a minimum), then returns. It is read-only.
#
# Usage: wait-requests.sh {github|gitlab}
#
# Tunables (env):
#   WAIT_INTERVAL       seconds between polls            (default 20)
#   WAIT_TIMEOUT        total seconds before giving up   (default 900)
#   WAIT_STABLE_CHECKS  consecutive equal polls = stable (default 3)
#   WAIT_MIN_REQUESTS   minimum count to accept as ready (default 1)
#
# Exit codes:
#   0: request count settled
#   1: timed out, or usage/auth error
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

INTERVAL="${WAIT_INTERVAL:-20}"
TIMEOUT="${WAIT_TIMEOUT:-900}"
STABLE_CHECKS="${WAIT_STABLE_CHECKS:-3}"
MIN_REQUESTS="${WAIT_MIN_REQUESTS:-1}"

# count_github prints the number of open Renovate PRs.
count_github() {
  local repo="${RENOVATE_GITHUB_TEST_FIXTURE_REPO:-verophi/test-fixtures}"
  gh pr list --repo "$repo" --label renovate --state open --limit 200 --json number --jq 'length'
}

# count_gitlab prints the number of open Renovate MRs.
count_gitlab() {
  local repo="${RENOVATE_GITLAB_TEST_FIXTURE_REPO:-verophi/test-fixtures}"
  glab mr list -P 100 -F json -R "$repo" 2>/dev/null \
    | jq '[.[] | select(.source_branch | startswith("renovate/"))] | length'
}

setup_github() {
  if [ -z "${RENOVATE_GITHUB_APP_ID:-}" ]; then
    echo "ERROR: RENOVATE_GITHUB_APP_ID is required" >&2
    exit 1
  fi
  export GH_PAGER=""
  export GH_TOKEN
  GH_TOKEN="$(gh token generate \
    --app-id "${RENOVATE_GITHUB_APP_ID}" \
    --installation-id "${RENOVATE_GITHUB_APP_INSTALLATION_ID:-}" \
    --key "$ROOT_DIR/${RENOVATE_GITHUB_APP_KEY_FILE:-verophi-renovate.private-key.pem}" \
    --token-only)"
}

setup_gitlab() {
  if [ -z "${RENOVATE_GITLAB_TOKEN:-}" ]; then
    echo "ERROR: RENOVATE_GITLAB_TOKEN is required" >&2
    exit 1
  fi
  export GITLAB_TOKEN="$RENOVATE_GITLAB_TOKEN"
  export GLAB_PAGER=""
}

PLATFORM="${1:-}"
case "$PLATFORM" in
  github)
    setup_github
    count_fn=count_github
    noun="PRs"
    ;;
  gitlab)
    setup_gitlab
    count_fn=count_gitlab
    noun="MRs"
    ;;
  *)
    echo "Usage: $0 {github|gitlab}" >&2
    exit 1
    ;;
esac

echo "==> Waiting for Renovate $noun to settle on $PLATFORM"
echo "    interval=${INTERVAL}s timeout=${TIMEOUT}s stable_checks=${STABLE_CHECKS} min=${MIN_REQUESTS}"

elapsed=0
prev=-1
stable=0

while :; do
  count="$("$count_fn" || echo "")"
  if [ -z "$count" ]; then
    echo "    [${elapsed}s] count query failed, retrying"
    count=-1
  fi

  if [ "$count" -ge "$MIN_REQUESTS" ] && [ "$count" -eq "$prev" ]; then
    stable=$((stable + 1))
  else
    stable=0
  fi
  echo "    [${elapsed}s] open=$count stable=$stable/$STABLE_CHECKS"

  if [ "$stable" -ge "$STABLE_CHECKS" ]; then
    echo "==> Settled: $count open $noun on $PLATFORM."
    exit 0
  fi

  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "ERROR: timed out after ${TIMEOUT}s; last count=$count (min=$MIN_REQUESTS)." >&2
    exit 1
  fi

  prev="$count"
  sleep "$INTERVAL"
  elapsed=$((elapsed + INTERVAL))
done
