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

MODE="${1:-}"

# --- GitHub cleanup ---

clean_github() {
  local repo="${RENOVATE_GITHUB_TEST_FIXTURE_REPO:-verophi/test-fixtures}"

  if [ -z "${RENOVATE_GITHUB_APP_ID:-}" ]; then
    echo "ERROR: RENOVATE_GITHUB_APP_ID is required" >&2
    exit 1
  fi

  export GH_PAGER=""

  # Generate installation token for gh CLI
  export GH_TOKEN
  GH_TOKEN="$(gh token generate \
    --app-id "${RENOVATE_GITHUB_APP_ID}" \
    --installation-id "${RENOVATE_GITHUB_APP_INSTALLATION_ID:-}" \
    --key "$ROOT_DIR/${RENOVATE_GITHUB_APP_KEY_FILE:-verophi-renovate.private-key.pem}" \
    --token-only)"

  echo "==> Closing Renovate PRs on GitHub ($repo)..."
  local pr_count=0
  for number in $(gh pr list --repo "$repo" --label renovate --json number -q '.[].number'); do
    echo "    Closing PR #$number + deleting branch"
    gh pr close "$number" --repo "$repo" --delete-branch
    ((pr_count++))
  done

  echo "==> Deleting remaining renovate/* branches on GitHub..."
  local branch_count=0
  for branch in $(gh api "repos/$repo/branches" --paginate -q '.[].name | select(startswith("renovate/"))'); do
    echo "    Deleting branch $branch"
    gh api --method DELETE "repos/$repo/git/refs/heads/$branch"
    ((branch_count++))
  done

  echo "==> Done. Closed $pr_count PRs, deleted $branch_count branches."
}

# --- GitLab cleanup ---

clean_gitlab() {
  local repo="${RENOVATE_GITLAB_TEST_FIXTURE_REPO:-verophi/test-fixtures}"

  if [ -z "${RENOVATE_GITLAB_TOKEN:-}" ]; then
    echo "ERROR: RENOVATE_GITLAB_TOKEN is required" >&2
    exit 1
  fi

  # glab uses GITLAB_TOKEN env var for auth, GH_PAGER/GLAMOUR_STYLE disable pager
  export GITLAB_TOKEN="$RENOVATE_GITLAB_TOKEN"
  export GLAB_PAGER=""

  echo "==> Closing Renovate MRs on GitLab ($repo)..."
  local mr_count=0
  for iid in $(glab mr list --source-branch "renovate/" --state opened -F json -R "$repo" 2>/dev/null | jq -r '.[].iid'); do
    echo "    Closing MR !$iid"
    glab mr close "$iid" -R "$repo" -y
    ((mr_count++))
  done

  echo "==> Deleting renovate/* branches on GitLab..."
  local branch_count=0
  for branch in $(glab api "projects/:id/repository/branches?search=renovate/&per_page=100" -R "$repo" --paginate 2>/dev/null | jq -r '.[].name'); do
    local encoded_branch
    encoded_branch="$(printf '%s' "$branch" | jq -Rr @uri)"
    echo "    Deleting branch $branch"
    glab api --method DELETE "projects/:id/repository/branches/$encoded_branch" -R "$repo"
    ((branch_count++))
  done

  echo "==> Done. Closed $mr_count MRs, deleted $branch_count branches."
}

# --- Main ---

case "$MODE" in
  github)
    clean_github
    ;;
  gitlab)
    clean_gitlab
    ;;
  all)
    clean_github
    clean_gitlab
    ;;
  *)
    echo "Usage: $0 {github|gitlab|all}" >&2
    exit 1
    ;;
esac
