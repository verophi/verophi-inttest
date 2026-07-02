# verophi-inttest

E2E test harness for [verophi](https://github.com/verophi/verophi).
Runs the verophi Docker container against real Renovate PRs/MRs and verifies
JSON output against `expectations.yaml`.

## How it works

```
test-fixtures     -> vulnerable packages + renovate.json (GitHub + GitLab)
Renovate          -> creates PRs/MRs from those packages
verophi           -> analyzes SBOM + PRs/MRs -> produces AnalysisResult JSON
verify            -> checks AnalysisResult against expectations.yaml
```

verophi is the system under test. It always runs as a Docker container.

## Structure

```
expectations.yaml         -> expected requests, scores, CVE correlations (SSOT)
testdata/
  sbom-frozen.json        -> committed SBOM fixture (deterministic regression input)
tools/verify/             -> compares verophi output against expectations (exact|drift)
pkg/expectations/         -> Go types + loader for expectations.yaml
scripts/
  renovate.sh             -> run Renovate (github|gitlab mode)
  clean.sh                -> close PRs/MRs + delete branches
  wait-requests.sh        -> wait until Renovate requests settle
out/                      -> generated artifacts (gitignored)
  sboms/                  -> SBOMs from trivy
  results/                -> verophi JSON output
  logs/                   -> Renovate logs
```

## Setup

```bash
cp .env.example .env     # fill in tokens + App credentials
make check               # verify Go compiles, scripts executable
```

For local dev against a locally built verophi image:

```bash
VEROPHI_IMAGE=verophi:dev make test-github
```

## Targets

```
make check            validate setup (build, script permissions)
make sboms            generate SBOMs from test-fixtures
make test-github      run verophi + verify (GitHub); MODE=exact|drift, SBOM_DIR=...
make test-gitlab      run verophi + verify (GitLab);  MODE=exact|drift, SBOM_DIR=...
make drift-github     fresh SBOM + drift verify (GitHub), no clean/renovate
make drift-gitlab     fresh SBOM + drift verify (GitLab),  no clean/renovate
make renovate-github  run Renovate against GitHub (creates PRs)
make renovate-gitlab  run Renovate against GitLab (creates MRs)
make wait-github      wait until open Renovate PRs settle
make wait-gitlab      wait until open Renovate MRs settle
make clean-github     close PRs + delete renovate/* branches
make clean-gitlab     close MRs + delete renovate/* branches
make e2e-github       full cycle: clean -> renovate -> wait -> fresh SBOM -> drift verify
make e2e-gitlab       full cycle: clean -> renovate -> wait -> fresh SBOM -> drift verify
make help             list all targets
```

## Verification modes

`verify` runs in one of two modes:

- `exact` (default): pins every field including scores, metrics, and the full
  uncorrelated advisory list. Run against the committed frozen SBOM so the result
  is deterministic and a failure means verophi changed.
- `drift`: pins only what stays stable across a live trivy/Renovate run, namely
  the schema, the `correlated + uncorrelated == total` invariant, each expected
  change identity and type, and the presence of each known advisory match with
  its occurrence versions. New CVEs and score shifts are tolerated; a vanished
  known correlation fails the run. Used by the live refresh layers.

`test-*` default to `MODE=exact` against `testdata/sbom-frozen.json`. The
`drift-*` and `e2e-*` targets generate a fresh SBOM and verify in drift mode.

## CI

Repo hygiene is separate from the integration layers:

- **Repo CI** (`repo-ci.yml`): build, unit tests, gofmt, vet of this repo's own
  Go code. Runs on pull requests and pushes to main. No platform tokens.
- **Layer 1 regression** (`layer1.yml`, called by `regression.yml`): exact verify
  against the committed frozen SBOM. The steps live in the reusable `layer1.yml`
  (`workflow_call`); `regression.yml` is a thin caller that runs it on pull
  requests here, on a daily schedule, on `workflow_dispatch`, and on a
  `repository_dispatch` (`verophi-image-published`) that verophi's CI fires after
  publishing a new image. verophi's own PR gate calls the same `layer1.yml`
  against an ephemeral image built from the pull request, which is why the logic
  is reusable.
- **Layer 2 daily refresh** (`daily-refresh.yml`): regenerates the SBOM with live
  trivy, verifies the existing requests in drift mode, and on success opens or
  updates the baseline-refresh PR. Read-only on the platforms.
- **Layer 3 weekly refresh** (`weekly-refresh.yml`): clean-slate cycle (recreate
  MRs with Renovate) plus drift verify, Sunday night UTC. Same baseline-refresh
  PR. Destructive, so schedule and manual only.

Both refresh layers regenerate the baseline (frozen SBOM + `expectations.yaml`),
run an exact self-check, and update a single PR on `ci/baseline-refresh`. A human
reviews the diff; merging it becomes the new deterministic baseline. A drift
failure opens no PR and fails the run instead.

Forks do not receive the org secrets. Repo CI still runs on fork pull requests;
the Layer 1 job runs too but fails fast with a clear message, since the E2E layer
needs those secrets. Open the PR from a branch in the repo, not a fork.

## Requirements

- Docker
- Go (see `go.mod`)
- `gh` + `glab` CLIs (see `.mise.toml`); `make renovate-github` also needs a `gh`
  extension providing `gh token generate` (GitHub App installation tokens)
- Tokens (see `.env.example`)

## Status and license

Published for transparency into how verophi is tested. This repo is not intended
for external contributions: the integration layers depend on org secrets and
shared fixtures that forks cannot access.

Licensed under the Apache License 2.0. See `LICENSE`.
