-include .env

# --- Config ---

VEROPHI_IMAGE ?= ghcr.io/verophi/verophi:latest
VEROPHI_TRIVY_IMAGE ?= ghcr.io/verophi/verophi-trivy:latest
FIXTURES_REPO_PATH ?= ../test-fixtures
SBOM_OUT_DIR := $(CURDIR)/out/sboms
PACKAGES_DIR := $(FIXTURES_REPO_PATH)/packages
RESULT_DIR := $(CURDIR)/out/results

EXPECTATIONS_PATH ?= expectations.yaml

# Directory mounted into the verophi container as /data. Defaults to the
# committed frozen SBOM fixture, so the regression gate is deterministic. The
# full cycle overrides it to the freshly generated $(SBOM_OUT_DIR).
SBOM_DIR ?= $(CURDIR)/testdata

# verify mode: exact (deterministic gate) or drift (live full cycle, tolerates
# new CVEs but fails when a known correlation disappears).
MODE ?= exact

VEROPHI_GITHUB_TOKEN ?=
VEROPHI_GITLAB_TOKEN ?=
VEROPHI_GITLAB_URL ?=

RENOVATE_GITHUB_APP_ID ?=
RENOVATE_GITHUB_APP_KEY_FILE ?=
RENOVATE_GITHUB_TEST_FIXTURE_REPO ?= verophi/test-fixtures

RENOVATE_GITLAB_TOKEN ?=
RENOVATE_GITLAB_TEST_FIXTURE_REPO ?= verophi/test-fixtures

RENOVATE_IMAGE ?= renovate/renovate:43.249.0

export VEROPHI_IMAGE VEROPHI_TRIVY_IMAGE VEROPHI_GITHUB_TOKEN VEROPHI_GITLAB_TOKEN VEROPHI_GITLAB_URL

# --- Validation ---

.PHONY: check
check: ## Validate basic setup (build, permissions)
	@echo "Checking Go module..."
	@go build ./... || (echo "ERROR: go build ./... failed" >&2; exit 1)
	@echo "Checking script permissions..."
	@for script in scripts/*; do \
		if [ -f "$$script" ] && [ ! -x "$$script" ]; then \
			echo "ERROR: $$script is not executable" >&2; \
			exit 1; \
		fi; \
	done
	@echo "All checks passed."

# --- E2E Tests ---

.PHONY: test-github test-gitlab test-all
test-github: ## Run verophi against GitHub PRs and verify (MODE=exact|drift)
	@mkdir -p $(RESULT_DIR)
	docker run --rm \
		-v $(SBOM_DIR):/data:ro \
		-e VEROPHI_GITHUB_TOKEN \
		$(VEROPHI_IMAGE) analyze \
			--sbom /data/sbom-frozen.json \
			--github-repo $(RENOVATE_GITHUB_TEST_FIXTURE_REPO) \
			--format json --no-color > $(RESULT_DIR)/github.json
	go run ./tools/verify --expectations $(EXPECTATIONS_PATH) --result $(RESULT_DIR)/github.json --mode $(MODE)

test-gitlab: ## Run verophi against GitLab MRs and verify (MODE=exact|drift)
	@mkdir -p $(RESULT_DIR)
	docker run --rm \
		-v $(SBOM_DIR):/data:ro \
		-e VEROPHI_GITLAB_TOKEN \
		$(if $(VEROPHI_GITLAB_URL),-e VEROPHI_GITLAB_URL) \
		$(VEROPHI_IMAGE) analyze \
			--sbom /data/sbom-frozen.json \
			--gitlab-project $(RENOVATE_GITLAB_TEST_FIXTURE_REPO) \
			--format json --no-color > $(RESULT_DIR)/gitlab.json
	go run ./tools/verify --expectations $(EXPECTATIONS_PATH) --result $(RESULT_DIR)/gitlab.json --mode $(MODE)

test-all: test-github test-gitlab ## Run both platform tests

# --- Renovate (create real PRs/MRs) ---

.PHONY: renovate-github renovate-gitlab
renovate-github: ## Run Renovate against GitHub (creates PRs)
	@test -n "$(RENOVATE_GITHUB_TOKEN)$(RENOVATE_GITHUB_APP_ID)" || (echo "ERROR: set RENOVATE_GITHUB_TOKEN or RENOVATE_GITHUB_APP_ID" >&2; exit 1)
	@./scripts/renovate.sh github

renovate-gitlab: ## Run Renovate against GitLab (creates MRs)
	@test -n "$(RENOVATE_GITLAB_TOKEN)" || (echo "ERROR: RENOVATE_GITLAB_TOKEN is required" >&2; exit 1)
	@./scripts/renovate.sh gitlab

# --- SBOM Generation ---

.PHONY: sboms validate-sboms
sboms: ## Generate the frozen SBOM from test-fixtures packages (via verophi-trivy image)
	@mkdir -p $(SBOM_OUT_DIR)
	@chmod 777 $(SBOM_OUT_DIR)
	docker run --rm \
		-v $(abspath $(PACKAGES_DIR)):/packages:ro \
		-v $(SBOM_OUT_DIR):/out \
		$(VEROPHI_TRIVY_IMAGE) \
		"trivy fs --format cyclonedx --scanners vuln --output /out/sbom-frozen.json /packages"
	@$(MAKE) validate-sboms

validate-sboms: ## Validate generated SBOM JSON files
	@for file in $(SBOM_OUT_DIR)/*.json; do \
		jq empty "$$file"; \
	done

# --- Cleanup ---

.PHONY: clean-github clean-gitlab clean-all
clean-github: ## Delete all Renovate PRs + branches on GitHub
	@./scripts/clean.sh github

clean-gitlab: ## Delete all Renovate MRs + branches on GitLab
	@./scripts/clean.sh gitlab

clean-all: ## Delete all Renovate PRs/MRs on both platforms
	@./scripts/clean.sh all

# --- Wait for Renovate to settle ---

.PHONY: wait-github wait-gitlab
wait-github: ## Wait until open Renovate PRs on GitHub settle
	@./scripts/wait-requests.sh github

wait-gitlab: ## Wait until open Renovate MRs on GitLab settle
	@./scripts/wait-requests.sh gitlab

# --- Drift verification (fresh SBOM, existing requests) ---

.PHONY: drift-github drift-gitlab drift-all
drift-github: ## Generate a fresh SBOM and verify GitHub in drift mode (no clean/renovate)
	@$(MAKE) sboms
	@$(MAKE) test-github SBOM_DIR=$(SBOM_OUT_DIR) MODE=drift

drift-gitlab: ## Generate a fresh SBOM and verify GitLab in drift mode (no clean/renovate)
	@$(MAKE) sboms
	@$(MAKE) test-gitlab SBOM_DIR=$(SBOM_OUT_DIR) MODE=drift

drift-all: ## One fresh SBOM, drift verify both platforms
	@$(MAKE) sboms
	@$(MAKE) test-github SBOM_DIR=$(SBOM_OUT_DIR) MODE=drift
	@$(MAKE) test-gitlab SBOM_DIR=$(SBOM_OUT_DIR) MODE=drift

# --- Seed (clean slate: close + recreate PRs/MRs, no drift) ---

.PHONY: seed-github seed-gitlab seed-all
seed-github: ## Clean slate on GitHub: close existing PRs/branches, run Renovate, wait to settle
	@$(MAKE) clean-github
	@$(MAKE) renovate-github
	@$(MAKE) wait-github

seed-gitlab: ## Clean slate on GitLab: close existing MRs/branches, run Renovate, wait to settle
	@$(MAKE) clean-gitlab
	@$(MAKE) renovate-gitlab
	@$(MAKE) wait-gitlab

seed-all: ## Clean slate on both platforms
	@$(MAKE) seed-github
	@$(MAKE) seed-gitlab

# --- Full E2E Cycle (seed + drift; local use) ---

.PHONY: e2e-github e2e-gitlab e2e-all
e2e-github: ## Full cycle (GitHub): seed + drift verify
	@$(MAKE) seed-github
	@$(MAKE) drift-github

e2e-gitlab: ## Full cycle (GitLab): seed + drift verify
	@$(MAKE) seed-gitlab
	@$(MAKE) drift-gitlab

e2e-all: ## Full cycle on both platforms
	@$(MAKE) e2e-github
	@$(MAKE) e2e-gitlab

# --- Help ---

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'
