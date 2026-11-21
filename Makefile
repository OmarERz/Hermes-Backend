# Quality gate (docs/14 §2). Minimal version from F0.1 (D-072); F0.3 adds import-linter,
# Semgrep, Gitleaks, pip-audit, coverage, verify-full, semgrep, zap and bruno.
.DEFAULT_GOAL := help
SHELL := /bin/bash

.PHONY: help verify lint typecheck test review

help: ## List the available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\n", $$1, $$2}'

verify: lint typecheck test ## Run the quality gate (same command locally and in CI)

lint: ## Formatting and lint (ruff)
	uv run --locked ruff format --check .
	uv run --locked ruff check .

typecheck: ## Strict type checking (mypy)
	uv run --locked mypy

test: ## Unit and integration tests (pytest)
	uv run --locked pytest

# TASK and REVIEWER reach the recipe as environment variables, so quotes in the task title stay intact.
export TASK REVIEWER

review: ## Automatic review by the other agent: make review TASK="F0.1-T1 · ..." REVIEWER=codex|claude
	@test -n "$$TASK" || { echo 'Usage: make review TASK="FNN.M-Tk · description" REVIEWER=codex|claude' >&2; exit 2; }
	@test -f scripts/review.sh || { echo "scripts/review.sh is local-only (D-062) and is not present in this clone" >&2; exit 2; }
	bash scripts/review.sh "$$TASK"
