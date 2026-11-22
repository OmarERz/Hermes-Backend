# Quality gate (docs/14 §2): F0.1 minimal version (D-072) extended in F0.3 with import-linter, coverage,
# Semgrep, Gitleaks, pip-audit, verify-full and the zap and bruno placeholders.
.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: help verify lint typecheck boundaries test coverage semgrep secrets audit verify-full zap bruno review

help: ## List the available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\n", $$1, $$2}'

verify: lint typecheck boundaries test coverage semgrep secrets audit ## Run the quality gate (same command locally and in CI)

lint: ## Formatting and lint (ruff)
	uv run --locked ruff format --check .
	uv run --locked ruff check .

typecheck: ## Strict type checking (mypy)
	uv run --locked mypy
	uv run --locked mypy --package-root=. scripts/check_coverage.py

boundaries: ## Package boundary contracts (import-linter)
	uv run --locked lint-imports

test: ## Unit and integration tests (pytest), writes coverage.json
	uv run --locked pytest --cov --cov-report=json --cov-report=term-missing:skip-covered

coverage: ## Coverage gate: 80% global, 95% core (needs make test first)
	uv run --locked python scripts/check_coverage.py

# Semgrep CE in Docker (docs/14 §3.2). Registry packs: python, owasp-top-ten, secrets, fastapi.
# Mounted read-only; --no-git-ignore keeps it working in git worktrees (the .git file points outside the mount).
SEMGREP_IMAGE ?= semgrep/semgrep:latest
GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

semgrep: ## Semgrep CE (Docker): registry packs + .semgrep/ project rules, fails on WARNING/ERROR
	docker run --rm -v "$(CURDIR):/src:ro" -w /src $(SEMGREP_IMAGE) semgrep scan \
	  --config p/python --config p/owasp-top-ten --config p/secrets --config p/fastapi \
	  --config /src/.semgrep/ --metrics=off --no-git-ignore \
	  --error --severity WARNING --severity ERROR .

# Scans the working tree (tracked and untracked files, minus ignored ones): the file list is streamed
# as a tar into the container, so caches and virtualenvs are not scanned and no temp dir is needed.
secrets: ## Gitleaks (Docker, pinned by tag and digest) on the working tree
	git ls-files -z --cached --others --exclude-standard | tar --null --ignore-failed-read -T - -cf - | \
	  docker run --rm -i --entrypoint sh $(GITLEAKS_IMAGE) -c \
	  'mkdir /work && tar -xf - -C /work && gitleaks dir /work --redact --no-banner -v'

audit: ## pip-audit on the locked dependencies
	uv export --locked --no-hashes --no-emit-project --format requirements-txt | uvx pip-audit --no-deps --disable-pip -r /dev/stdin

verify-full: verify ## Full gate before closing a feature: verify + Schemathesis + adversarial suite
	@echo "Schemathesis: not available until F0.5 (needs the OpenAPI of the API); skipped."
	@echo "Adversarial suite (E1-E22): not available until F6 (needs the judge); skipped."

zap: ## OWASP ZAP against the API in Docker (placeholder, arrives in F12)
	@echo "make zap is a placeholder: OWASP ZAP is wired in F12 (security hardening)."

bruno: ## Bruno API collection (placeholder, arrives in F0.7)
	@echo "make bruno is a placeholder: the Bruno collection is created in F0.7."

# TASK and REVIEWER reach the recipe as environment variables, so quotes in the task title stay intact.
export TASK REVIEWER

review: ## Automatic review by the other agent: make review TASK="F0.1-T1 · ..." REVIEWER=codex|claude
	@test -n "$$TASK" || { echo 'Usage: make review TASK="FNN.M-Tk · description" REVIEWER=codex|claude' >&2; exit 2; }
	@test -f scripts/review.sh || { echo "scripts/review.sh is local-only (D-062) and is not present in this clone" >&2; exit 2; }
	bash scripts/review.sh "$$TASK"
