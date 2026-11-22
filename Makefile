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

coverage: test ## Coverage gate: 80% global, 95% core (runs the tests first)
	uv run --locked python scripts/check_coverage.py

# Semgrep CE in Docker (docs/14 §3.2). Registry packs: python, owasp-top-ten, secrets, fastapi.
# Mounted read-only; --no-git-ignore keeps it working in git worktrees (the .git file points outside the mount).
SEMGREP_IMAGE ?= semgrep/semgrep:latest
GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

# Only files git would version (tracked and untracked, minus ignored): local-only material stays out.
# The NUL-delimited list reaches Semgrep as individual arguments, so odd file names cannot split or inject.
semgrep: ## Semgrep CE (Docker): registry packs + .semgrep/ project rules, fails on WARNING/ERROR
	git ls-files -z --cached --others --exclude-standard | xargs -0 -r \
	  docker run --rm -v "$(CURDIR):/src:ro" -w /src $(SEMGREP_IMAGE) semgrep scan \
	  --config p/python --config p/owasp-top-ten --config p/secrets --config p/fastapi \
	  --config /src/.semgrep/ --metrics=off --no-git-ignore \
	  --error --severity WARNING --severity ERROR --

# Scans the working tree (tracked and untracked files, minus ignored ones): the file list is streamed
# as a tar into the container, so caches and virtualenvs are not scanned and no temp dir is needed.
secrets: ## Gitleaks (Docker, pinned by tag and digest) on the working tree
	git ls-files -z --cached --others --exclude-standard | tar --null --ignore-failed-read -T - -cf - | \
	  docker run --rm -i --entrypoint sh $(GITLEAKS_IMAGE) -c \
	  'mkdir /work && tar -xf - -C /work && gitleaks dir /work --redact --no-banner -v'

audit: ## pip-audit on the locked dependencies
	uv export --locked --no-hashes --no-emit-project --format requirements-txt | uvx pip-audit --no-deps --disable-pip -r /dev/stdin

SCHEMATHESIS_VERSION ?= 4.33.4
BRUNO_CLI_VERSION ?= 4.3.0
ZAP_IMAGE ?= ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af
OPENAPI_SNAPSHOT ?= openapi/openapi.json

# Not part of plain `make verify`. A step is skipped only while the phase that creates its prerequisite
# has not landed, and says so with an explicit SKIPPED line; once the prerequisite exists it must pass.
verify-full: verify ## Full gate before closing a feature: verify + Schemathesis + adversarial suite
	@if [ -f "$(OPENAPI_SNAPSHOT)" ]; then \
	  test -n "$${API_URL:-}" || { echo "API_URL is not set: Schemathesis needs the running API (e.g. API_URL=http://localhost:8000)" >&2; exit 2; }; \
	  uvx schemathesis@$(SCHEMATHESIS_VERSION) run "$(OPENAPI_SNAPSHOT)" --url "$$API_URL"; \
	else \
	  echo "SKIPPED: Schemathesis, $(OPENAPI_SNAPSHOT) does not exist yet (arrives in F0.5)"; \
	fi
	@rc=0; uv run --locked pytest -m adversarial -q --no-cov || rc=$$?; \
	if [ $$rc -eq 5 ]; then echo "SKIPPED: adversarial suite, no test carries the adversarial marker yet (arrives in F6)"; \
	else exit $$rc; fi

zap: ## OWASP ZAP API scan in Docker against API_URL/api/openapi.json (needs API_URL)
	@test -n "$${API_URL:-}" || { echo "API_URL is not set: ZAP needs the running API (e.g. API_URL=http://localhost:8000)" >&2; exit 2; }
	docker run --rm --network host $(ZAP_IMAGE) zap-api-scan.py -t "$${API_URL%/}/api/openapi.json" -f openapi

bruno: ## Bruno API collection (bruno/ folder, environment local)
	@test -d bruno || { echo "bruno/ folder not found: the Bruno collection is created in F0.7 (D-070)" >&2; exit 2; }
	cd bruno && npx --yes @usebruno/cli@$(BRUNO_CLI_VERSION) run --env local

# TASK and REVIEWER reach the recipe as environment variables, so quotes in the task title stay intact.
export TASK REVIEWER

review: ## Automatic review by the other agent: make review TASK="F0.1-T1 · ..." REVIEWER=codex|claude
	@test -n "$$TASK" || { echo 'Usage: make review TASK="FNN.M-Tk · description" REVIEWER=codex|claude' >&2; exit 2; }
	@test -f scripts/review.sh || { echo "scripts/review.sh is local-only (D-062) and is not present in this clone" >&2; exit 2; }
	bash scripts/review.sh "$$TASK"
