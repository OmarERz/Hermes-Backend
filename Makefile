# Quality gate (docs/14 §2): F0.1 minimal version (D-072) extended in F0.3 with import-linter, coverage,
# Semgrep, Gitleaks, pip-audit, verify-full and the zap and bruno placeholders.
.DEFAULT_GOAL := help
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: up demo backup compose-secrets help openapi verify lint typecheck boundaries test coverage semgrep kics secrets audit verify-full schemathesis adversarial dynamic zap bruno ci-lint seed events emulator-token itop-up itop-install itop-seed itop-token itop-down review

help: ## List the available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\n", $$1, $$2}'

verify: lint typecheck boundaries test coverage semgrep kics secrets audit ## Run the quality gate (same command locally and in CI)

lint: ## Formatting and lint (ruff)
	uv run --locked ruff format --check .
	uv run --locked ruff check .

typecheck: ## Strict type checking (mypy)
	uv run --locked mypy
	uv run --locked mypy --package-root=. scripts/check_coverage.py scripts/export_openapi.py

boundaries: ## Package boundary contracts (import-linter)
	uv run --locked lint-imports

test: ## Unit and integration tests (pytest), writes coverage.json and coverage.xml
	uv run --locked pytest --cov --cov-report=json --cov-report=xml --cov-report=term-missing:skip-covered

openapi: ## Regenerate the OpenAPI snapshot (openapi/openapi.json) after changing routes or schemas
	uv run --locked python scripts/export_openapi.py

coverage: test ## Coverage gate: 80% global, 95% core (runs the tests first)
	uv run --locked python scripts/check_coverage.py

# Semgrep CE in Docker (docs/14 §3.2). Registry packs: python, owasp-top-ten, secrets, fastapi.
# Mounted read-only; --no-git-ignore keeps it working in git worktrees (the .git file points outside the mount).
# Scanner images pinned by digest like the others (F12.3): a scanner that changes under us cannot pass or fail a build
# for reasons outside the repository. The registry rule packs (p/...) still come fresh on every run.
SEMGREP_IMAGE ?= semgrep/semgrep:1.185.0@sha256:67518c174185a2043fdbed16c70631b79209499b3671178e7194379b48295a0d
KICS_IMAGE ?= checkmarx/kics:v2.2.1@sha256:49ccc54b6ae7f5d5fc95e96f8f95c18c57f3bba047ab611a03d80792bdff6757
GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

# Only files git would version (tracked and untracked, minus ignored): local-only material stays out.
# The NUL-delimited list reaches Semgrep as individual arguments, so odd file names cannot split or inject.
semgrep: ## Semgrep CE (Docker): registry packs + .semgrep/ project rules, fails on WARNING/ERROR
	git ls-files -z --cached --others --exclude-standard | xargs -0 -r \
	  docker run --rm -v "$(CURDIR):/src:ro" -w /src $(SEMGREP_IMAGE) semgrep scan \
	  --config p/python --config p/owasp-top-ten --config p/secrets --config p/fastapi \
	  --config /src/.semgrep/ --metrics=off --no-git-ignore \
	  --error --severity WARNING --severity ERROR --

# --disable-secrets: Gitleaks already scans every file and the history for secrets (`make secrets`).
kics: ## KICS (Docker, pinned) on compose.yaml: fails on CRITICAL, HIGH and MEDIUM (Trivy does not read Compose files)
	docker run --rm -v "$(CURDIR)/compose.yaml:/scan/compose.yaml:ro" $(KICS_IMAGE) scan -p /scan/compose.yaml \
	  --type DockerCompose --fail-on critical,high,medium --disable-secrets --no-progress --ci

# Working tree: tracked and untracked files minus ignored ones, streamed as a tar into the container, so
# caches and virtualenvs are not scanned and no temp dir is needed.
# History: `gitleaks git` over the commits of the current branch, i.e. those reachable from HEAD and not from
# GITLEAKS_BASE (develop, D-064); all history with GITLEAKS_FULL_HISTORY=1, and the whole of HEAD when the
# base ref does not exist (fresh clone). The repository is mounted from the common git dir (read-only), which
# also works in git worktrees where .git is a file; HEAD is passed as an explicit SHA for the same reason.
GITLEAKS_BASE ?= develop
GITLEAKS_FULL_HISTORY ?= 0

secrets: ## Gitleaks (Docker, pinned): working tree + branch history (GITLEAKS_FULL_HISTORY=1 for all history)
	git ls-files -z --cached --others --exclude-standard | tar --null --ignore-failed-read -T - -cf - | \
	  docker run --rm -i --entrypoint sh $(GITLEAKS_IMAGE) -c \
	  'mkdir /work && tar -xf - -C /work && gitleaks dir /work --redact --no-banner -v'
	@head=$$(git rev-parse HEAD); \
	if [ "$(GITLEAKS_FULL_HISTORY)" = "1" ]; then revs="--all"; \
	elif git rev-parse --verify --quiet "$(GITLEAKS_BASE)^{commit}" >/dev/null; then revs="^$(GITLEAKS_BASE) $$head"; \
	else revs="$$head"; fi; \
	echo "gitleaks history scan: $$revs"; \
	docker run --rm -v "$$(git rev-parse --path-format=absolute --git-common-dir):/repo/.git:ro" -w /repo \
	  -v "$(CURDIR)/.gitleaksignore:/ignore/.gitleaksignore:ro" \
	  $(GITLEAKS_IMAGE) git /repo --redact --no-banner -v --log-opts="$$revs" \
	  --gitleaks-ignore-path /ignore/.gitleaksignore

audit: ## pip-audit on the locked dependencies (backend and embeddings service)
	uv export --locked --no-hashes --no-emit-project --format requirements-txt | uvx pip-audit --no-deps --disable-pip -r /dev/stdin
	@# The service's torch is the CPU build of the same release (local version +cpu): audit the upstream version.
	uv export --project docker/embeddings --locked --no-hashes --no-emit-project --format requirements-txt \
	  | sed 's/+cpu//' | uvx pip-audit --no-deps --disable-pip -r /dev/stdin

SCHEMATHESIS_VERSION ?= 4.33.4
BRUNO_CLI_VERSION ?= 4.3.0
ZAP_IMAGE ?= ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af
OPENAPI_SNAPSHOT ?= openapi/openapi.json
# Operations with external effects are excluded from fuzzing (docs/14 §4.3). --exclude-path drops every
# method of the path; later phases extend this list (e.g. SCHEMATHESIS_EXCLUDES += --exclude-path /api/x).
SCHEMATHESIS_EXCLUDES ?= --exclude-path /api/scans --exclude-path /api/stix/export

# Not part of plain `make verify`. A step is skipped only while the phase that creates its prerequisite
# has not landed, and says so with an explicit SKIPPED line; once the prerequisite exists it must pass.
verify-full: verify dynamic ## Full gate before closing a feature: verify + dynamic checks

dynamic: schemathesis adversarial ## Dynamic checks only: Schemathesis + adversarial suite (CI runs them after verify's steps)

schemathesis: ## Schemathesis against the running API (API_URL and TEST_TOKEN) once openapi/openapi.json exists
	@if [ -f "$(OPENAPI_SNAPSHOT)" ]; then \
	  test -n "$${API_URL:-}" || { echo "API_URL is not set: Schemathesis needs the running API (e.g. API_URL=http://localhost:8000)" >&2; exit 2; }; \
	  test -n "$${TEST_TOKEN:-}" || { echo "TEST_TOKEN is not set: Schemathesis needs a Firebase emulator bearer token (docs/14 §4.3)" >&2; exit 2; }; \
	  uvx schemathesis@$(SCHEMATHESIS_VERSION) run "$(OPENAPI_SNAPSHOT)" --url "$$API_URL" \
	    -H "Authorization: Bearer $$TEST_TOKEN" $(SCHEMATHESIS_EXCLUDES); \
	else \
	  echo "SKIPPED: Schemathesis, $(OPENAPI_SNAPSHOT) does not exist yet (arrives in F0.5)"; \
	fi

adversarial: ## Adversarial judge suite (pytest -m adversarial)
	@rc=0; uv run --locked pytest -m adversarial -q --no-cov || rc=$$?; \
	if [ $$rc -eq 5 ]; then echo "SKIPPED: adversarial suite, no test carries the adversarial marker yet (arrives in F6)"; \
	else exit $$rc; fi

zap: ## OWASP ZAP API scan in Docker against API_URL/api/openapi.json (needs API_URL and TEST_TOKEN)
	@test -n "$${API_URL:-}" || { echo "API_URL is not set: ZAP needs the running API (e.g. API_URL=http://localhost:8000)" >&2; exit 2; }
	@test -n "$${TEST_TOKEN:-}" || { echo "TEST_TOKEN is not set: ZAP needs a Firebase emulator bearer token (docs/14 §4.4)" >&2; exit 2; }
	docker run --rm --network host $(ZAP_IMAGE) zap-api-scan.py -t "$${API_URL%/}/api/openapi.json" -f openapi \
	  -z "-config replacer.full_list(0).description=auth -config replacer.full_list(0).enabled=true \
	  -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization \
	  -config replacer.full_list(0).regex=false -config 'replacer.full_list(0).replacement=Bearer $$TEST_TOKEN'"

bruno: ## Bruno API collection (bruno/ folder, environment local)
	@test -d bruno || { echo "bruno/ folder not found: the Bruno collection is created in F0.7 (D-070)" >&2; exit 2; }
	cd bruno && npx --yes @usebruno/cli@$(BRUNO_CLI_VERSION) run --env local $${TEST_TOKEN:+--env-var token="$$TEST_TOKEN"}

# Prints one Firebase Auth emulator ID token (D-069); the emulator comes from `docker compose up auth-emulator`.
# Defaults to the emulator published on localhost; the tool itself refuses to run without an emulator host.
emulator-token: ## Print an emulator ID token: make emulator-token ROLE=admin|analyst|reader
	@test -n "$${ROLE:-}" || { echo "Usage: make emulator-token ROLE=admin|analyst|reader" >&2; exit 2; }
	@FIREBASE_AUTH_EMULATOR_HOST="$${FIREBASE_AUTH_EMULATOR_HOST:-127.0.0.1:9099}" \
	  uv run --locked python -m core.devtools.emulator token --role "$$ROLE"

# Admin CLI (core.devtools.admin): seed as migrator (MIGRATION_DATABASE_URL), events as app (DATABASE_URL).
seed: ## Load a seed scenario: make seed SCENARIO=empty|demo|edge
	@test -n "$${SCENARIO:-}" || { echo "Usage: make seed SCENARIO=empty|demo|edge" >&2; exit 2; }
	uv run --locked python -m core.devtools.admin seed --scenario "$$SCENARIO"

events: ## List the latest notification events as JSON lines (optional LIMIT, STATUS, TYPE)
	@uv run --locked python -m core.devtools.admin events --limit "$${LIMIT:-20}" \
	  $${STATUS:+--status "$$STATUS"} $${TYPE:+--type "$$TYPE"}

# iTop 3.2.2 test instance (compose.itop.yaml, docs/itop-test-instance.md). Needs ITOP_DB_ROOT_PASSWORD,
# ITOP_DB_PASSWORD and ITOP_ADMIN_PASSWORD in the environment; every compose call below reads them.
ITOP_COMPOSE ?= docker compose -f compose.itop.yaml --profile itop

itop-up: ## Start the iTop test instance (Docker)
	$(ITOP_COMPOSE) up -d --build --wait --wait-timeout 300

itop-install: ## Unattended iTop install, extension and REST users (idempotent)
	$(ITOP_COMPOSE) exec -T -u www-data itop /opt/hermes-itop/install.sh

itop-seed: ## Load the synthetic stack into iTop (dry run; add APPLY=1 to write)
	@ITOP_URL="http://127.0.0.1:$${ITOP_PORT:-8080}" \
	  ITOP_TOKEN="$$($(ITOP_COMPOSE) exec -T itop cat /var/www/html/data/hermes-seed-token)" \
	  PYTHONPATH=tests uv run --locked python -m harness.itop_seed docker/itop/stack.yaml $(if $(APPLY),--apply)

itop-token: ## Print the least-privilege REST token of the iTop test instance
	@$(ITOP_COMPOSE) exec -T itop cat /var/www/html/data/hermes-rest-token

itop-down: ## Stop the iTop test instance and delete its data
	$(ITOP_COMPOSE) down -v --remove-orphans

ACTIONLINT_VERSION ?= 1.7.12.24

ci-lint: ## Lint the GitHub Actions workflows (actionlint, not part of verify)
	uvx --from actionlint-py@$(ACTIONLINT_VERSION) actionlint

# TASK and REVIEWER reach the recipe as environment variables, so quotes in the task title stay intact.
export TASK REVIEWER

review: ## Automatic review by the other agent: make review TASK="F0.1-T1 · ..." REVIEWER=codex|claude
	@test -n "$$TASK" || { echo 'Usage: make review TASK="FNN.M-Tk · description" REVIEWER=codex|claude' >&2; exit 2; }
	@test -f scripts/review.sh || { echo "scripts/review.sh is local-only (D-062) and is not present in this clone" >&2; exit 2; }
	bash scripts/review.sh "$$TASK"

compose-secrets: ## Write the Docker secret files compose.yaml mounts (from your environment)
	bash docker/compose-secrets.sh

up: compose-secrets ## Start the local stack: write the Docker secret files, then docker compose up --build -d
	docker compose up --build -d --wait

demo: ## Load the demo data and run one full cycle (no network, no tokens); the stack must be up
	docker compose --profile demo run --rm --build demo

backup: ## Dump the database to backups/hermes-<date>.dump (pg_dump custom format); the stack must be up
	@mkdir -p backups
	docker compose exec -T db pg_dump -U hermes -d hermes -Fc > "backups/hermes-$$(date +%Y%m%d-%H%M%S).dump"
	@ls -1t backups | head -1
