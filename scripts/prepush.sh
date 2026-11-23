#!/usr/bin/env bash
# Local pre-push gate (D-086): what the remote CI runs, on this machine, before a feature branch is pushed.
#   1. make verify: lint, types, boundaries, tests with the coverage gate, Semgrep, KICS, Gitleaks and pip-audit
#      (the CI static and tests jobs). Gitleaks scans the history from origin/develop, like the CI on a pull request.
#   2. An isolated Compose stack, as in the CI schemathesis job and the ZAP job of security-weekly.yml: a project name,
#      published ports (20000-39999) and throwaway passwords unique to this run, the secret files in a temporary
#      directory outside the repository, no env file (CI has none, so no real key reaches the stack), the embeddings
#      fake (compose.ci.yaml) and the API docs on (ZAP reads /api/openapi.json).
#   3. Firebase emulator tokens for admin, analyst and reader, then make dynamic (Schemathesis and the adversarial
#      suite), make bruno with the three tokens and make zap.
# The stack and the temporary directory are always removed (also on Ctrl-C; a SIGTERM is handled once the running
# command ends). A run killed outright is swept by the next integration test session: the project name follows
# E2E_PROJECT in tests/harness/isolation.py and carries this script's process id.
# On success the run is recorded for the tree of HEAD in .review/prepush.json of this checkout and appended to
# .review/prepush.log of the main checkout (shared by every worktree); the local pre-push hook and the merge helper
# read them. The working tree must be clean, so the record certifies exactly the committed tree.
# Run it from the checkout to check (make prepush); a branch without the target can run this file by its path.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
root="$PWD"
main_root="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"

if [ -n "$(git status --porcelain)" ]; then
  echo "✖ prepush: the working tree has uncommitted or untracked changes; commit them first:" >&2
  git status --short >&2
  exit 1
fi
head="$(git rev-parse HEAD)"
tree="$(git rev-parse 'HEAD^{tree}')"
branch="$(git symbolic-ref --quiet --short HEAD || echo detached)"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started="$(date +%s)"

# Knobs that would narrow a step (a Bruno folder, fewer fuzzed paths) or change the stack must not leak in from the
# caller's environment: every step runs as in CI.
unset BRUNO_ARGS SCHEMATHESIS_EXCLUDES OPENAPI_SNAPSHOT COMPOSE_PROFILES COMPOSE_ENV_FILES TEST_TOKEN ANALYST_TOKEN \
  READER_TOKEN API_URL
export GITLEAKS_BASE="${GITLEAKS_BASE:-origin/develop}"

current_step="start"
steps=""
tmp=""
project=""
stack_started=""

dc() { docker compose --env-file /dev/null "$@"; }

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ -n "$stack_started" ]; then
    echo "==> prepush: removing the stack $project"
    dc down -v --remove-orphans --rmi local >/dev/null 2>&1 || echo "warning: could not remove the stack $project" >&2
  fi
  if [ -n "$tmp" ]; then rm -rf "$tmp"; fi
  if [ "$rc" -ne 0 ]; then echo "✖ prepush failed at step '$current_step' (nothing recorded)" >&2; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# step NAME COMMAND...: runs one step and keeps its duration for the record.
step() {
  local name="$1" t0
  shift
  current_step="$name"
  echo "==> prepush: $name"
  t0="$(date +%s)"
  "$@"
  steps="$steps $name=$(($(date +%s) - t0))"
}

stack_up() {
  local ports var
  # Only what this stack sets reaches Compose: drop every variable compose.yaml interpolates (as on a CI runner).
  for var in $(grep -ohE '\$\{[A-Z_][A-Z0-9_]*' compose.yaml compose.ci.yaml | cut -c3- | sort -u) ADVISORY_DOMAINS; do
    unset "$var"
  done
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/hermes-prepush.XXXXXX")"
  project="hermes-prepush-e2e-$(printf '%s' "$root" | sha256sum | cut -c1-8)-$$-$(openssl rand -hex 3)"
  ports="$(PYTHONPATH=tests uv run --locked python -c '
from harness.isolation import free_port
ports = set()
while len(ports) < 3:
    ports.add(free_port())
print(*sorted(ports))')"
  read -r API_PORT AUTH_EMULATOR_PORT DB_PORT <<<"$ports"
  export COMPOSE_FILE=compose.yaml:compose.ci.yaml COMPOSE_PROJECT_NAME="$project" COMPOSE_SECRETS_DIR="$tmp/compose"
  export API_PORT AUTH_EMULATOR_PORT DB_PORT API_DOCS_ENABLED=true

  # Throwaway passwords, written as the secret files compose.yaml mounts (D-042); the optional keys stay blank.
  (
    unset ITOP_TOKEN NVD_API_KEY DEEPSEEK_API_KEY ABUSECH_AUTH_KEY RANSOMWARELIVE_API_KEY ITOP_WEBHOOK_TOKEN
    for var in POSTGRES_PASSWORD MIGRATOR_DB_PASSWORD APP_DB_PASSWORD RETENTION_DB_PASSWORD CURSOR_SIGNING_KEY; do
      printf -v "$var" "%s" "$(openssl rand -hex 24)"
      export "$var"
    done
    ENV_FILE=/dev/null make --no-print-directory compose-secrets
  )
  echo "project $project, API on 127.0.0.1:$API_PORT"
  stack_started=1
  dc up --build --wait --wait-timeout 600 -d
}

token() {
  FIREBASE_AUTH_EMULATOR_HOST="127.0.0.1:$AUTH_EMULATOR_PORT" make -s --no-print-directory emulator-token ROLE="$1"
}

tokens() {
  admin_token="$(token admin)"
  analyst_token="$(token analyst)"
  reader_token="$(token reader)"
}

dynamic() { API_URL="http://127.0.0.1:$API_PORT" TEST_TOKEN="$admin_token" make --no-print-directory dynamic; }

bruno() {
  API_URL="http://127.0.0.1:$API_PORT" TEST_TOKEN="$admin_token" ANALYST_TOKEN="$analyst_token" \
    READER_TOKEN="$reader_token" make --no-print-directory bruno
}

# A fresh admin token: emulator ID tokens last one hour and the earlier steps may take a while.
zap() { API_URL="http://localhost:$API_PORT" TEST_TOKEN="$(token admin)" make --no-print-directory zap; }

step verify make --no-print-directory verify
step stack stack_up
step tokens tokens
step dynamic dynamic
step bruno bruno
step zap zap

current_step="record"
if [ "$(git rev-parse HEAD)" != "$head" ] || [ -n "$(git status --porcelain)" ]; then
  echo "✖ prepush: HEAD or the working tree changed during the run; run it again on the final commit" >&2
  exit 1
fi
finished="$(date +%s)"
P_HEAD="$head" P_TREE="$tree" P_BRANCH="$branch" P_STARTED="$started_at" P_DURATION="$((finished - started))" \
  P_STEPS="$steps" uv run --locked python - "$root/.review/prepush.json" "$main_root/.review/prepush.log" <<'PY'
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

env = os.environ
record = {
    "result": "green",
    "head": env["P_HEAD"],
    "tree": env["P_TREE"],
    "branch": env["P_BRANCH"],
    "started_at": env["P_STARTED"],
    "finished_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "duration_seconds": int(env["P_DURATION"]),
    "steps": [{"name": n, "seconds": int(s)} for n, s in (item.split("=", 1) for item in env["P_STEPS"].split())],
}
latest, log = Path(sys.argv[1]), Path(sys.argv[2])
latest.parent.mkdir(parents=True, exist_ok=True)
fd, partial = tempfile.mkstemp(dir=latest.parent, prefix=".prepush-", suffix=".json")
with os.fdopen(fd, "w", encoding="utf-8") as out:
    json.dump(record, out, indent=2)
    out.write("\n")
os.replace(partial, latest)
log.parent.mkdir(parents=True, exist_ok=True)
with log.open("a", encoding="utf-8") as out:
    out.write(json.dumps(record, separators=(",", ":")) + "\n")
PY
summary=""
for item in $steps; do summary="$summary ${item%%=*} ${item#*=}s ·"; done
total="$((finished - started))"
echo "✔ prepush green for $branch (${head:0:9}, tree ${tree:0:9}) in $((total / 60))m $((total % 60))s:${summary% ·}"
echo "  recorded in .review/prepush.json and $main_root/.review/prepush.log"
