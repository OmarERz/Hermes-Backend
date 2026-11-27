#!/usr/bin/env bash
# Write the Docker secret files compose.yaml mounts (D-042). Values come from the environment or, when a variable
# is not exported, from the local env file ($ENV_FILE, default .env), parsed as KEY=VALUE lines without executing
# it. Run it before `docker compose up` (make compose-secrets does). Required variables must be set; optional API
# keys may be blank (an empty file means "not configured").
# Files: one per secret in $COMPOSE_SECRETS_DIR (default .compose-secrets, gitignored); the directory is private
# to the user (700), the files are world-readable (644) because compose bind-mounts them as they are and the
# containers run as non-root users.
set -euo pipefail
dir="${COMPOSE_SECRETS_DIR:-.compose-secrets}"
env_file="${ENV_FILE:-.env}"
required=(POSTGRES_PASSWORD MIGRATOR_DB_PASSWORD APP_DB_PASSWORD RETENTION_DB_PASSWORD CURSOR_SIGNING_KEY)
optional=(ITOP_TOKEN NVD_API_KEY DEEPSEEK_API_KEY ABUSECH_AUTH_KEY RANSOMWARELIVE_API_KEY ITOP_WEBHOOK_TOKEN
          SLACK_DB_PASSWORD SLACK_BOT_TOKEN SLACK_APP_TOKEN)

# value_of NAME: exported value, else the last NAME=... line of the env file, read with the env-file syntax that
# docker compose accepts (optional `export`, spaces around `=`, quoted values, ` #` comments after unquoted values)
# but never executed.
value_of() {
  local name="$1" line key value="" found=""
  if [ -n "${!name+x}" ]; then
    printf '%s' "${!name}"
    return
  fi
  [ -f "$env_file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"          # trim leading spaces
    [[ -z "$line" || "$line" == \#* ]] && continue
    line="${line#export }"
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    key="${key%"${key##*[![:space:]]}"}"             # trim trailing spaces of the key
    [ "$key" = "$name" ] || continue
    value="${line#*=}"
    value="${value#"${value%%[![:space:]]*}"}"       # spaces after `=`
    found=1
  done < "$env_file"
  [ -n "$found" ] || return 0
  if [[ "$value" == \"*\"* ]]; then                  # "double quoted" (anything after the closing quote is ignored)
    value="${value:1}"; value="${value%%\"*}"
  elif [[ "$value" == \'*\'* ]]; then                # 'single quoted'
    value="${value:1}"; value="${value%%\'*}"
  else                                               # unquoted: drop a ` #` comment and trailing spaces
    value="${value%%[[:space:]]#*}"
    value="${value%"${value##*[![:space:]]}"}"
  fi
  printf '%s' "$value"
}

# The output directory must be the gitignored default or live outside the repository (it holds credentials).
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
case "$(mkdir -p "$dir" && cd "$dir" && pwd)" in
  "$repo_root/.compose-secrets") ;;
  "$repo_root"|"$repo_root"/*) echo "COMPOSE_SECRETS_DIR must be .compose-secrets or outside the repository" >&2; exit 2 ;;
esac

umask 077
mkdir -p "$dir"
chmod 700 "$dir"
for name in "${required[@]}"; do
  if [ -z "$(value_of "$name")" ]; then
    echo "missing required variable: $name (export it or set it in $env_file)" >&2
    exit 2
  fi
done
for name in "${required[@]}" "${optional[@]}"; do
  file="$dir/${name,,}"
  value_of "$name" > "$file"
  chmod 644 "$file"
done
echo "compose secrets written to $dir"
