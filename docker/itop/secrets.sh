#!/usr/bin/env bash
# Write the Docker secret files compose.itop.yaml mounts (D-042), in $COMPOSE_SECRETS_DIR (default .compose-secrets,
# gitignored, the same directory as the Hermes stack's secrets). `make itop-secrets` runs it; `make itop-up` too.
#   itop_db_root_password, itop_db_password, itop_admin_password
#       an existing non-empty file is kept; otherwise the exported variable of the same name in upper case is used
#       when set, else a random password is generated (read it from its file). They only take effect on the first
#       install: changing them later needs the rotation steps of the README ("Guía de operación" §9).
#   itop_webhook_token
#       shared with the Hermes stack, whose `make compose-secrets` writes it from ITOP_WEBHOOK_TOKEN; when the file
#       does not exist yet it is created empty (the webhook then goes out without a token and the API refuses it).
# The directory is private to the user (700); the files are world-readable (644) because compose bind-mounts them as
# they are and the containers run as non-root users (mysql, www-data).
set -euo pipefail
dir="${COMPOSE_SECRETS_DIR:-.compose-secrets}"

# The output directory must be the gitignored default or live outside the repository (it holds credentials).
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
case "$(mkdir -p "$dir" && cd "$dir" && pwd)" in
  "$repo_root/.compose-secrets") ;;
  "$repo_root"|"$repo_root"/*) echo "COMPOSE_SECRETS_DIR must be .compose-secrets or outside the repository" >&2; exit 2 ;;
esac

umask 077
chmod 700 "$dir"

write() {
  printf '%s' "$2" > "$1"
  chmod 644 "$1"
}

for name in ITOP_DB_ROOT_PASSWORD ITOP_DB_PASSWORD ITOP_ADMIN_PASSWORD; do
  file="$dir/${name,,}"
  if [ -s "$file" ]; then
    continue
  fi
  if [ -n "${!name:-}" ]; then
    write "$file" "${!name}"
  else
    random="$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
    write "$file" "Aa1-${random:0:28}"  # upper, lower, digit and symbol, whatever iTop's password policy asks
    echo "generated a random ${name}: read it from $file"
  fi
done

if [ ! -f "$dir/itop_webhook_token" ]; then
  write "$dir/itop_webhook_token" ""
  echo "WARNING: $dir/itop_webhook_token is empty: set ITOP_WEBHOOK_TOKEN and run make compose-secrets" >&2
fi
echo "iTop secrets ready in $dir"
