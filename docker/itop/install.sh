#!/bin/bash
# Unattended iTop 3.2.2 install for the test instance. Runs INSIDE the itop container as www-data:
#   docker compose -f compose.itop.yaml --profile itop exec -u www-data itop /opt/hermes-itop/install.sh
# Idempotent: does nothing when iTop is already configured.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ITOP_DIR=/var/www/html
CONFIG="$ITOP_DIR/conf/production/config-itop.php"

for name in ITOP_DB_PASSWORD ITOP_ADMIN_PASSWORD ITOP_PORT; do
  [ -n "${!name:-}" ] || { echo "missing environment variable $name" >&2; exit 2; }
done

if [ -f "$CONFIG" ]; then
  echo "iTop is already installed ($CONFIG exists); skipping the install"
else
  response="$(mktemp)"
  trap 'rm -f "$response"' EXIT
  chmod 600 "$response"
  # php escapes the values for XML, so passwords may contain any character
  php -r '
    $t = file_get_contents($argv[1]);
    foreach (["ITOP_DB_PASSWORD", "ITOP_ADMIN_PASSWORD", "ITOP_PORT"] as $n) {
      $t = str_replace("@$n@", htmlspecialchars(getenv($n), ENT_XML1), $t);
    }
    file_put_contents($argv[2], $t);
  ' "$HERE/response.xml.template" "$response"
  php "$ITOP_DIR/setup/unattended-install/unattended-install.php" --installation_xml="$ITOP_DIR/datamodels/2.x/installation.xml" --param-file="$response"
fi

php "$HERE/provision.php"
echo "iTop is ready"
