#!/bin/bash
# Unattended iTop 3.2.2 install, recompilation and provisioning. Runs INSIDE the itop container as www-data:
#   docker compose -f compose.itop.yaml --profile itop exec -u www-data itop /opt/hermes-itop/install.sh
# Idempotent, safe to run after every start:
#   - no configuration yet: fresh install;
#   - a configuration, but the compiled model (env-production volume) is missing or was built from another version of
#     the extension or of iTop (fingerprint in the data volume): recompile in upgrade mode, which keeps the data and
#     takes the database settings from the configuration;
#   - otherwise nothing is compiled.
# Then provision.php (re)applies the Hermes objects. Passwords come from the files named by ITOP_DB_PASSWORD_FILE and
# ITOP_ADMIN_PASSWORD_FILE (Docker secrets); the plain variables still work when no file is named.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ITOP_DIR=/var/www/html
CONFIG="$ITOP_DIR/conf/production/config-itop.php"
STAMP="$ITOP_DIR/data/hermes-model.sha256"

# What the compiled model depends on: the extensions' files and iTop's own version.
fingerprint() {
  (
    cd "$ITOP_DIR"
    find extensions -type f -print0 | sort -z | xargs -0 -r sha256sum
    sha256sum datamodels/2.x/version.xml
  ) | sha256sum | cut -d' ' -f1
}

# run_setup MODE: render the response file (it holds passwords: mode 600, deleted on exit) and run the installer.
response=""
trap 'rm -f "$response"' EXIT
run_setup() {
  local mode="$1"
  response="$(mktemp)"
  chmod 600 "$response"
  # php reads the secret files itself and escapes every value for XML, so passwords may contain any character
  HERMES_SETUP_MODE="$mode" HERMES_PREVIOUS_CONFIG="$CONFIG" php -r '
    function value(string $name): string {
      $file = getenv($name."_FILE");
      if ($file !== false && $file !== "") {
        $text = @file_get_contents($file);
        if ($text === false) { fwrite(STDERR, "cannot read $file\n"); exit(2); }
        return rtrim($text, "\r\n");  // like the MariaDB image, a trailing newline is not part of the value
      }
      return (string) getenv($name);
    }
    $values = ["MODE" => getenv("HERMES_SETUP_MODE"), "PREVIOUS_CONFIG" => "", "ITOP_PORT" => value("ITOP_PORT"),
      "ITOP_DB_PASSWORD" => "", "ITOP_ADMIN_PASSWORD" => ""];
    if ($values["MODE"] === "upgrade") {
      $values["PREVIOUS_CONFIG"] = getenv("HERMES_PREVIOUS_CONFIG");  // database settings come from it
    } else {
      foreach (["ITOP_PORT", "ITOP_DB_PASSWORD", "ITOP_ADMIN_PASSWORD"] as $name) {
        $values[$name] = value($name);
        if ($values[$name] === "") {
          fwrite(STDERR, "missing value for $name (set the file named by {$name}_FILE or the variable)\n");
          exit(2);
        }
      }
    }
    $t = file_get_contents($argv[1]);
    foreach ($values as $name => $value) {
      $t = str_replace("@$name@", htmlspecialchars($value, ENT_XML1), $t);
    }
    file_put_contents($argv[2], $t);
  ' "$HERE/response.xml.template" "$response"
  local options=()
  [ "$mode" = upgrade ] && options+=(--use_itop_config)
  php "$ITOP_DIR/setup/unattended-install/unattended-install.php" \
    --installation_xml="$ITOP_DIR/datamodels/2.x/installation.xml" --param-file="$response" "${options[@]}"
  rm -f "$response"
}

wanted="$(fingerprint)"
if [ ! -f "$CONFIG" ]; then
  echo "iTop is not installed yet: fresh install"
  run_setup install
  echo "$wanted" > "$STAMP"
elif [ -z "$(ls -A "$ITOP_DIR/env-production" 2>/dev/null)" ] || [ "$(cat "$STAMP" 2>/dev/null)" != "$wanted" ]; then
  echo "the compiled model is missing or out of date (extension or iTop version changed): recompiling"
  # The setup leaves the configuration read-only (0440) and an upgrade rewrites it: unlock it, then lock it again.
  # With use_itop_config the installer means to put the original file back (it keeps settings changed by hand, such as
  # the timezone) but fails on the read-only file, so that last step is done here.
  chmod 640 "$CONFIG"
  run_setup upgrade
  if [ -f "$CONFIG.backup" ]; then
    chmod 640 "$CONFIG"
    cp "$CONFIG.backup" "$CONFIG"
    rm -f "$CONFIG.backup"
  fi
  chmod 440 "$CONFIG"
  echo "$wanted" > "$STAMP"
else
  echo "iTop is installed and its model is up to date"
fi

php "$HERE/provision.php"
echo "iTop is ready"
