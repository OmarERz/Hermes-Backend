#!/bin/bash
# The iTop cron (itop-cron service): webservices/cron.php every minute as www-data. cron.php processes the background
# tasks (notifications, SLA computation, asynchronous tasks, scheduled backups, log rotation) for up to
# cron_max_execution_time and keeps a mutex, so overlapping runs exit at once. It logs in as the hermes-cron
# administrator whose credentials live in a param file of the data volume (provision.php), never on the command line;
# until that file exists (iTop not installed yet) the loop only waits.
set -uo pipefail
PARAMS=/var/www/html/data/hermes-cron.params
trap 'exit 0' TERM INT
while :; do
  if [ -r "$PARAMS" ]; then
    php /var/www/html/webservices/cron.php --param_file="$PARAMS" || echo "cron.php exited with status $?" >&2
  fi
  sleep 60 &
  wait $!
done
