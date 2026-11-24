# iTop 3.2.2 (D-085): the pinned base image, changed to run without root and without capabilities:
#  - the MariaDB client: the unattended installer refuses to run without `mysqldump` (its backup prerequisite
#    check) and the -base image lacks it;
#  - Apache runs directly as www-data on port 8080 (no privileged port, no init system, no setuid), logging to the
#    container's output; its run, lock and log folders belong to www-data;
#  - an empty env-production owned by www-data, so its named volume (the compiled data model) starts writable;
#  - PHP removes expired sessions itself (Debian leaves that to a cron job that no longer runs here).
# The iTop cron runs in its own container from the same image (compose.itop.yaml, itop-cron).
FROM vbkunin/itop:3.2.2-base@sha256:903f950e660c597a5684e88a2a59f2a9712a0574bf9f6e608b72172fec26db0d
RUN apt-get update \
 && apt-get install -y --no-install-recommends mariadb-client \
 && rm -rf /var/lib/apt/lists/* \
 && sed -i 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \
 && sed -i -e 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' -e 's#^\(\s*\)ErrorLog .*#\1ErrorLog /dev/stderr#' \
      -e 's#^\(\s*\)CustomLog .*#\1CustomLog /dev/stdout combined#' /etc/apache2/sites-available/000-default.conf \
 && sed -i 's#^ErrorLog .*#ErrorLog /dev/stderr#' /etc/apache2/apache2.conf \
 && install -d -o www-data -g www-data /var/run/apache2 /var/lock/apache2 /var/www/html/env-production \
 && chown -R www-data:www-data /var/log/apache2 \
 && printf 'session.gc_probability = 1\nsession.gc_divisor = 100\n' > /etc/php/8.3/apache2/conf.d/99-hermes.ini
USER www-data
EXPOSE 8080
CMD ["/bin/sh", "-c", ". /etc/apache2/envvars && exec /usr/sbin/apache2 -DFOREGROUND"]
