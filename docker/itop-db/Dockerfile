# MariaDB 10.11 of the persistent iTop (compose.itop.yaml): the pinned official image without `gosu`, as docker/db does
# for PostgreSQL. The entrypoint calls gosu only when it starts as root, and healthcheck.sh only with --su options;
# the container always runs as the mysql user with `--connect --innodb_initialized`, so gosu is never used. Its binary
# was built with Go 1.24.6 and carried every fixable HIGH and CRITICAL Trivy finding of this image; the pinned digest
# is still the newest 10.11 build (10.11.19), so a newer digest would not remove them.
FROM mariadb:10.11@sha256:e5fe75b2b9de0eb9f6f9a4d9c97272fb3a7480e389ccd487a786bab2a12cc0d7
RUN rm -f /usr/local/bin/gosu
USER mysql
