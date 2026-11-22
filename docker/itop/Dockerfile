# iTop 3.2.2 for the test instance: the pinned base image plus the MariaDB client, because the unattended
# installer refuses to run without `mysqldump` (its backup prerequisite check) and the -base image lacks it.
FROM vbkunin/itop:3.2.2-base@sha256:903f950e660c597a5684e88a2a59f2a9712a0574bf9f6e608b72172fec26db0d
RUN apt-get update \
 && apt-get install -y --no-install-recommends mariadb-client \
 && rm -rf /var/lib/apt/lists/*
