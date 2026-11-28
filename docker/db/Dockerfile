# PostgreSQL 18 + pgvector for Compose: the pinned official image without `gosu`.
# The official entrypoint calls gosu only to drop root privileges (`if [ "$(id -u)" = '0' ]`); this image always runs
# as the postgres user, so gosu is never used. Its binary was built with an old Go toolchain and carried fixable
# HIGH findings in Trivy (user decision, docs/02 §4, F12.1). Keep the digest in step with tests/integration/conftest.py.
# The pinned digest is still the newest pg18 build, so Debian's security updates published since (fixable Trivy
# findings such as libpam and zstd) are applied here.
FROM pgvector/pgvector:pg18@sha256:38681dc6eaf55308e2a4c6de392d131652dcfac70e1263e35cd9b5ea3fe39782
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::=--force-confold \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/local/bin/gosu
USER postgres
