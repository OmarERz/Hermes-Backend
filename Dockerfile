# syntax=docker/dockerfile:1
# Backend image for the api and workers services (same image, different command).
# Base images pinned by digest (docs/14 §10.4).

FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:3.12.16-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12.16-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS runtime
# Debian security updates published after the pinned base was built (fixable Trivy findings such as libpam and
# zstd); the base digest is the newest build of its tag, so they are applied here.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::=--force-confold \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 hermes && useradd --system --uid 10001 --gid hermes --no-create-home hermes
WORKDIR /app
COPY --from=build --chown=root:root /app/.venv /app/.venv
# Alembic configuration and migrations (the migrate service runs them as the migrator role)
COPY --chown=root:root alembic.ini ./
COPY --chown=root:root migrations ./migrations
# JSON contracts in schemas/: read from SCHEMAS_DIR by the LLM client (tool definitions) and core.validation
COPY --chown=root:root schemas ./schemas
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SCHEMAS_DIR=/app/schemas
USER hermes
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status != 200)"]
# --no-server-header: no `server: uvicorn` on the answers (ASVS 5.0 V13.4.6, F12.3), like the embeddings service.
# --reset-contextvars: each request starts from a clean context, so a log line Uvicorn writes for the connection later
# (keep-alive) never carries the previous request's id or user (F12.3, request context in the logs).
CMD ["uvicorn", "--factory", "api.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", \
     "--reset-contextvars"]
