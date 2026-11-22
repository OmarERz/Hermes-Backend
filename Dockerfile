# syntax=docker/dockerfile:1
# Backend image for the api and workers services (same image, different command).
# Base images pinned by digest (docs/14 §10.4).

FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS runtime
RUN groupadd --system --gid 10001 hermes && useradd --system --uid 10001 --gid hermes --no-create-home hermes
WORKDIR /app
COPY --from=build --chown=root:root /app/.venv /app/.venv
# Alembic configuration and migrations (the migrate service runs them as the migrator role)
COPY --chown=root:root alembic.ini ./
COPY --chown=root:root migrations ./migrations
# JSON contracts: the LLM client loads its tool definitions from here (SCHEMAS_DIR); an installed package has no schemas/
COPY --chown=root:root schemas ./schemas
ENV PATH="/app/.venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SCHEMAS_DIR=/app/schemas
USER hermes
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status != 200)"]
CMD ["uvicorn", "--factory", "api.app:create_app", "--host", "0.0.0.0", "--port", "8000"]
