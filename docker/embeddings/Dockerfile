# syntax=docker/dockerfile:1
# Embeddings service (docs/02 §4, 22 nov 2026): sentence-transformers on CPU behind local HTTP, so the backend image
# carries no torch. Internal Compose network only. Base image pinned by digest (docs/14 §10.4), the same Python as
# the backend; dependencies locked with hashes in this directory's uv.lock (CPU-only torch from the PyTorch index).

FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
# The model is pinned to one Hugging Face commit, downloaded once, here, and saved as a plain directory with a manifest
# of SHA-256 hashes; at start app.py checks the manifest and every file, and at run time nothing is fetched (offline).
# TODO(P-019): confirm the model with the team. Changing the revision is a reviewed change (Dependabot cannot see it).
ARG EMBEDDINGS_MODEL_NAME=intfloat/multilingual-e5-small
ARG EMBEDDINGS_MODEL_REVISION=614241f622f53c4eeff9890bdc4f31cfecc418b3
COPY app.py ./app.py
RUN HF_HOME=/tmp/hf /opt/venv/bin/python app.py prepare "$EMBEDDINGS_MODEL_NAME" "$EMBEDDINGS_MODEL_REVISION" /opt/model \
 && rm -rf /tmp/hf \
 && chmod -R a+rX,go-w /opt/model

FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS runtime
ARG EMBEDDINGS_MODEL_NAME=intfloat/multilingual-e5-small
ARG EMBEDDINGS_MODEL_REVISION=614241f622f53c4eeff9890bdc4f31cfecc418b3
RUN groupadd --system --gid 10002 embeddings \
 && useradd --system --uid 10002 --gid embeddings --no-create-home embeddings
COPY --from=build --chown=root:root /opt/venv /opt/venv
COPY --from=build --chown=root:root /opt/model /opt/model
COPY --chown=root:root app.py /app/app.py
WORKDIR /app
# Read-only root filesystem in Compose: every cache goes to the /tmp tmpfs and the hub is never contacted.
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp \
    HF_HOME=/tmp/hf HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 OMP_NUM_THREADS=2 \
    EMBEDDINGS_MODEL_DIR=/opt/model EMBEDDINGS_MODEL_NAME=$EMBEDDINGS_MODEL_NAME \
    EMBEDDINGS_MODEL_REVISION=$EMBEDDINGS_MODEL_REVISION
USER embeddings
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=60s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status != 200)"]
CMD ["uvicorn", "--factory", "app:create_app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
