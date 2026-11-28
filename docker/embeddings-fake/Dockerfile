# Deterministic stand-in for the embeddings service, for the CI dynamic jobs only (compose.ci.yaml): standard library,
# no dependencies, a few MB instead of the 2.8 GB real image. Same base image as the backend, pinned by digest.
FROM python:3.12.16-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64
RUN groupadd --system --gid 10002 embeddings \
 && useradd --system --uid 10002 --gid embeddings --no-create-home embeddings
COPY --chown=root:root server.py /app/server.py
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER embeddings
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status != 200)"]
CMD ["python", "server.py"]
