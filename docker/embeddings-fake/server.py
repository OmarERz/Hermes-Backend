"""Deterministic stand-in for the embeddings service, for the CI dynamic jobs only (compose.ci.yaml).

The real image (`docker/embeddings`) weighs about 2.8 GB (torch plus the model); Schemathesis and ZAP test the API and
never the vectors, so CI swaps it for this standard-library server with the same contract: `POST /embed` with the
same limits (413 for a large body, declared or chunked; 422 for an invalid one) and `GET /health`. Vectors are a
hashed bag of words, L2-normalised, so texts that share words are similar. It reports the configured model name so
the worker accepts it; it is never used outside CI (the weekly Trivy scan and production use the real image).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final

MODEL_NAME = os.environ.get("EMBEDDINGS_MODEL_NAME", "intfloat/multilingual-e5-small")
DIMENSIONS: Final = 384
MAX_TEXTS: Final = 64
MAX_CHARS: Final = 4_000
MAX_BODY_BYTES: Final = 2 * 1024 * 1024
WORD: Final = re.compile(r"\w+")


def embed(text: str) -> list[float]:
    vector = [0.0] * DIMENSIONS
    for word in WORD.findall(text.lower()):
        vector[int.from_bytes(hashlib.sha256(word.encode()).digest()[:4], "big") % DIMENSIONS] += 1.0
    norm = math.sqrt(sum(x * x for x in vector))
    if norm == 0:
        vector[0], norm = 1.0, 1.0
    return [x / norm for x in vector]


def valid_texts(body: object) -> list[str] | None:
    if not isinstance(body, dict) or set(body) != {"texts"}:
        return None
    texts = body["texts"]
    if not isinstance(texts, list) or not 1 <= len(texts) <= MAX_TEXTS:
        return None
    if not all(isinstance(t, str) and len(t) <= MAX_CHARS for t in texts):
        return None
    return texts


class Handler(BaseHTTPRequestHandler):
    server_version = "embeddings-fake"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"status": "ok", "model": MODEL_NAME, "revision": "ci-fake"})
        else:
            self._json(404, {"detail": "Not Found"})

    def do_POST(self) -> None:
        if self.path != "/embed":
            self._json(404, {"detail": "Not Found"})
            return
        body = self._body()
        if body is None:
            self._json(413, {"detail": f"request body above {MAX_BODY_BYTES} bytes"})
            return
        try:
            texts = valid_texts(json.loads(body))
        except ValueError:
            texts = None
        if texts is None:
            self._json(422, {"detail": "invalid request"})
            return
        vectors = [embed(text) for text in texts]
        self._json(200, {"model": MODEL_NAME, "revision": "ci-fake", "dimensions": DIMENSIONS, "vectors": vectors})

    def _body(self) -> bytes | None:
        """The request body, or None above the limit (declared Content-Length, or a chunked body as it arrives)."""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            parts: list[bytes] = []
            size = 0
            while chunk := int(self.rfile.readline().split(b";")[0].strip() or b"0", 16):
                size += chunk
                if size > MAX_BODY_BYTES:
                    self.close_connection = True
                    return None
                parts.append(self.rfile.read(chunk))
                self.rfile.readline()  # the CRLF after each chunk
            self.rfile.readline()  # the empty line after the last chunk
            return b"".join(parts)
        declared = self.headers.get("Content-Length", "0")
        length = int(declared) if declared.isdigit() else 0
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            return None
        return self.rfile.read(length)

    def log_message(self, fmt: str, *args: object) -> None:
        """Quiet: one line per request would flood the CI log."""

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(host: str = "", port: int = 8080) -> ThreadingHTTPServer:
    """All interfaces of the container by default ("" in http.server): only its internal Compose network sees it."""
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    serve().serve_forever()
