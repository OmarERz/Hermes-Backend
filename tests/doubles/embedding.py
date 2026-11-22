"""Deterministic embedding double: hashed bag of words, L2 normalized (no model download, no network)."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence

from core.ingestion.embeddings import EMBEDDING_DIMENSIONS

_WORD = re.compile(r"[a-z0-9]+")


def fake_embed(texts: Sequence[str]) -> list[list[float]]:
    """Texts that share words get a high cosine similarity; unrelated texts get about zero."""
    vectors: list[list[float]] = []
    for text in texts:
        vector = [0.0] * EMBEDDING_DIMENSIONS
        for word in _WORD.findall(text.lower()):
            slot = int.from_bytes(hashlib.sha256(word.encode()).digest()[:4], "big") % EMBEDDING_DIMENSIONS
            vector[slot] += 1.0
        norm = math.sqrt(sum(x * x for x in vector)) or 1.0
        vectors.append([x / norm for x in vector])
    return vectors
