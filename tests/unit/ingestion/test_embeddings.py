"""Embeddings: the e5 input, the shape checks and the HTTP client of the embeddings service (respx, no network)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from core.ingestion.embeddings import (
    EMBEDDING_DIMENSIONS,
    EMBEDDING_MODEL,
    MAX_EMBED_CHARS,
    EmbeddingError,
    HttpEmbedder,
    HttpEmbedderConfig,
    check_vectors,
    embedding_input,
)

pytestmark = pytest.mark.unit
URL = "http://embeddings:8080"


def vectors(n: int, value: float = 0.5, width: int = EMBEDDING_DIMENSIONS) -> dict[str, object]:
    return {"model": EMBEDDING_MODEL, "dimensions": width, "vectors": [[value] * width for _ in range(n)]}


def embedder(max_attempts: int = 3, batch_size: int = 32) -> tuple[HttpEmbedder, list[float]]:
    slept: list[float] = []
    config = HttpEmbedderConfig(max_attempts=max_attempts, batch_size=batch_size, sleep=slept.append)
    return HttpEmbedder(URL + "/", config), slept


def test_input_is_an_e5_passage_with_title_and_start_of_text() -> None:
    value = embedding_input(" Title ", "body")
    assert value == "passage: Title\nbody"
    assert embedding_input("T", None) == "passage: T\n"
    assert len(embedding_input("T", "x" * 10_000)) == MAX_EMBED_CHARS


def test_wrong_width_and_non_finite_vectors_are_rejected() -> None:
    with pytest.raises(EmbeddingError, match="wrong shape"):
        check_vectors([[0.0] * EMBEDDING_DIMENSIONS], 2)
    with pytest.raises(EmbeddingError, match="wrong shape"):
        check_vectors([[0.0] * 10], 1)
    with pytest.raises(EmbeddingError, match="non-finite"):
        check_vectors([[float("nan")] * EMBEDDING_DIMENSIONS], 1)


@respx.mock
def test_texts_are_posted_in_batches_and_the_vectors_come_back_in_order() -> None:
    sent: list[list[str]] = []

    def answer(request: httpx.Request) -> httpx.Response:
        texts = json.loads(request.content)["texts"]
        sent.append(texts)
        return httpx.Response(200, json=vectors(len(texts), value=float(len(sent))))

    respx.post(f"{URL}/embed").mock(side_effect=answer)
    embed, slept = embedder(batch_size=2)
    result = embed(["a", "b", "c"])
    assert sent == [["a", "b"], ["c"]]
    assert [row[0] for row in result] == [1.0, 1.0, 2.0]
    assert embed([]) == []
    assert slept == []


@respx.mock
def test_transport_errors_and_5xx_are_retried_with_backoff() -> None:
    route = respx.post(f"{URL}/embed").mock(
        side_effect=[httpx.ConnectError("down"), httpx.Response(503), httpx.Response(200, json=vectors(1))]
    )
    embed, slept = embedder()
    assert len(embed(["a"])) == 1
    assert route.call_count == 3
    assert slept == [1.0, 2.0]


@respx.mock
def test_the_service_down_fails_closed_after_the_last_attempt() -> None:
    respx.post(f"{URL}/embed").mock(side_effect=httpx.ReadTimeout("slow"))
    embed, slept = embedder(max_attempts=2)
    with pytest.raises(EmbeddingError, match=r"unavailable: no answer \(ReadTimeout\)"):
        embed(["a"])
    assert slept == [1.0]


@respx.mock
def test_a_client_error_is_not_retried() -> None:
    route = respx.post(f"{URL}/embed").mock(return_value=httpx.Response(422, json={"detail": "x"}))
    embed, slept = embedder()
    with pytest.raises(EmbeddingError, match="HTTP 422"):
        embed(["a"])
    assert (route.call_count, slept) == (1, [])


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(200, text="not json"), "did not answer JSON"),
        (httpx.Response(200, json=[1, 2]), "unexpected shape"),
        (httpx.Response(200, json={"model": EMBEDDING_MODEL, "vectors": "x"}), "unexpected shape"),
        (httpx.Response(200, json={"model": EMBEDDING_MODEL, "vectors": [["a"]]}), "non-numeric"),
        (httpx.Response(200, json={**vectors(1), "model": "other/model-384"}), "runs another model"),
        (httpx.Response(200, json={"vectors": [[0.5] * EMBEDDING_DIMENSIONS]}), "runs another model"),
        (httpx.Response(200, json=vectors(1, width=10)), "wrong shape"),
        (httpx.Response(200, json=vectors(2)), "wrong shape"),
    ],
)
@respx.mock
def test_bad_answers_are_rejected(response: httpx.Response, message: str) -> None:
    respx.post(f"{URL}/embed").mock(return_value=response)
    embed, _ = embedder()
    with pytest.raises(EmbeddingError, match=message):
        embed(["a"])


def test_an_injected_client_is_reused_and_not_closed() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=vectors(1)))
    with httpx.Client(transport=transport) as client:
        embed = HttpEmbedder(URL, http=client)
        assert len(embed(["a"])) == 1
        assert len(embed(["b"])) == 1
        assert not client.is_closed
