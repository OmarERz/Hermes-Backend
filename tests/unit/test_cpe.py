"""CPE mapping validation, candidate parsing and ranking."""

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from core.cpe.candidates import CpeDictionaryClient, clean_query, parse_cpe_name, similarity
from core.cpe.mapping import MappingError, MappingInput, validate
from core.vulndata.http import JsonSource, SourceUnavailableError


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (MappingInput(" F5 ", "NGINX"), MappingInput("f5", "nginx")),
        (
            MappingInput(None, None, " F5 Networks ", " NGINX Plus "),
            MappingInput(None, None, "F5 Networks", "NGINX Plus"),
        ),
        (MappingInput("a", "b", "", ""), MappingInput("a", "b")),
        (MappingInput("vendor:inc", "wid+get"), MappingInput("vendor:inc", "wid+get")),  # what the search proposes
    ],
)
def test_valid_mappings_are_normalized(data: MappingInput, expected: MappingInput) -> None:
    assert validate(data) == expected


@pytest.mark.parametrize(
    "data",
    [
        MappingInput(),
        MappingInput("f5", None),
        MappingInput(None, None, "vendor", None),
        MappingInput("f5 inc", "nginx"),
        MappingInput("-f5", "nginx"),
        MappingInput("f5", "ngi/nx"),
        MappingInput("f5", "nginx;drop"),
        MappingInput(None, None, "a" * 201, "b"),
        MappingInput(None, None, "a\x00b", "c"),
    ],
)
def test_invalid_mappings_are_refused_with_a_readable_message(data: MappingInput) -> None:
    with pytest.raises(MappingError):
        validate(data)


def test_cpe_names_parse_with_escapes_and_wildcards() -> None:
    assert parse_cpe_name("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*") == ("f5", "nginx")
    assert parse_cpe_name("cpe:2.3:a:vendor\\:inc:wid\\+get:*:*:*:*:*:*:*:*") == ("vendor:inc", "wid+get")
    assert parse_cpe_name("cpe:2.3:h:acme:box:1:*:*:*:*:*:*:*") is None
    assert parse_cpe_name("cpe:2.3:a:*:x:1:*:*:*:*:*:*:*") is None
    assert parse_cpe_name("garbage") is None


def test_similarity_and_query_cleaning() -> None:
    assert similarity("nginx", "f5", "nginx") == 0.5
    assert similarity("F5 nginx", "f5", "nginx") == 1.0
    assert similarity("postgresql", "postgresql", "postgresql") == 1.0
    assert similarity("zzz", "f5", "nginx") == 0.0
    assert similarity("", "f5", "nginx") == 0.0
    assert clean_query("  nginx   web ") == "nginx web"
    for bad in ("", "   ", "x" * 101, "a\x00b"):
        with pytest.raises(ValueError, match="search text"):
            clean_query(bad)


def dictionary(answer: object, status: int = 200) -> tuple[CpeDictionaryClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=answer)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    return CpeDictionaryClient(JsonSource(http=http, max_attempts=1), SecretStr("k")), seen


def product(name: str, deprecated: bool = False, title: str = "") -> dict[str, object]:
    return {
        "cpe": {"cpeName": name, "deprecated": deprecated, "titles": [{"lang": "en", "title": title}] if title else []}
    }


def test_dictionary_search_dedupes_skips_deprecated_and_scores() -> None:
    client, seen = dictionary(
        {
            "products": [
                product("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", title="F5 NGINX 1.24.0"),
                product("cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*"),
                product("cpe:2.3:a:old:nginx:1.0:*:*:*:*:*:*:*", deprecated=True),
                product("cpe:2.3:o:linux:kernel:5:*:*:*:*:*:*:*"),
                {"cpe": {"cpeName": 5}},
                "junk",
            ]
        }
    )
    found = client.search("nginx")
    assert [(c.vendor, c.product, c.source, c.title) for c in found] == [
        ("f5", "nginx", "nvd_dictionary", "F5 NGINX 1.24.0"),
        ("linux", "kernel", "nvd_dictionary", None),
    ]
    assert found[0].score == 0.5
    assert seen[0].url.params["keywordSearch"] == "nginx" and seen[0].headers["apiKey"] == "k"


def test_dictionary_incomplete_answer_is_an_error() -> None:
    client, _ = dictionary({"nope": 1})
    with pytest.raises(SourceUnavailableError, match="incomplete"):
        client.search("nginx")


def test_dictionary_search_follows_pages_until_the_total() -> None:
    pages = {
        "0": {
            "totalResults": 3,
            "products": [product("cpe:2.3:a:f5:nginx:1:*:*:*:*:*:*:*"), product("cpe:2.3:a:f5:nginx:2:*:*:*:*:*:*:*")],
        },
        "2": {"totalResults": 3, "products": [product("cpe:2.3:a:nginx:nginx:3:*:*:*:*:*:*:*")]},
    }
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params["startIndex"])
        return httpx.Response(200, json=pages[request.url.params["startIndex"]])

    client = CpeDictionaryClient(JsonSource(http=httpx.Client(transport=httpx.MockTransport(handler))))
    assert [(c.vendor, c.product) for c in client.search("nginx")] == [("f5", "nginx"), ("nginx", "nginx")]
    assert seen == ["0", "2"]
