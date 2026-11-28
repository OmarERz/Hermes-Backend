"""CPE mapping validation, candidate parsing and ranking."""

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from core.cpe.candidates import CpeDictionaryClient, clean_query, cpe_uri, parse_cpe_name, parse_cpe_parts, similarity
from core.cpe.mapping import MappingError, MappingInput, validate
from core.vulndata.http import JsonSource, SourceUnavailableError


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (MappingInput(" F5 ", "NGINX", nvd_part="a"), MappingInput("f5", "nginx", nvd_part="a")),
        (
            MappingInput(None, None, " F5 Networks ", " NGINX Plus "),
            MappingInput(None, None, "F5 Networks", "NGINX Plus"),
        ),
        (MappingInput("a", "b", "", "", "a"), MappingInput("a", "b", nvd_part="a")),
        # what the search proposes
        (MappingInput("vendor:inc", "wid+get", nvd_part="a"), MappingInput("vendor:inc", "wid+get", nvd_part="a")),
        # D-107: the part of the CPE name is kept (the kernel is an operating system), in lower case
        (MappingInput("linux", "linux_kernel", nvd_part="o"), MappingInput("linux", "linux_kernel", nvd_part="o")),
        (MappingInput("cisco", "asa_5505", nvd_part=" H "), MappingInput("cisco", "asa_5505", nvd_part="h")),
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
        MappingInput("linux", "linux_kernel", nvd_part="x"),  # not a CPE part
        MappingInput("linux", "linux_kernel"),  # an NVD pair needs its part (D-107)
        MappingInput("linux", "linux_kernel", nvd_part="  "),
        MappingInput(None, None, "Linux", "Linux", nvd_part="o"),  # a part needs the NVD pair (D-107)
    ],
)
def test_invalid_mappings_are_refused_with_a_readable_message(data: MappingInput) -> None:
    with pytest.raises(MappingError):
        validate(data)


def test_cpe_names_parse_with_escapes_and_wildcards() -> None:
    assert parse_cpe_name("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*") == ("f5", "nginx")
    assert parse_cpe_name("cpe:2.3:a:vendor\\:inc:wid\\+get:*:*:*:*:*:*:*:*") == ("vendor:inc", "wid+get")
    assert parse_cpe_name("cpe:2.3:h:acme:box:1:*:*:*:*:*:*:*") == ("acme", "box")  # the search keeps the part
    assert parse_cpe_name("cpe:2.3:x:acme:box:1:*:*:*:*:*:*:*") is None
    assert parse_cpe_name("cpe:2.3:a:*:x:1:*:*:*:*:*:*:*") is None
    assert parse_cpe_name("garbage") is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", ("o", "linux", "linux_kernel")),
        ("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", ("a", "f5", "nginx")),
        ("cpe:2.3:h:cisco:asa_5505:-:*:*:*:*:*:*:*", ("h", "cisco", "asa_5505")),
        ("cpe:2.3:A:f5:nginx:*:*:*:*:*:*:*:*", None),  # the part is lower case in CPE 2.3
        ("cpe:2.3:o:*:linux_kernel:*:*:*:*:*:*:*:*", None),
    ],
)
def test_the_part_of_a_cpe_name_is_read(name: str, expected: tuple[str, str, str] | None) -> None:
    assert parse_cpe_parts(name) == expected


def test_the_cpe_uri_keeps_the_stored_part() -> None:
    assert cpe_uri("linux", "linux_kernel", "o") == "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
    assert cpe_uri("cisco", "asa_5505", "h") == "cpe:2.3:h:cisco:asa_5505:*:*:*:*:*:*:*:*"
    assert cpe_uri("f5", "nginx") == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    assert cpe_uri("f5", "nginx", None) == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"  # a CNA-only mapping has no part
    assert cpe_uri("f5", "nginx", "x") == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


@pytest.mark.parametrize(
    ("name", "part"),
    [("cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*", "o"), ("cpe:2.3:h:cisco:asa_5505:-:*:*:*:*:*:*:*", "h")],
)
def test_dictionary_candidates_keep_their_part(name: str, part: str) -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"products": [{"cpe": {"cpeName": name, "titles": []}}], "totalResults": 1})

    client = CpeDictionaryClient(JsonSource(http=httpx.Client(transport=httpx.MockTransport(answer))))
    (found,) = client.search("some product")
    assert found.part == part
    assert cpe_uri(found.vendor, found.product, found.part).split(":")[2] == part


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


def test_mapping_errors_name_the_part_of_the_request_at_fault() -> None:
    with pytest.raises(MappingError) as cna:
        validate(MappingInput(None, None, "a" * 201, "b"))
    with pytest.raises(MappingError) as nvd:
        validate(MappingInput("linux", "linux_kernel"))
    assert (cna.value.field, nvd.value.field) == ("cna", "cpe")
