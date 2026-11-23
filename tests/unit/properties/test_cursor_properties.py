"""Properties of the signed pagination cursor (API-02): it round-trips and any edit is refused."""

from __future__ import annotations

import string
import uuid
from datetime import UTC, datetime

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from api.errors import ApiError
from api.pagination import CursorSigner, KeyPart, Keyset, PageParams, decode_key, encode_key

SIGNER = CursorSigner("property-test-key-0123456789abcdef")
OTHER = CursorSigner("another-property-test-key-fedcba98")
scalars = st.one_of(
    st.text(max_size=40),
    st.integers(min_value=-(2**63), max_value=2**63),
    st.floats(allow_nan=False, allow_infinity=False),
    st.booleans(),
    st.none(),
)
keysets = st.dictionaries(st.text(min_size=1, max_size=12), scalars, min_size=1, max_size=6)
moments = st.integers(min_value=946_684_800, max_value=4_102_444_800).map(lambda s: datetime.fromtimestamp(s, UTC))
KeyValue = int | uuid.UUID | datetime
key_values = st.lists(st.one_of(st.integers(min_value=0, max_value=2**62), st.uuids(), moments), min_size=1, max_size=3)


def part_of(value: KeyValue) -> KeyPart:
    if isinstance(value, uuid.UUID):
        return "uuid"
    return "time" if isinstance(value, datetime) else "int"


def refused(cursor: str) -> bool:
    try:
        SIGNER.decode(cursor)
    except ApiError as error:
        return error.status_code == 400 and error.code == "invalid_cursor"
    return False


@given(keysets)
def test_a_cursor_round_trips(keyset: Keyset) -> None:
    assert SIGNER.decode(SIGNER.encode(keyset)) == keyset


@given(keysets)
def test_encoding_is_deterministic_and_url_safe(keyset: Keyset) -> None:
    cursor = SIGNER.encode(keyset)
    assert cursor == SIGNER.encode(dict(reversed(list(keyset.items()))))
    assert set(cursor) <= set(string.ascii_letters + string.digits + "-_.")
    assert cursor.count(".") == 1


@given(keysets, st.data())
def test_changing_any_character_is_refused(keyset: Keyset, data: st.DataObject) -> None:
    cursor = SIGNER.encode(keyset)
    index = data.draw(st.integers(min_value=0, max_value=len(cursor) - 1))
    replacement = data.draw(st.sampled_from(string.ascii_letters + string.digits + "-_."))
    assume(replacement != cursor[index])
    assert refused(cursor[:index] + replacement + cursor[index + 1 :])


@given(keysets, st.data())
def test_truncating_extending_or_dropping_a_character_is_refused(keyset: Keyset, data: st.DataObject) -> None:
    cursor = SIGNER.encode(keyset)
    index = data.draw(st.integers(min_value=0, max_value=len(cursor) - 1))
    assert refused(cursor[:index])
    assert refused(cursor[:index] + cursor[index + 1 :])
    assert refused(cursor + data.draw(st.sampled_from(["A", ".", "=", "AA"])))
    assert refused(cursor + "." + cursor)


@given(keysets, keysets)
def test_swapping_a_signature_between_cursors_is_refused(first: Keyset, second: Keyset) -> None:
    assume(first != second)
    payload = SIGNER.encode(first).split(".")[0]
    signature = SIGNER.encode(second).split(".")[1]
    assert refused(f"{payload}.{signature}")


@given(keysets)
def test_a_cursor_from_another_key_is_refused(keyset: Keyset) -> None:
    assert refused(OTHER.encode(keyset))


@given(st.text(max_size=300))
def test_arbitrary_text_is_never_accepted_and_only_raises_the_documented_error(text: str) -> None:
    with pytest.raises(ApiError) as caught:
        SIGNER.decode(text)
    assert (caught.value.status_code, caught.value.code) == (400, "invalid_cursor")


@given(key_values)
def test_list_cursors_round_trip_their_typed_values(values: list[KeyValue]) -> None:
    cursor = encode_key(SIGNER, "things", values)
    assert cursor is not None
    params = PageParams(limit=10, keyset=SIGNER.decode(cursor))
    assert decode_key(params, "things", [part_of(v) for v in values]) == tuple(values)


@given(key_values)
def test_a_cursor_only_works_for_the_list_that_issued_it(values: list[KeyValue]) -> None:
    cursor = encode_key(SIGNER, "things", values)
    assert cursor is not None
    params = PageParams(limit=10, keyset=SIGNER.decode(cursor))
    with pytest.raises(ApiError):
        decode_key(params, "others", [part_of(v) for v in values])
