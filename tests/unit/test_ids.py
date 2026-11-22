"""UUIDv7 layout: version, variant and time ordering."""

from core.db.ids import new_id


def test_version_and_variant() -> None:
    value = new_id()
    assert value.version == 7
    assert value.variant == "specified in RFC 4122"


def test_time_ordered() -> None:
    first, second = new_id(now_ms=1_000), new_id(now_ms=2_000)
    assert first < second
    assert int.from_bytes(first.bytes[:6], "big") == 1_000
