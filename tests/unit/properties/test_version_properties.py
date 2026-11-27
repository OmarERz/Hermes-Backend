"""Properties of the tolerant version comparison (ESC-13): a total preorder where `+build` and `v` are ignored."""

from __future__ import annotations

from hypothesis import assume, given
from hypothesis import strategies as st

from core.scan.versions import (
    POST_RELEASE,
    PRE_RELEASE,
    compare_versions,
    in_range,
    known_order,
    parse_version,
    release_of,
)

numbers = st.integers(min_value=0, max_value=10_000)
release = st.lists(numbers, min_size=1, max_size=5).map(lambda parts: ".".join(map(str, parts)))
label = st.sampled_from(sorted(PRE_RELEASE) + sorted(POST_RELEASE))
suffix = st.one_of(
    st.just(""),
    st.builds(lambda name, n, sep: f"{sep}{name}{n}", label, numbers, st.sampled_from(["", "-", ".", "_"])),
    st.builds(lambda name, sep: f"{sep}{name}", label, st.sampled_from(["-", "."])),
)
versions = st.builds(lambda base, tail: base + tail, release, suffix).filter(lambda v: parse_version(v) is not None)
build = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-", min_size=1, max_size=12)


@given(versions)
def test_a_version_equals_itself(version: str) -> None:
    assert compare_versions(version, version) == 0


@given(versions, versions)
def test_the_order_is_antisymmetric(a: str, b: str) -> None:
    assert compare_versions(a, b) == -(compare_versions(b, a) or 0)


@given(versions, versions, versions)
def test_the_order_is_transitive(a: str, b: str, c: str) -> None:
    ab, bc, ac = compare_versions(a, b), compare_versions(b, c), compare_versions(a, c)
    assert None not in (ab, bc, ac)
    if ab is not None and bc is not None and ac is not None:
        if ab <= 0 and bc <= 0:
            assert ac <= 0
        if ab >= 0 and bc >= 0:
            assert ac >= 0
        if ab == 0 and bc == 0:
            assert ac == 0


@given(versions, build)
def test_build_metadata_is_ignored(version: str, metadata: str) -> None:
    assert compare_versions(version, f"{version}+{metadata}") == 0
    assert parse_version(f"{version}+{metadata}") == parse_version(version)


@given(versions)
def test_prefix_case_and_padding_are_ignored(version: str) -> None:
    assert compare_versions(version, f"v{version.upper()}") == 0
    assert compare_versions(version, f" {version} ") == 0


@given(release)
def test_trailing_zero_components_do_not_matter(base: str) -> None:
    assert compare_versions(base, f"{base}.0") == 0
    assert compare_versions(base, f"{base}.0.0") == 0


@given(st.lists(numbers, min_size=1, max_size=4), numbers)
def test_a_larger_last_number_is_newer(parts: list[int], bump: int) -> None:
    assume(bump > 0)
    older = ".".join(map(str, parts))
    newer = ".".join(map(str, [*parts[:-1], parts[-1] + bump]))
    assert compare_versions(older, newer) == -1


@given(release, st.sampled_from(sorted(PRE_RELEASE)), numbers)
def test_a_pre_release_precedes_its_release(base: str, tag: str, n: int) -> None:
    assert compare_versions(f"{base}-{tag}{n}", base) == -1


@given(release, st.sampled_from(sorted(POST_RELEASE)), numbers)
def test_a_post_release_follows_its_release(base: str, tag: str, n: int) -> None:
    assert compare_versions(base, f"{base}.{tag}{n}") == -1


@given(st.text(max_size=150))
def test_arbitrary_text_never_raises(text: str) -> None:
    parsed = parse_version(text)
    assert parsed is None or isinstance(parsed.release, tuple)
    assert compare_versions(text, "1.0") in (-1, 0, 1, None)


@given(versions, versions, versions, st.booleans(), st.booleans())
def test_in_range_agrees_with_the_order(version: str, start: str, end: str, start_in: bool, end_in: bool) -> None:
    inside = in_range(version, start, start_in, end, end_in)
    lo, hi = compare_versions(version, start), compare_versions(version, end)
    assert lo is not None and hi is not None and inside is not None
    expected = (lo > 0 or (lo == 0 and start_in)) and (hi < 0 or (hi == 0 and end_in))
    assert inside is expected


@given(versions)
def test_a_range_without_bounds_covers_every_readable_version(version: str) -> None:
    assert in_range(version, None, None, None, None) is True


@given(st.text(alphabet="0123456789.\u0660\u0661\u0662\u0966\u0967\uff11\uff12", min_size=1, max_size=12))
def test_digits_of_other_scripts_are_not_version_numbers(text: str) -> None:
    if not text.isascii():
        assert parse_version(text) is None


def test_arabic_indic_digits_are_not_a_version() -> None:
    assert parse_version("\u0661.\u0662") is None
    assert compare_versions("\u0661.\u0662", "1.2") is None


letters = st.text(alphabet="abcdefghijklmnopqrstuvwyz", min_size=1, max_size=3)  # no "x": a wildcard
letter_releases = st.builds(lambda base, tail: base + tail, release, letters)
off_scale = letter_releases.filter(lambda v: parse_version(v) is None)  # `1.1.1zd`, not `1.0a` (alpha) or `2.0p` (post)


@given(st.one_of(versions, letter_releases), st.one_of(versions, letter_releases))
def test_known_order_agrees_with_the_comparator_and_is_antisymmetric(a: str, b: str) -> None:
    order = known_order(a, b)
    if compare_versions(a, b) is not None:
        assert order == compare_versions(a, b)
    assert known_order(b, a) == (None if order is None else -order)


@given(off_scale, st.one_of(versions, letter_releases))
def test_a_letter_release_is_ordered_only_by_its_release(a: str, b: str) -> None:
    release_a, release_b = release_of(a), release_of(b)
    assert release_a is not None and release_b is not None
    order = known_order(a, b)
    if release_a != release_b:
        assert order == (release_a > release_b) - (release_a < release_b)
    elif a.lower() != b.lower():
        assert order is None


@given(st.text(max_size=150), st.text(max_size=150))
def test_known_order_never_raises(a: str, b: str) -> None:
    assert known_order(a, b) in (-1, 0, 1, None)
