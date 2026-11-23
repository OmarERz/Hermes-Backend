"""One escape-aware CPE splitter for our names and for NVD's criteria (F12.5)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from core.cpe.candidates import cpe_uri, parse_cpe_name
from core.cpe.fields import split_cpe_fields, unescape_cpe
from core.vulndata.nvd import _range

NAME_PARTS = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=15).filter(
    lambda s: s not in {"-", "*"}
)


@given(NAME_PARTS, NAME_PARTS, st.sampled_from(["1.0", "2.5"]))
def test_nvd_criteria_split_exactly_like_our_own_cpe_names(vendor: str, product: str, bound: str) -> None:
    """One splitter for both: the NVD parser reads back what `cpe_uri` wrote, whatever the escapes."""
    criteria = cpe_uri(vendor, product)
    assert parse_cpe_name(criteria) == (vendor, product)
    record = _range({"criteria": criteria, "vulnerable": True, "versionEndExcluding": bound})
    assert record is not None and (record.vendor, record.product, record.version_end) == (vendor, product, bound)


@given(st.text(alphabet=st.sampled_from("a:\\*"), max_size=30))
def test_splitting_then_joining_gives_the_name_back(text: str) -> None:
    assert ":".join(split_cpe_fields(text)) == text
    assert all(unescape_cpe(part) is not None for part in split_cpe_fields(text))
