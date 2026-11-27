"""Affected ranges of the group's product in a review package (D-101, docs/07 §13 JUE-MIT-10).

Correlation renders every range of the CVE as `vendor:product [start,end)` (`core/correlation/packages.py`): `[` and
`]` include the bound, `(` and `)` exclude it, and an empty bound leaves that side open (`(,)` covers every version).
Only the ranges of the group's product count: vendor and product equal to those of `group.cpe` (`vendor:product`, or
a CPE 2.3 name) after normalization, both of them (COR-02). The name is what comes before a ` [` or ` (` that starts
the interval; spaces around a bound are dropped (`[3.0.0,3.0.23 )`, a CNA `lessThan` keeps them). A range of the product
whose interval cannot be read is kept as unreadable: no version is known to be outside it. A string that names no
product of the group is left out. A version is compared with each bound by the scan's comparator without guessing
(ESC-13).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.correlation.keys import normalize_name
from core.judge.package import ReviewPackage
from core.scan.versions import known_order

_SPLIT = re.compile(r"\s(?=[\[(])")
_INTERVAL = re.compile(r"([\[(])([^,]*),([^,]*)([\])])")
_CPE23 = "cpe:2.3:"
_UNESCAPED_COLON = re.compile(r"(?<!\\):")
_ESCAPED = re.compile(r"\\(.)")
_ANY = frozenset({"", "*", "-"})  # a CPE 2.3 field that names no vendor or product
_PRODUCT_FIELD = 4  # cpe:2.3:part:vendor:product:...


@dataclass(frozen=True)
class AffectedRange:
    text: str  # as the package renders it
    start: str | None
    start_inclusive: bool
    end: str | None
    end_inclusive: bool
    readable: bool = True

    def contains(self, version: str) -> bool | None:
        """True inside, False outside, None when the comparator cannot tell (ESC-13). One bound that leaves the
        version out decides, even if the other bound cannot be compared; a range with no bounds holds every version."""
        if not self.readable:
            return None
        checks: list[bool | None] = []
        if self.start is not None:
            order = known_order(version, self.start)
            checks.append(None if order is None else order > 0 or (order == 0 and self.start_inclusive))
        if self.end is not None:
            order = known_order(version, self.end)
            checks.append(None if order is None else order < 0 or (order == 0 and self.end_inclusive))
        if False in checks:
            return False
        return None if None in checks else True


def _key(vendor: str, product: str) -> str | None:
    vendor, product = normalize_name(vendor), normalize_name(product)
    return f"{vendor}:{product}" if vendor not in _ANY and product not in _ANY else None


def product_key(cpe: str | None) -> str | None:
    """The normalized `vendor:product` of the group's CPE (`openssl:openssl`, `cpe:2.3:a:openssl:openssl:*:…`)."""
    if not cpe:
        return None
    if cpe.lower().startswith(_CPE23):
        fields = _UNESCAPED_COLON.split(cpe)
        if len(fields) <= _PRODUCT_FIELD:
            return None
        return _key(_ESCAPED.sub(r"\1", fields[3]), _ESCAPED.sub(r"\1", fields[_PRODUCT_FIELD]))
    vendor, _, product = cpe.partition(":")
    return _key(vendor, product)


def product_ranges(package: ReviewPackage) -> tuple[AffectedRange, ...]:
    """The affected ranges of the group's product, as the package carries them; none without a group or a CPE."""
    group, cve = package.content["group"], package.cve_data
    key = product_key(group.get("cpe")) if group else None
    if key is None or cve is None:
        return ()
    found = (_read(str(text), key) for text in cve["affected_ranges"])
    return tuple(affected for affected in found if affected is not None)


def _read(text: str, key: str) -> AffectedRange | None:
    """The range a string gives for the product, or None when it is a range of another product or of none."""
    for split in _SPLIT.finditer(text):
        vendor, colon, product = text[: split.start()].partition(":")
        if not colon or _key(vendor, product) != key:
            continue
        bounds = _INTERVAL.fullmatch(text, split.end())
        if bounds is None:
            return AffectedRange(text, None, False, None, False, readable=False)
        opening, start, end, closing = bounds.groups()
        return AffectedRange(text, start.strip() or None, opening == "[", end.strip() or None, closing == "]")
    return None
