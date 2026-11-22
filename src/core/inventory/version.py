"""Version normalization (ESC-08): the upstream version for matching and the distribution package version for OSV.

`7.2.4-1ubuntu0.2` keeps `7.2.4` as the version and `7.2.4-1ubuntu0.2` as the package version. Only a trailing
Debian or RPM style revision (starting with a digit) is stripped, so `2.0.0-rc1` stays whole: a pre-release is
a different version from its final release. The comparator (F1.4) decides what to do with what is left.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple

EPOCH: Final = re.compile(r"^\d+:")
REVISION: Final = re.compile(r"^(?P<upstream>[0-9][^\s-]*)-(?P<revision>[0-9][A-Za-z0-9.+~_]*)$")


class NormalizedVersion(NamedTuple):
    version: str
    package_version: str | None


def normalize_version(raw: str) -> NormalizedVersion | None:
    """Split a raw iTop version; None when there is nothing usable (blank): the caller records no finding (ESC-12)."""
    text = raw.strip()
    if not text:
        return None
    without_epoch = EPOCH.sub("", text)
    match = REVISION.match(without_epoch)
    upstream = match["upstream"] if match else without_epoch
    return NormalizedVersion(upstream, text if upstream != text else None)
