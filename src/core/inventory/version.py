"""Version normalization (ESC-08): the upstream version for matching and the distribution package version for OSV.

`7.2.4-1ubuntu0.2` keeps `7.2.4` as the version and `7.2.4-1ubuntu0.2` as the package version. Only a trailing
Debian or RPM style revision that names its distribution (ubuntu, deb, el9...) is stripped, so `2.0.0-rc1`
stays whole: a pre-release is a different version from its final release. The comparator (F1.4) decides the rest.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple

EPOCH: Final = re.compile(r"^[0-9]+:")
# A revision counts as a distribution one only with evidence in it (ubuntu, deb, el9, fc39, bpo...). A bare
# `1.2.3-1` is ambiguous (could be an upstream version) and is kept whole.
REVISION: Final = re.compile(
    r"^(?P<upstream>[0-9][^\s-]*)-(?P<revision>[0-9][A-Za-z0-9.+~_]*(?:ubuntu|deb|bpo|build|\.?el[0-9]|\.?fc[0-9])[A-Za-z0-9.+~_]*)$"
)
ANY_REVISION: Final = re.compile(r"^(?P<upstream>[0-9][^\s-]*)-(?P<revision>[0-9][A-Za-z0-9.+~_]*)$")


class NormalizedVersion(NamedTuple):
    version: str
    package_version: str | None


def normalize_version(raw: str) -> NormalizedVersion | None:
    """Split a raw iTop version; None when there is nothing usable (blank): the caller records no finding (ESC-12)."""
    text = raw.strip()
    if not text:
        return None
    without_epoch = EPOCH.sub("", text)
    # An epoch only exists in distribution versions, so with one any trailing numeric revision is a package revision.
    match = (ANY_REVISION if without_epoch != text else REVISION).match(without_epoch)
    upstream = match["upstream"] if match else without_epoch
    return NormalizedVersion(upstream, text if upstream != text else None)
