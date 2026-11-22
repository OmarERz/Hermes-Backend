"""OSV client: has a distribution already patched this CVE for this package version? (ESC-11)

`POST https://api.osv.dev/v1/query` with `{"package": {"name", "ecosystem"}, "version"}` answers
`{"vulns": [{"id", "aliases", "affected": [...]}], "next_page_token"}`; repeat with `page_token` until the token
is gone (checked against OSV's documentation on 22 Nov 2026). Querying with a version returns only the advisories
that affect that version, so a CVE that OSV knows for the package (query without version) but not for this version
was fixed by the distribution, possibly as a backport that upstream's range does not reflect. Nothing is stored:
the scan (F1.4) asks at scan time and decides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Literal

from core.vulndata.http import JsonSource, SourceUnavailableError
from core.vulndata.records import CVE_ID

OSV_URL: Final = "https://api.osv.dev/v1/query"
MAX_PAGES: Final = 20

BackportStatus = Literal["affected", "fixed", "unknown"]


@dataclass(frozen=True)
class OsvVuln:
    id: str
    aliases: tuple[str, ...]
    has_fix: bool = False  # some affected range names a `fixed` version: the evidence that a patch exists

    @property
    def cve_ids(self) -> frozenset[str]:
        return frozenset(i for i in (self.id, *self.aliases) if CVE_ID.match(i))


def _has_fix(vuln: dict[str, Any]) -> bool:
    """A range that starts at the very beginning (`introduced: "0"`) and names a `fixed` version.

    Only then does "the advisory no longer lists this version" mean "this version carries the fix": with a later
    `introduced`, an older version is simply outside the advisory.
    """
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or [] if isinstance(affected, dict) else []:
            events = [e for e in rng.get("events") or [] if isinstance(e, dict)] if isinstance(rng, dict) else []
            if any(e.get("introduced") == "0" for e in events) and any("fixed" in e for e in events):
                return True
    return False


@dataclass
class OsvClient:
    source: JsonSource
    url: str = OSV_URL

    def query(self, package: str, ecosystem: str, version: str | None = None) -> list[OsvVuln]:
        """Every advisory for the package (or only those affecting `version`), following the pagination."""
        found: list[OsvVuln] = []
        token: str | None = None
        for _ in range(MAX_PAGES):
            body: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
            if version is not None:
                body["version"] = version
            if token:
                body["page_token"] = token
            answer = self.source.post(self.url, body)
            if not isinstance(answer, dict) or not isinstance(answer.get("vulns", []), list):
                raise SourceUnavailableError("incomplete OSV answer")
            for vuln in answer.get("vulns", []):
                if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                    aliases = tuple(str(a) for a in vuln.get("aliases") or [])
                    found.append(OsvVuln(vuln["id"], aliases, _has_fix(vuln)))
            token = answer.get("next_page_token")
            if not token:
                return found
        raise SourceUnavailableError("too many OSV pages")

    def backport_evidence(
        self, cve_id: str, package: str, ecosystem: str, version: str
    ) -> tuple[BackportStatus, str | None]:
        """Status plus the OSV advisory id that proves a `fixed` result (None otherwise).

        `fixed` when the distribution's advisory covers the CVE, names a fix, and no longer affects this version.
        `unknown` when OSV has no advisory for the CVE and package, or the advisory names no fixed version (a
        `last_affected` only, or an older version than the one introduced): no evidence, so no suppression.
        """
        if not CVE_ID.match(cve_id):
            raise ValueError("not a CVE id")
        covering = [v for v in self.query(package, ecosystem) if cve_id in v.cve_ids]
        fixing = [v for v in covering if v.has_fix]
        if not fixing:
            return "unknown", None
        affecting = self.query(package, ecosystem, version)
        if any(cve_id in v.cve_ids for v in affecting):
            return "affected", None
        return "fixed", fixing[0].id

    def backport_status(self, cve_id: str, package: str, ecosystem: str, version: str) -> BackportStatus:
        return self.backport_evidence(cve_id, package, ecosystem, version)[0]
