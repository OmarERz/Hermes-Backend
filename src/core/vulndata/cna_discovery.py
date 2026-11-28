"""Which CVE.org records the refresh loads, and loading them (F15.9, D-103; ESC-05, ESC-09: certainty 0.9).

CVE.org has no search by product, so the candidates come from the NVD records the refresh already downloads (the
recency window and every KEV CVE): a CVE that NIST has not enriched yet (no NVD configuration) is a candidate when its
description names a mapped product (the CNA product, its NVD product or its iTop name, as whole words; names shorter
than `MIN_KEYWORD` characters are left out, since `go` or `r` would match ordinary text), or when its CNA (NVD's
`sourceIdentifier`) published a record whose `affected[]` names a mapped CNA pair. That second rule finds the CNAs
whose descriptions name a module instead of the product (CPython's `tarfile`); a CNA with more than `LEARN_MAX` such
CVEs published in the window (in the real window GitHub's and VulDB's have thousands) is only followed by name. A CNA
is known from the stored records that name a mapped pair while one of its records is in this refresh's NVD pages
(enriched by NIST or not); one with no such record in the last 90 days is only found by name until it publishes one.
Known CNAs compete with the named candidates for the request budget, newest publication first; a CNA learned from
this refresh's own records is followed with what is left of it. A CVE that NVD or CVE.org rejects loses its CNA
ranges, so the scan stops matching it.

Each candidate is one file of cvelistV5 on GitHub (`CveOrgClient`); downloading the whole list (hundreds of MB a
day) is not worth it for a few thousand records. The cache is the database: a candidate whose CNA ranges are already
stored and whose NVD `lastModified` is not newer than what we held before this refresh is not asked again (NVD
re-dates a record when it takes in a CNA update). That date only advances when the CNA record is stored: a record due
again that this refresh did not store (cap, outage, not found) gets its previous date back, so the next refresh asks
for it again. Requests are bounded by `MAX_REQUESTS` per refresh (every HTTP request counts, retries and redirects
included; a record is only asked when its worst case still fits), newest first; the rest wait for the next refresh. No
database transaction is open during a download: each batch is fetched, then stored in one short transaction. An outage
of GitHub stops this step and keeps what was stored.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import delete, func, select, tuple_, update
from sqlalchemy.orm import Session, sessionmaker

from core.db import models as m
from core.vulndata.cvelist import CveOrgClient, parse_cve5
from core.vulndata.http import MAX_REDIRECTS, SourceRefusedError, SourceUnavailableError
from core.vulndata.records import CNA_AFFECTED, CVE_ID, CveRecord, parse_timestamp
from core.vulndata.store import store_cve

MAX_REQUESTS: Final = 5_000  # HTTP requests per refresh, retries included (the first after mapping the kernel: ~3,500)
LEARN_MAX: Final = 500  # a CNA followed by its records publishes at most this many unenriched CVEs in the window
BATCH: Final = 200  # records fetched, then stored in one transaction
REJECTED: Final = "Rejected"
MIN_KEYWORD: Final = 3  # shorter names (`go`) would match ordinary words
EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Sighting:
    """An NVD record without NVD configuration, as the refresh saw it."""

    cve_id: str
    source: str  # NVD `sourceIdentifier`: the CNA that published it
    description: str
    published: datetime | None
    last_modified: datetime | None
    in_window: bool = True  # False: a KEV record of any age (it does not count towards `LEARN_MAX`)


def sighting(item: dict[str, Any], *, in_window: bool = True) -> Sighting | None:
    """The sighting of one NVD `vulnerabilities[]` entry; None when NVD configured it, rejected it or it is invalid."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict) or cve.get("configurations") or cve.get("vulnStatus") == REJECTED:
        return None
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not CVE_ID.match(cve_id):
        return None
    description = next(
        (str(d["value"]) for d in cve.get("descriptions") or [] if d.get("lang") == "en" and "value" in d), ""
    )
    return Sighting(
        cve_id,
        str(cve.get("sourceIdentifier") or ""),
        description,
        parse_timestamp(cve.get("published")),
        parse_timestamp(cve.get("lastModified")),
        in_window,
    )


@dataclass
class Observed:
    """What the refresh's NVD pages tell this step: the unenriched records, the CNA of every record and the rejected
    ones. Filled while the pages are stored (`core.pipeline.wiring._load_nvd`)."""

    sightings: list[Sighting] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)  # CVE id -> NVD `sourceIdentifier`, enriched or not
    rejected: set[str] = field(default_factory=set)

    def see(self, item: dict[str, Any], *, in_window: bool = True) -> None:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
            return
        if cve.get("vulnStatus") == REJECTED:
            self.rejected.add(cve["id"])
            return
        if cve.get("sourceIdentifier"):
            self.sources[cve["id"]] = str(cve["sourceIdentifier"])
        if (found := sighting(item, in_window=in_window)) is not None:
            self.sightings.append(found)


@dataclass(frozen=True)
class Watch:
    """The CNA pairs of the mappings (lower case) and the product names a candidate's description may carry."""

    pairs: frozenset[tuple[str, str]]
    names: re.Pattern[str] | None

    def mentions(self, text: str) -> bool:
        return self.names is not None and self.names.search(text) is not None

    def matches(self, record: CveRecord) -> bool:
        return any((r.vendor.lower(), r.product.lower()) in self.pairs for r in record.ranges)


def load_watch(session: Session) -> Watch:
    """From every mapping with a CNA pair: the pair, and its CNA product, NVD product and iTop name as keywords."""
    rows = session.execute(
        select(m.CpeMapping.cna_vendor, m.CpeMapping.cna_product, m.CpeMapping.nvd_product, m.SoftwareProduct.itop_name)
        .join(m.SoftwareProduct, m.SoftwareProduct.id == m.CpeMapping.software_product_id)
        .where(m.CpeMapping.cna_vendor.is_not(None), m.CpeMapping.cna_product.is_not(None))
    ).all()
    return watch_from([tuple(row) for row in rows])


def watch_from(rows: Sequence[Sequence[str | None]]) -> Watch:
    """The watch of (CNA vendor, CNA product, NVD product, iTop name) rows."""
    pairs = frozenset((str(row[0]).lower(), str(row[1]).lower()) for row in rows)
    names = [str(name).strip().lower() for row in rows for name in row[1:] if name]
    # an NVD product counts as written (`linux_kernel`) and with its underscores as spaces (`linux kernel`)
    words = {" ".join(form.split()) for name in names for form in (name, name.replace("_", " "))}
    words = {word for word in words if len(word) >= MIN_KEYWORD}
    if not words:
        return Watch(pairs, None)
    # literal words only (descriptions are third-party data); any run of spaces or line breaks between them
    alternatives = "|".join(re.escape(word).replace(r"\ ", r"\s+") for word in sorted(words, key=len, reverse=True))
    return Watch(pairs, re.compile(rf"(?<!\w)(?:{alternatives})(?!\w)", re.IGNORECASE))


@dataclass
class CveOrgResult:
    candidates: int = 0  # sightings worth a request in this refresh, before the cap
    fetched: int = 0
    stored: int = 0
    missing: int = 0  # not in cvelistV5 (404)
    skipped: int = 0  # rejected or not a CVE JSON 5 record
    unchanged: int = 0  # cached: CNA ranges held and NVD shows no change since
    followed_sources: list[str] = field(default_factory=list)
    requests: int = 0  # HTTP requests sent to GitHub, retries included
    cleared: int = 0  # rejected CVEs whose CNA ranges were removed
    git_only: int = 0  # product entries given only as git commits: not comparable (ESC-13), counted and logged
    capped: bool = False
    interrupted: bool = False


def refresh_cve_org(
    factory: sessionmaker[Session],
    client: CveOrgClient,
    observed: Observed,
    held: dict[str, datetime],
    *,
    limit: int | None = None,
) -> CveOrgResult:
    """Load the CVE.org records of the candidates (see the module notes); `held` is each CVE's `last_modified_at`
    as it was before this refresh wrote anything. Whatever happens, a record due again that was not stored gets its
    previous date back."""
    seen = _unique(observed.sightings)
    stored: set[str] | None = None
    loader: _Loader | None = None
    try:
        with factory() as session:
            watch = load_watch(session)
            stored = set(
                session.scalars(select(m.CveAffectedRange.cve_id).where(m.CveAffectedRange.source == CNA_AFFECTED))
            )
            hits = _mapped_hits(session, watch) if watch.pairs else set()
        loader = _Loader(factory, client, watch, MAX_REQUESTS if limit is None else limit)
        if watch.pairs:
            _load_candidates(loader, seen, observed.sources, hits, lambda s: _cached(s, stored, held))
        loader.result.cleared = clear_rejected(factory, (observed.rejected | loader.rejected_ids) & stored)
    finally:
        restore_due(factory, seen, stored, held, done=loader.stored_ids if loader is not None else ())
    result = loader.result
    log.info(
        "CVE.org: %d candidates, %d requests, %d stored, %d unchanged, %d missing, %d rejected cleared, %d product "
        "entries only as git commits (not comparable, ESC-13), CNAs followed: %s%s",
        result.candidates,
        result.requests,
        result.stored,
        result.unchanged,
        result.missing,
        result.cleared,
        result.git_only,
        ", ".join(result.followed_sources) or "none",
        " (capped)" if result.capped else "",
    )
    return result


def _cached(item: Sighting, stored: set[str], held: dict[str, datetime]) -> bool:
    """CNA ranges held and no change at NVD since the previous refresh: not asked again."""
    before = held.get(item.cve_id)
    changed = before is None or item.last_modified is None or item.last_modified > before
    return item.cve_id in stored and not changed


def _load_candidates(
    loader: _Loader,
    seen: list[Sighting],
    sources: dict[str, str],
    hits: set[str],
    cached: Callable[[Sighting], bool],
) -> None:
    window = Counter(s.source for s in seen if s.in_window)

    def followable(hit_ids: set[str]) -> set[str]:
        cnas = {sources[cve] for cve in hit_ids if cve in sources}
        return {cna for cna in cnas if window[cna] <= LEARN_MAX}

    known = followable(hits)  # CNAs whose records we already hold: same budget, newest first, as the named ones
    first = [s for s in seen if loader.watch.mentions(s.description) or s.source in known]
    learned = followable(hits | loader.load(loader.fresh(first, cached))) - known
    asked = {s.cve_id for s in first}
    loader.load(loader.fresh([s for s in seen if s.source in learned and s.cve_id not in asked], cached))
    loader.result.followed_sources = sorted(known | learned)


def restore_due(
    factory: sessionmaker[Session],
    seen: Iterable[Sighting],
    stored: set[str] | None,
    held: dict[str, datetime],
    *,
    done: Collection[str] = (),
) -> None:
    """Give back their previous date to the records with CNA ranges that NVD re-dated in this refresh and whose CNA
    record was not stored (cap, outage, not found, or a failure earlier in the refresh): the next refresh asks for
    them again instead of keeping their old ranges as current. `stored` None reads the CVEs with CNA ranges."""
    if stored is None:
        with factory() as session:
            stored = set(
                session.scalars(select(m.CveAffectedRange.cve_id).where(m.CveAffectedRange.source == CNA_AFFECTED))
            )
    due = {s.cve_id for s in seen if s.cve_id in stored and not _cached(s, stored, held)}
    _restore_dates(factory, {cve: held[cve] for cve in due - set(done) if cve in held})


def clear_rejected(factory: sessionmaker[Session], cve_ids: set[str]) -> int:
    """A CVE rejected by NVD or by CVE.org keeps no CNA range: the scan must not match an invalid CVE."""
    if not cve_ids:
        return 0
    with factory() as session, session.begin():
        session.execute(
            delete(m.CveAffectedRange).where(
                m.CveAffectedRange.cve_id.in_(sorted(cve_ids)), m.CveAffectedRange.source == CNA_AFFECTED
            )
        )
    log.info("CVE.org: CNA ranges removed for %d rejected CVEs", len(cve_ids))
    return len(cve_ids)


def _restore_dates(factory: sessionmaker[Session], dates: dict[str, datetime]) -> None:
    """Give back their previous date to the records due again that were not stored, so the cache asks for them on the
    next refresh instead of keeping their old CNA ranges as current."""
    if not dates:
        return
    with factory() as session, session.begin():
        for cve_id, date in dates.items():
            session.execute(update(m.Cve).where(m.Cve.id == cve_id).values(last_modified_at=date))
    log.info("CVE.org: %d records due again were not refreshed; they are asked again next time", len(dates))


def _unique(sightings: Iterable[Sighting]) -> list[Sighting]:
    """One sighting per CVE, newest publication first. The window and the KEV pages can both carry a CVE: the copy
    with the latest NVD date is kept (it is the one stored), and it counts as in the window if either was."""
    found: dict[str, Sighting] = {}
    for item in sightings:
        kept = found.get(item.cve_id)
        if kept is None:
            found[item.cve_id] = item
            continue
        newer = item if (item.last_modified or EPOCH) > (kept.last_modified or EPOCH) else kept
        found[item.cve_id] = replace(newer, in_window=kept.in_window or item.in_window)
    return sorted(found.values(), key=lambda s: (s.published is not None, s.published or EPOCH, s.cve_id), reverse=True)


def _mapped_hits(session: Session, watch: Watch) -> set[str]:
    """CVEs whose stored CNA ranges already name a mapped pair."""
    pairs = list(watch.pairs)
    return set(
        session.scalars(
            select(m.CveAffectedRange.cve_id).where(
                m.CveAffectedRange.source == CNA_AFFECTED,
                tuple_(func.lower(m.CveAffectedRange.vendor), func.lower(m.CveAffectedRange.product)).in_(pairs),
            )
        )
    )


@dataclass
class _Loader:
    """Fetches and stores CVE.org records within the refresh's request budget."""

    factory: sessionmaker[Session]
    client: CveOrgClient
    watch: Watch
    budget: int  # HTTP requests
    result: CveOrgResult = field(default_factory=CveOrgResult)
    stored_ids: set[str] = field(default_factory=set)
    rejected_ids: set[str] = field(default_factory=set)

    def fresh(self, items: Sequence[Sighting], cached: Callable[[Sighting], bool]) -> list[str]:
        wanted = [s.cve_id for s in items if not cached(s)]
        self.result.unchanged += len(items) - len(wanted)
        self.result.candidates += len(wanted)
        return wanted

    def load(self, cve_ids: list[str]) -> set[str]:
        """Fetch and store what the budget allows; the ids whose ranges name a mapped pair."""
        if self.stopped():
            return set()
        hits: set[str] = set()
        for start in range(0, len(cve_ids), BATCH):
            records = self._fetch(cve_ids[start : start + BATCH])
            if records:
                with self.factory() as session, session.begin():
                    for record in records:
                        store_cve(session, record)
                self.result.stored += len(records)
                self.result.git_only += sum(r.uncomparable for r in records)
                self.stored_ids |= {r.cve_id for r in records}
                hits |= {r.cve_id for r in records if self.watch.matches(r)}
            if self.stopped() or self.result.capped:
                break
        return hits

    def stopped(self) -> bool:
        """GitHub failed or refused: the step stops (a method, so the state is read again after each batch)."""
        return self.result.interrupted

    def _fits(self) -> bool:
        """The next record's worst case (every attempt and redirect) still fits in the request budget."""
        source = self.client.source
        return self.result.requests + source.max_attempts * (MAX_REDIRECTS + 1) <= self.budget

    def _fetch(self, cve_ids: list[str]) -> list[CveRecord]:
        records: list[CveRecord] = []
        for cve_id in cve_ids:
            if not self._fits():
                self.result.capped = True
                break
            before = self.client.source.sent
            try:
                document = self.client.fetch(cve_id)
            except (SourceUnavailableError, SourceRefusedError) as error:
                self.result.requests += self.client.source.sent - before
                log.warning("CVE.org stopped at %s (%s); what was fetched is kept", cve_id, type(error).__name__)
                self.result.interrupted = True
                break
            self.result.requests += self.client.source.sent - before
            self.result.fetched += 1
            record = parse_cve5(document) if document is not None else None
            if document is None:
                self.result.missing += 1
            elif record is None or record.cve_id != cve_id:
                self.result.skipped += 1
                if (document.get("cveMetadata") or {}).get("state") == "REJECTED":
                    self.rejected_ids.add(cve_id)
            else:
                records.append(record)
        return records
