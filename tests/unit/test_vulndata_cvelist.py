"""cvelistV5: parsing CVE JSON 5, the raw file layout and the fetch client."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from core.scan.versions import in_range
from core.vulndata.cvelist import CveOrgClient, _ranges, clone_files, parse_cve5, raw_path
from core.vulndata.http import JsonSource, SourceRefusedError
from core.vulndata.records import CNA_AFFECTED, RangeRecord, ReferenceRecord, WorkaroundRecord

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "vulndata"


def document(name: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return loaded


def test_raw_path_layout() -> None:
    assert raw_path("CVE-2024-1234") == "2024/1xxx/CVE-2024-1234.json"
    assert raw_path("CVE-2026-0001") == "2026/0xxx/CVE-2026-0001.json"
    assert raw_path("CVE-2023-123456") == "2023/123xxx/CVE-2023-123456.json"


def test_parse_published_record() -> None:
    record = parse_cve5(document("cve5_0001.json"))
    assert record is not None
    assert (record.cve_id, record.origin) == ("CVE-2026-0001", "cna")
    assert record.published_at == datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
    assert (record.cvss_version, record.cvss_score, record.cvss_source) == ("3.1", Decimal("7.5"), "cna")
    assert record.cwes == ["CWE-787"]
    assert record.references == [
        ReferenceRecord("https://nginx.org/security", ("Vendor Advisory", "Patch")),
        ReferenceRecord("https://example.test/poc", ("Exploit",)),
    ]
    assert record.workarounds == [WorkaroundRecord("Disable the affected module.", "cna")]


def test_affected_ranges() -> None:
    record = parse_cve5(document("cve5_0001.json"))
    assert record is not None
    assert record.ranges == [
        RangeRecord(CNA_AFFECTED, "F5", "nginx", "1.20.0", True, "1.25.3", False),
        RangeRecord(CNA_AFFECTED, "F5", "nginx", None, None, "1.18.5", True),
        RangeRecord(CNA_AFFECTED, "F5", "nginx", "1.19.0", True, "1.19.0", True),
        RangeRecord(CNA_AFFECTED, "Acme", "Everything"),
    ]


def test_status_changes_default_affected_and_solutions() -> None:
    record = parse_cve5(document("cve5_0005.json"))
    assert record is not None
    assert record.ranges == [
        RangeRecord(CNA_AFFECTED, "Acme", "Server", "2.0", True, "2.3", False),
        RangeRecord(CNA_AFFECTED, "Acme", "Server", "2.4", True, "2.4.1", False),
        RangeRecord(CNA_AFFECTED, "Acme", "Server", "3.0", True, "3.9", False),
        # A bare unaffected version is only that version (CVE JSON 5, F15.9): both sides stay affected
        RangeRecord(CNA_AFFECTED, "Acme", "Client", None, None, "5.1", False),
        RangeRecord(CNA_AFFECTED, "Acme", "Client", "5.1", False, None, None),
        RangeRecord(CNA_AFFECTED, "Acme", "Many", None, None, "5.1", False),
        RangeRecord(CNA_AFFECTED, "Acme", "Many", "5.1", False, "6.1", False),
        RangeRecord(CNA_AFFECTED, "Acme", "Many", "6.1", False, None, None),
    ]
    assert record.workarounds == [WorkaroundRecord("Upgrade to 2.4.1.", "cna")]


def test_clone_files_lists_cve_files(tmp_path: Path) -> None:
    (tmp_path / "cves" / "2026" / "0xxx").mkdir(parents=True)
    (tmp_path / "cves" / "2026" / "0xxx" / "CVE-2026-0001.json").write_text("{}")
    (tmp_path / "cves" / "2026" / "0xxx" / "notes.txt").write_text("")
    assert [p.name for p in clone_files(tmp_path)] == ["CVE-2026-0001.json"]


def test_rejected_and_invalid_documents_are_skipped() -> None:
    assert parse_cve5(document("cve5_rejected.json")) is None
    assert parse_cve5({}) is None
    assert parse_cve5({"cveMetadata": {"cveId": "bad", "state": "PUBLISHED"}}) is None


def client_for(handler: Any) -> CveOrgClient:
    return CveOrgClient(JsonSource(http=httpx.Client(transport=httpx.MockTransport(handler)), max_attempts=1))


def test_fetch_requests_the_raw_file_and_maps_404_to_none() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if "CVE-2026-0001" in request.url.path:
            return httpx.Response(
                200, text=json.dumps(document("cve5_0001.json")), headers={"content-type": "text/plain"}
            )
        return httpx.Response(404)

    client = client_for(handler)
    assert client.fetch("CVE-2026-0001") is not None
    assert client.fetch("CVE-2026-0002") is None
    assert seen[0].endswith("/cves/2026/0xxx/CVE-2026-0001.json")


def test_fetch_rejects_a_bad_id_and_surfaces_other_refusals() -> None:
    client = client_for(lambda _r: httpx.Response(403))
    with pytest.raises(ValueError, match="CVE id"):
        client.fetch("../../etc/passwd")
    with pytest.raises(SourceRefusedError):
        client.fetch("CVE-2026-0001")


def test_fetch_ignores_a_non_object_answer() -> None:
    assert client_for(lambda _r: httpx.Response(200, json=[1])).fetch("CVE-2026-0001") is None


# --- F15.9: CNA ranges as the CNAs of the inventory write them (records from CVE.org, 27 Nov 2026, trimmed) --------
def cna_record(cve_id: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((FIXTURES / "cveorg" / f"{cve_id}.json").read_text(encoding="utf-8"))
    return loaded


def ranges_of(cve_id: str) -> list[RangeRecord]:
    record = parse_cve5(cna_record(cve_id))
    assert record is not None
    return record.ranges


def linux(start: str | None, start_inclusive: bool | None, end: str | None, end_inclusive: bool | None) -> RangeRecord:
    return RangeRecord(CNA_AFFECTED, "Linux", "Linux", start, start_inclusive, end, end_inclusive)


def test_the_kernel_cna_lists_fixed_lines_and_every_gap_between_them_is_affected() -> None:
    """`defaultStatus: affected` with unaffected lines (`6.1.192 <= v <= 6.1.*`): the affected versions are the gaps.
    CVE-2026-100080 was introduced in 3.16 and fixed in 6.1.192, so 6.1.0 is affected (F20 dry run, P1-1)."""
    assert ranges_of("CVE-2026-100080") == [
        linux("3.16", True, "5.10.274", False),
        linux("5.10.*", False, "5.15.225", False),
        linux("5.15.*", False, "6.1.192", False),
        linux("6.1.*", False, "6.6.162", False),
        linux("6.6.*", False, "6.12.116", False),
        linux("6.12.*", False, "6.18.62", False),
        linux("6.18.*", False, "7.3.3", False),
        linux("7.3.*", False, "7.4-rc2", False),
    ]
    assert any(
        in_range("6.1.0", r.version_start, r.start_inclusive, r.version_end, r.end_inclusive)
        for r in ranges_of("CVE-2026-100080")
    )


def test_a_kernel_cve_introduced_after_the_installed_line_does_not_cover_it() -> None:
    found = ranges_of("CVE-2026-80872")
    assert found == [
        linux("6.6", True, "6.18.40", False),
        linux("6.18.*", False, "7.1.5", False),
        linux("7.1.*", False, "7.2", False),
    ]
    assert not any(in_range("6.1.0", r.version_start, r.start_inclusive, r.version_end, r.end_inclusive) for r in found)


def test_a_cna_that_writes_no_vendor_keeps_its_product_name() -> None:
    """The PostgreSQL CNA writes vendor `n/a`: the range is kept under that literal name, as the mapping stores it."""
    assert ranges_of("CVE-2026-116303") == [
        RangeRecord(CNA_AFFECTED, "n/a", "PostgreSQL", "18", True, "18.7", False),
        RangeRecord(CNA_AFFECTED, "n/a", "PostgreSQL", "17", True, "17.12", False),
        RangeRecord(CNA_AFFECTED, "n/a", "PostgreSQL", "16", True, "16.16", False),
        RangeRecord(CNA_AFFECTED, "n/a", "PostgreSQL", "15", True, "15.20", False),
        RangeRecord(CNA_AFFECTED, "n/a", "PostgreSQL", None, None, "14.25", False),
    ]


def test_github_constraint_strings_are_read_as_ranges() -> None:
    assert ranges_of("CVE-2026-75604") == [
        RangeRecord(CNA_AFFECTED, "vercel", "next.js", "13.4.0", True, "15.5.24", False),
        RangeRecord(CNA_AFFECTED, "vercel", "next.js", "16.0.0", True, "16.3.3", False),
    ]
    vite = [r for r in ranges_of("CVE-2026-112945") if r.product == "vite"]
    assert RangeRecord(CNA_AFFECTED, "vitejs", "vite", None, None, "6.4.4", False) in vite
    assert RangeRecord(CNA_AFFECTED, "vitejs", "vite", "8.3.0", True, "8.3.3", False) in vite


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("<= 2.0", (None, None, "2.0", True)),
        ("> 1.0, < 2.0", ("1.0", False, "2.0", False)),
        ("= 1.2.3", ("1.2.3", True, "1.2.3", True)),
        (">= 3.0", ("3.0", True, None, None)),
    ],
)
def test_constraint_forms(version: str, expected: tuple[str | None, bool | None, str | None, bool | None]) -> None:
    affected = [{"vendor": "acme", "product": "tool", "versions": [{"version": version, "status": "affected"}]}]
    assert _ranges(affected) == [RangeRecord(CNA_AFFECTED, "acme", "tool", *expected)]


def test_an_unreadable_constraint_is_kept_for_the_scan_to_count_as_a_comparison_error() -> None:
    """ESC-13: nothing is guessed; the raw text reaches the scan, which records a comparison error."""
    affected = [
        {"vendor": "acme", "product": "tool", "versions": [{"version": ">= 1.0 < 2.0 ~ 3", "status": "affected"}]}
    ]
    assert _ranges(affected) == [
        RangeRecord(CNA_AFFECTED, "acme", "tool", ">= 1.0 < 2.0 ~ 3", True, ">= 1.0 < 2.0 ~ 3", True)
    ]


def test_an_open_wildcard_end_is_no_bound() -> None:
    affected = [
        {
            "vendor": "acme",
            "product": "tool",
            "versions": [{"version": "2.0", "lessThanOrEqual": "*", "status": "affected"}],
        }
    ]
    assert _ranges(affected) == [RangeRecord(CNA_AFFECTED, "acme", "tool", "2.0", True, None, None)]


def kernel_entry(*unaffected: tuple[str, str, str]) -> list[dict[str, Any]]:
    versions = [{"version": v, key: bound, "status": "unaffected"} for v, key, bound in unaffected]
    return [{"vendor": "Linux", "product": "Linux", "defaultStatus": "affected", "versions": versions}]


def test_overlapping_unaffected_lines_are_merged() -> None:
    """Kernel CNA, CVE-2026-80731 (27 Nov 2026): introduced in 4.6, yet a fix is also listed for the 3.2 line, inside
    `[0, 4.6)`. The unaffected versions are the union of what the CNA says; the gaps are what is left."""
    found = _ranges(
        kernel_entry(
            ("0", "lessThan", "4.6"),
            ("3.2.81", "lessThanOrEqual", "3.2.*"),
            ("5.10.265", "lessThanOrEqual", "5.10.*"),
            ("6.1.183", "lessThanOrEqual", "6.1.*"),
            ("7.2", "lessThanOrEqual", "*"),
        )
    )
    assert found == [
        linux("4.6", True, "5.10.265", False),
        linux("5.10.*", False, "6.1.183", False),
        linux("6.1.*", False, "7.2", False),
    ]


def test_lines_fixed_before_the_introduction_leave_only_later_gaps() -> None:
    """CVE-2026-89624: introduced in 6.15, with fixes listed for 6.6 and 6.12 inside `[0, 6.15)`: 6.1.0 is not
    affected."""
    found = _ranges(
        kernel_entry(
            ("0", "lessThan", "6.15"),
            ("6.6.160", "lessThanOrEqual", "6.6.*"),
            ("6.12.111", "lessThanOrEqual", "6.12.*"),
            ("6.18.50", "lessThanOrEqual", "6.18.*"),
            ("7.3", "lessThanOrEqual", "*"),
        )
    )
    assert found == [linux("6.15", True, "6.18.50", False), linux("6.18.*", False, "7.3", False)]
    assert not any(in_range("6.1.0", r.version_start, r.start_inclusive, r.version_end, r.end_inclusive) for r in found)


def test_touching_exclusions_are_one_and_leave_no_gap_between_them() -> None:
    found = _ranges(kernel_entry(("0", "lessThan", "2.0"), ("2.0", "lessThanOrEqual", "2.*")))
    assert found == [linux("2.*", False, None, None)]
    apart = _ranges(kernel_entry(("0", "lessThan", "2.0"), ("2.1", "lessThanOrEqual", "2.*")))
    assert apart == [linux("2.0", True, "2.1", False), linux("2.*", False, None, None)]


def test_a_wildcard_line_in_less_than_is_the_whole_line() -> None:
    """CVE JSON 5: `lessThan: "2.*"` is beyond every 2.x version, like `lessThanOrEqual: "2.*"`."""
    affected = [
        {"vendor": "acme", "product": "tool", "versions": [{"version": "1.0", "lessThan": "2.*", "status": "affected"}]}
    ]
    (found,) = _ranges(affected)
    assert found == RangeRecord(CNA_AFFECTED, "acme", "tool", "1.0", True, "2.*", True)
    assert in_range("2.4.1", found.version_start, found.start_inclusive, found.version_end, found.end_inclusive)
    assert _ranges(kernel_entry(("0", "lessThan", "2.*"))) == [linux("2.*", False, None, None)]


def test_a_wider_line_absorbs_a_narrower_one() -> None:
    found = _ranges(kernel_entry(("5.0", "lessThanOrEqual", "5.*"), ("5.4.10", "lessThanOrEqual", "5.4.*")))
    assert found == [linux(None, None, "5.0", False), linux("5.*", False, None, None)]


def test_unaffected_lines_that_cannot_be_read_give_no_range() -> None:
    """A complement is only computed over readable exclusions; anything else is not guessed."""
    for versions in ([("0", "lessThan", "two")], [("1.0", "lessThanOrEqual", "1.*"), ("1.x5", "lessThan", "2.0")]):
        assert _ranges(kernel_entry(*versions)) == []


def test_an_unknown_product_is_skipped_whatever_the_vendor() -> None:
    affected = [{"vendor": "acme", "product": "n/a", "defaultStatus": "affected"}]
    assert _ranges(affected) == []


def test_the_watch_names_mapped_products_as_whole_words() -> None:
    """F15.9: the product names a CVE.org candidate's description may carry, as `load_watch` builds them from the
    mappings (CNA product, NVD product, iTop name)."""
    from core.vulndata.cna_discovery import watch_from  # noqa: PLC0415

    watch = watch_from(
        [
            ("Linux", "Linux", "linux_kernel", "Linux Kernel"),
            ("vercel", "next.js", "next.js", "Next.js"),
            ("vitejs", "vite", "vite", "Vite"),
            ("golang", "go", "go", "Go"),
        ]
    )
    assert watch.pairs == frozenset({("linux", "linux"), ("vercel", "next.js"), ("vitejs", "vite"), ("golang", "go")})
    assert watch.mentions("In the Linux\nkernel, the following vulnerability has been resolved")
    assert watch.mentions("drivers in kernel.Linux are affected")  # any non-word character bounds a word
    assert watch.mentions("Next.js is a React framework")
    assert not watch.mentions("vitest runs the tests")
    assert not watch.mentions("go to the settings page")  # names under 3 characters are not keywords
    assert not watch_from([]).mentions("Linux")


def acme(default: str | None, *versions: dict[str, Any]) -> list[RangeRecord]:
    entry: dict[str, Any] = {"vendor": "acme", "product": "tool", "versions": list(versions)}
    if default:
        entry["defaultStatus"] = default
    return _ranges([entry])


def tool(start: str | None, start_inclusive: bool | None, end: str | None, end_inclusive: bool | None) -> RangeRecord:
    return RangeRecord(CNA_AFFECTED, "acme", "tool", start, start_inclusive, end, end_inclusive)


def test_changes_can_make_an_unaffected_range_affected() -> None:
    """T4 review r2: an item that starts unaffected and `changes` to affected yields the affected part."""
    item = {
        "version": "1.0",
        "lessThan": "3.0",
        "status": "unaffected",
        "changes": [{"at": "2.0", "status": "affected"}],
    }
    assert acme(None, item) == [tool("2.0", True, "3.0", False)]


def test_changes_inside_an_exclusion_are_honoured_with_default_affected() -> None:
    item = {"version": "0", "lessThan": "5.0", "status": "unaffected", "changes": [{"at": "4.0", "status": "affected"}]}
    assert acme("affected", item) == [tool("4.0", True, None, None)]


def test_changes_are_applied_in_version_order() -> None:
    item = {
        "version": "2.0",
        "lessThan": "3.0",
        "status": "affected",
        "changes": [{"at": "2.4", "status": "affected"}, {"at": "2.3", "status": "unaffected"}],
    }
    assert acme(None, item) == [tool("2.0", True, "2.3", False), tool("2.4", True, "3.0", False)]
    unreadable = {**item, "changes": [{"at": "two", "status": "unaffected"}]}
    assert acme(None, unreadable) == []


def test_an_exact_zero_version_is_a_point_not_the_start_of_time() -> None:
    """T4 review r2: `0.0.0` unaffected, with no bound, excludes only that version."""
    found = acme("affected", {"version": "0.0.0", "status": "unaffected"})
    assert found == [tool(None, None, "0.0.0", False), tool("0.0.0", False, None, None)]
    assert any(in_range("1.5", r.version_start, r.start_inclusive, r.version_end, r.end_inclusive) for r in found)


def test_an_exclusion_that_names_no_version_leaves_the_entry_without_range() -> None:
    """T4 review r3: with `defaultStatus: affected`, an exclusion that cannot be placed is not guessed away."""
    assert acme("affected", {"version": "unspecified", "status": "unaffected"}) == []
    # with the default unaffected, an affected item that names no version simply states nothing
    assert acme(None, {"version": "unspecified", "status": "affected"}, {"version": "1.0", "status": "affected"}) == [
        tool("1.0", True, "1.0", True)
    ]


def test_changes_apply_only_inside_their_entry() -> None:
    """T4 review r3: a change past `lessThan` does not stretch the range ([2.0, 3.0), change at 4.0)."""
    item = {
        "version": "2.0",
        "lessThan": "3.0",
        "status": "affected",
        "changes": [{"at": "4.0", "status": "unaffected"}],
    }
    found = acme(None, item)
    assert found == [tool("2.0", True, "3.0", False)]
    assert not any(in_range("3.5", r.version_start, r.start_inclusive, r.version_end, r.end_inclusive) for r in found)
    before = {**item, "changes": [{"at": "1.0", "status": "unaffected"}]}
    assert acme(None, before) == [tool("2.0", True, "3.0", False)]


def test_entries_given_only_as_git_commits_are_counted_not_compared() -> None:
    """The kernel CNA's first entry lists git commits only: no range is made from it (ESC-13) and the record counts it,
    so the refresh logs how many it could not compare."""
    record = parse_cve5(cna_record("CVE-2026-100080"))
    assert record is not None
    assert record.uncomparable == 1  # the git entry; the semver entry gives the ranges
    assert all("." in (r.version_end or "") for r in record.ranges)


def test_the_newest_nvd_copy_of_a_cve_is_the_one_the_cache_compares() -> None:
    """T4 review r3: the window and the KEV pages can carry the same CVE with different NVD dates."""
    from core.vulndata.cna_discovery import Observed, _unique  # noqa: PLC0415

    def item(modified: str) -> dict[str, Any]:
        return {
            "cve": {
                "id": "CVE-2026-10001",
                "sourceIdentifier": "cna@x",
                "published": "2026-10-01T00:00:00",
                "lastModified": modified,
                "descriptions": [{"lang": "en", "value": "x"}],
            }
        }

    observed = Observed()
    observed.see(item("2026-11-01T00:00:00"))
    observed.see(item("2026-11-20T00:00:00"), in_window=False)
    (kept,) = _unique(observed.sightings)
    assert kept.last_modified == datetime(2026, 11, 20, tzinfo=UTC) and kept.in_window


def test_a_change_at_an_inclusive_start_applies_from_the_start() -> None:
    """T4 review forced finding: `[1.0.0, 2.0.0)` unaffected, changed to affected at 1.0.0, is affected throughout."""
    item = {
        "version": "1.0.0",
        "lessThan": "2.0.0",
        "status": "unaffected",
        "changes": [{"at": "1.0.0", "status": "affected"}],
    }
    assert acme(None, item) == [tool("1.0.0", True, "2.0.0", False)]


def test_the_nvd_product_name_counts_as_written_too() -> None:
    """T4 review forced finding: a description may name `linux_kernel` itself."""
    from core.vulndata.cna_discovery import watch_from  # noqa: PLC0415

    watch = watch_from([("Linux", "Linux Foundation Kernel", "linux_kernel", "Kernel X")])
    assert watch.mentions("affects linux_kernel builds")
    assert watch.mentions("affects the Linux kernel")
