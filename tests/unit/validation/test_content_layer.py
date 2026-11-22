"""VAL-03 content rules for the analysts."""

from __future__ import annotations

import pytest
from validation_samples import ARTICLE, CVE_TEXT, cve, news

from core.validation.content import (
    check_cve_analysis,
    check_cvss_vector,
    check_news_analysis,
    check_quote,
    normalize_text,
    quote_in_text,
)
from core.validation.violations import signature

KNOWN = {"CVE-2026-1111", "CVE-2026-2222"}


def exists(value: str) -> bool:
    return value in KNOWN


def rules(violations: list) -> set[tuple[str, str]]:
    return {(v.rule, v.path) for v in violations}


def test_normalization_and_quotes() -> None:
    assert normalize_text("  a " + chr(10) + chr(9) + " b" + chr(0xA0) + "c  ") == "a b c"
    assert normalize_text(chr(0xFF21)) == chr(0xFF21)  # no compatibility folding
    assert quote_in_text("Acme Firewall appliances", ARTICLE)  # the article has extra spaces
    assert quote_in_text("is  being\nattacked".replace("is ", "are "), ARTICLE)
    assert not quote_in_text("acme firewall", ARTICLE)  # case matters
    assert not quote_in_text("", ARTICLE)
    assert not quote_in_text("   ", ARTICLE)


def test_quote_checks() -> None:
    assert check_quote("Acme Firewall", ARTICLE, "q") == []
    assert [v.message for v in check_quote("", ARTICLE, "q")] == ["The claim has no quote"]
    assert [v.message for v in check_quote(None, ARTICLE, "q")] == ["The claim has no quote"]
    assert check_quote("invented sentence", ARTICLE, "q")[0].rule == "VAL-03.quote"


def test_a_good_news_output_passes() -> None:
    assert check_news_analysis(news(), ARTICLE, "story-1", exists) == []


def test_wrong_story_id() -> None:
    assert rules(check_news_analysis(news(), ARTICLE, "other", exists)) == {("VAL-03.news_id", "news_id")}


def test_invented_quote_is_rejected_at_its_path() -> None:
    output = news()
    output["cves"][1]["quote"] = "there is plenty of evidence of CVE-2026-2222"
    output["victims"][0]["quote"] = ""
    assert rules(check_news_analysis(output, ARTICLE, "story-1", exists)) == {
        ("VAL-03.quote", "cves[1].quote"),
        ("VAL-03.quote", "victims[0].quote"),
    }


def test_cve_format_and_existence() -> None:
    output = news()
    output["cves"][0]["cve"] = "CVE-26-1"
    output["cves"][1]["cve"] = "CVE-2026-9999"
    assert rules(check_news_analysis(output, ARTICLE, "story-1", exists)) == {
        ("VAL-03.cve_format", "cves[0].cve"),
        ("VAL-03.cve_exists", "cves[1].cve"),
    }
    output["cves"][0]["cve"] = 5
    assert rules(check_news_analysis(output, ARTICLE, "story-1", exists)) >= {("VAL-03.cve_format", "cves[0].cve")}


@pytest.mark.parametrize("cpe", ["Acme Firewall", "acme", "acme:firewall:1", "acme/firewall", 7])
def test_candidate_cpe_format(cpe: object) -> None:
    output = news()
    output["products"][0]["candidate_cpe"] = cpe
    assert rules(check_news_analysis(output, ARTICLE, "story-1", exists)) == {
        ("VAL-03.cpe_format", "products[0].candidate_cpe")
    }


def test_empty_candidate_cpe_is_allowed_and_odd_shapes_are_skipped() -> None:
    output = news()
    output["products"][0]["candidate_cpe"] = ""
    output["actors"] = ["not an object"]
    output["conditions"] = "nor a list"
    assert check_news_analysis(output, ARTICLE, "story-1", exists) == []


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    ],
)
def test_valid_vectors(vector: str) -> None:
    assert check_cvss_vector(vector, "v") == []


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "AV:N/AC:L",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" + chr(10),
        None,
        9.8,
    ],
)
def test_invalid_vectors(vector: object) -> None:
    assert [v.rule for v in check_cvss_vector(vector, "v")] == ["VAL-03.cvss_syntax"]


def test_cve_analysis_rules() -> None:
    assert check_cve_analysis(cve(), "CVE-2026-1111", CVE_TEXT, exists) == []
    wrong = cve(cve="CVE-2026-2222", inferred_cvss_vector="nonsense")
    wrong["components"][0]["quote"] = "a fork of Something Else"
    wrong["conditions"][0]["quote"] = ""
    assert rules(check_cve_analysis(wrong, "CVE-2026-1111", CVE_TEXT, exists)) == {
        ("VAL-03.cve_id", "cve"),
        ("VAL-03.cvss_syntax", "inferred_cvss_vector"),
        ("VAL-03.quote", "components[0].quote"),
        ("VAL-03.quote", "conditions[0].quote"),
    }
    unknown = cve(cve="CVE-2026-0000")
    assert rules(check_cve_analysis(unknown, "CVE-2026-0000", CVE_TEXT, exists)) == {("VAL-03.cve_exists", "cve")}
    # An output without the optional vector key counts as "not inferred".
    del unknown["inferred_cvss_vector"]
    assert ("VAL-03.cvss_syntax", "inferred_cvss_vector") not in rules(
        check_cve_analysis(unknown, "CVE-2026-0000", CVE_TEXT, exists)
    )


def test_trailing_newlines_do_not_pass_the_format_rules() -> None:
    output = news()
    output["cves"][0]["cve"] = "CVE-2026-1111" + chr(10)
    output["products"][0]["candidate_cpe"] = "acme:firewall" + chr(10)
    assert rules(check_news_analysis(output, ARTICLE, "story-1", exists)) >= {
        ("VAL-03.cve_format", "cves[0].cve"),
        ("VAL-03.cpe_format", "products[0].candidate_cpe"),
    }


def test_missing_and_invented_quotes_are_different_failures() -> None:
    missing = check_quote("", ARTICLE, "q")[0]
    invented = check_quote("made up", ARTICLE, "q")[0]
    assert signature([missing]) != signature([invented])


def test_a_quote_about_another_cve_cannot_back_this_one() -> None:
    output = news()
    output["cves"][1]["quote"] = "attacked through CVE-2026-1111"  # both CVEs are in the article; wrong evidence
    assert rules(check_news_analysis(output, ARTICLE, "story-1", exists)) == {("VAL-03.cve_in_quote", "cves[1].quote")}


def test_a_quote_that_changes_a_character_is_not_verbatim() -> None:
    article = "The patch fixes version 2 of the product."
    assert quote_in_text("version 2", article)
    assert not quote_in_text("version " + chr(0xB2), article)


def test_cvss_31_base_metrics_may_come_in_any_order_but_not_repeat_or_go_missing() -> None:
    ok = "CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"
    assert check_cvss_vector(ok, "v") == []
    for bad in (
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:HH/I:H/A:H",
    ):
        assert check_cvss_vector(bad, "v")


def test_the_quote_must_name_the_whole_cve_it_supports() -> None:
    known = {"CVE-2026-1111"}
    output = news()
    output["cves"] = [output["cves"][0]]
    output["actors"] = output["victims"] = []
    longer = "Acme Firewall appliances are attacked through CVE-2026-11112 only."
    output["cves"][0]["quote"] = "attacked through CVE-2026-11112"
    assert rules(check_news_analysis(output, longer, "story-1", known.__contains__)) == {
        ("VAL-03.cve_in_quote", "cves[0].quote")
    }
    dashed = "Acme Firewall appliances are attacked through CVE" + chr(0x2011) + "2026" + chr(0x2013) + "1111 today."
    output["cves"][0]["quote"] = "attacked through CVE" + chr(0x2011) + "2026" + chr(0x2013) + "1111"
    assert check_news_analysis(output, dashed, "story-1", known.__contains__) == []
