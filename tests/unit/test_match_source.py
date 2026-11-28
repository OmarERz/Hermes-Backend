"""F18.9: the match source of a finding and its certainty (ESC-09), as the read models and the API give them."""

from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

from api.routes.models import Certainty, MatchSource
from core.views.common import MATCH_CERTAINTY, match_sources

ROOT = Path(__file__).resolve().parents[2]


def test_every_source_the_database_allows_has_its_certainty() -> None:
    schema = (ROOT / "migrations" / "sql" / "0001_schema_up.sql").read_text(encoding="utf-8")
    check = re.search(r"finding_match_source_check CHECK \(match_source IN \(([^)]*)\)\)", schema)
    assert check is not None
    allowed = set(re.findall(r"'([a-z_]+)'", check.group(1)))
    assert set(MATCH_CERTAINTY) == allowed == set(get_args(MatchSource))
    assert MATCH_CERTAINTY == {"nvd_cpe": "1.0", "kev": "1.0", "cna_affected": "0.9"}
    assert set(MATCH_CERTAINTY.values()) == set(get_args(Certainty))


def test_sources_are_distinct_and_most_certain_first() -> None:
    assert match_sources(["cna_affected", "nvd_cpe", "cna_affected"]) == ("nvd_cpe", "cna_affected")
    assert match_sources(["cna_affected", "kev"]) == ("kev", "cna_affected")
    assert match_sources([]) == ()
