"""Every nightly metric has a place on the metrics board (`GET /api/metrics`, FRO-21)."""

from __future__ import annotations

import pytest

from core.metrics.dashboard import CATALOG
from core.metrics.nightly import QUERIES

pytestmark = pytest.mark.unit


def test_every_nightly_metric_is_on_the_board() -> None:
    """A metric the nightly job stores but the catalog lacks would never reach the front: the board skips unknown
    codes. The catalog lists nothing the job does not store either."""
    assert set(CATALOG) == set(QUERIES)


def test_the_metrics_the_comparison_shows_live_say_they_are_nightly() -> None:
    """Rehearsal 2, P2-C: the board and the comparison screen count different things; the board says which."""
    described = {code for code, info in CATALOG.items() if info.description}
    assert described == {"reclassified", "hidden_criticals", "noise_avoided"}
    for code in described:
        assert "del día UTC {day}, al cierre de esa noche" in str(CATALOG[code].description)


def test_the_accepted_original_score_sits_with_the_judge_feedback_metrics() -> None:
    """RE-9 (F18.2): a ratio with a Spanish label, right after «Prioridad incorrecta» on judge adjustments."""
    codes = list(CATALOG)
    assert codes.index("original_score_accepted") == codes.index("wrong_priority_judged") + 1
    info = CATALOG["original_score_accepted"]
    assert (info.label, info.kind, info.fold) == ("«Aceptar puntaje original» en ajustes del juez", "ratio", "only")
