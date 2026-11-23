"""Sample events and feedback validate against the JSON Schemas and the Pydantic models (NOT-07)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError

from notifications_api import FeedbackInput, FeedbackResult, LogConsumer, NotificationEvent

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "events"
EVENT_TYPES = ["new_ticket", "level_up", "reopened", "partially_fixed", "fixed", "threat_alert", "inferred_alert"]


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(load(ROOT / "schemas" / name), format_checker=FormatChecker())


@pytest.mark.parametrize("event_type", EVENT_TYPES)
def test_event_sample_validates_against_schema_and_model(event_type: str) -> None:
    data = load(FIXTURES / f"{event_type}.json")
    assert data["type"] == event_type
    validator("notification_event.schema.json").validate(data)
    model = NotificationEvent.model_validate(data)
    assert model.type == event_type


def test_one_sample_per_event_type_and_no_extra() -> None:
    names = {p.stem for p in FIXTURES.glob("*.json")} - {"feedback"}
    assert names == set(EVENT_TYPES)


def test_feedback_sample_validates_against_schema_and_model() -> None:
    data = load(FIXTURES / "feedback.json")
    validator("feedback.schema.json").validate(data)
    assert FeedbackInput.model_validate(data).verdict == "wrong_priority"


def test_event_rejects_extra_field_and_bad_version() -> None:
    data = load(FIXTURES / "new_ticket.json")
    with pytest.raises(ValidationError):
        NotificationEvent.model_validate({**data, "extra": 1})
    with pytest.raises(ValidationError):
        NotificationEvent.model_validate({**data, "contract_version": "2.0"})
    with pytest.raises(ValidationError):
        NotificationEvent.model_validate({k: v for k, v in data.items() if k != "news"})


def test_wrong_priority_requires_proposed_level_in_schema_and_model() -> None:
    data = {**load(FIXTURES / "feedback.json"), "proposed_level": None}
    assert not validator("feedback.schema.json").is_valid(data)
    with pytest.raises(ValidationError):
        FeedbackInput.model_validate(data)
    ok = {**data, "verdict": "relevant"}
    assert validator("feedback.schema.json").is_valid(ok)
    FeedbackInput.model_validate(ok)


def test_feedback_comment_limit() -> None:
    data = {**load(FIXTURES / "feedback.json"), "comment": "x" * 2001}
    assert not validator("feedback.schema.json").is_valid(data)
    with pytest.raises(ValidationError):
        FeedbackInput.model_validate(data)


@pytest.mark.parametrize("ticket", [None, "123", "123456789012"])
def test_feedback_ticket_is_optional_and_numeric(ticket: str | None) -> None:
    base = load(FIXTURES / "feedback.json")
    assert "ticket_itop_id" not in base  # the field is optional: existing payloads stay valid
    data = base if ticket is None else {**base, "ticket_itop_id": ticket}
    assert validator("feedback.schema.json").is_valid(data)
    assert FeedbackInput.model_validate(data).ticket_itop_id == ticket
    assert validator("feedback.schema.json").is_valid({**base, "ticket_itop_id": None})


def test_an_empty_feedback_ticket_counts_as_absent() -> None:
    data = {**load(FIXTURES / "feedback.json"), "ticket_itop_id": ""}  # event sent before iTop created the ticket
    assert validator("feedback.schema.json").is_valid(data)
    assert FeedbackInput.model_validate(data).ticket_itop_id is None


@pytest.mark.parametrize("ticket", ["R-000123", "1234567890123", " 12", 123])
def test_feedback_ticket_rejects_non_ids(ticket: object) -> None:
    data = {**load(FIXTURES / "feedback.json"), "ticket_itop_id": ticket}
    assert not validator("feedback.schema.json").is_valid(data)
    with pytest.raises(ValidationError):
        FeedbackInput.model_validate(data)


@pytest.mark.parametrize("event_type", EVENT_TYPES)
def test_log_consumer_logs_one_line_without_personal_data(event_type: str, caplog: pytest.LogCaptureFixture) -> None:
    event = NotificationEvent.model_validate(load(FIXTURES / f"{event_type}.json"))
    with caplog.at_level(logging.INFO, logger="notifications_api.log_consumer"):
        LogConsumer().process(event)
    assert len(caplog.records) == 1
    line = caplog.text
    assert event.event_id in line
    for forbidden in ("@", "Alex Example", "Sam Sample", "srv-example", "Synthetic headline"):
        assert forbidden not in line
    if event.assets:
        assert "CI-0001" in line


def test_log_consumer_is_idempotent_by_event_id(caplog: pytest.LogCaptureFixture) -> None:
    event = NotificationEvent.model_validate(load(FIXTURES / "new_ticket.json"))
    consumer = LogConsumer()
    with caplog.at_level(logging.INFO, logger="notifications_api.log_consumer"):
        consumer.process(event)
        consumer.process(event)
    assert len(caplog.records) == 1


def test_log_consumer_retries_after_a_failed_write_and_bounds_its_memory() -> None:
    class Flaky(logging.Logger):
        failures = 1

        def info(self, msg: object, *args: object, **kwargs: Any) -> None:
            if self.failures:
                self.failures -= 1
                raise OSError("disk full")

    data = load(FIXTURES / "new_ticket.json")
    event = NotificationEvent.model_validate(data)
    consumer = LogConsumer(Flaky("flaky"), max_seen=2)
    with pytest.raises(OSError, match="disk full"):
        consumer.process(event)
    consumer.process(event)  # the failed write was not recorded, so the retry is written
    for event_id in ("b", "c"):
        consumer.process(NotificationEvent.model_validate({**data, "event_id": event_id}))
    assert len(consumer._seen) == 2


@pytest.mark.parametrize(
    ("model", "fixture", "field", "value"),
    [
        (FeedbackInput, "feedback", "proposed_score", "80"),
        (FeedbackInput, "feedback", "proposed_score", True),
        (FeedbackInput, "feedback", "proposed_score", 80.5),
        (NotificationEvent, "new_ticket", "date", 1767177000),
        (NotificationEvent, "new_ticket", "date", "yesterday"),
        (NotificationEvent, "new_ticket", "date", "2026-01-15T10:30:00"),
        (NotificationEvent, "new_ticket", "date", "2026-01-15"),
        (NotificationEvent, "new_ticket", "date", "2026-01-15T10:30Z"),
        (NotificationEvent, "new_ticket", "date", "2026-01-15T10:30:00+0000"),
        (NotificationEvent, "new_ticket", "date", "2026-01-15T10:30:00+00:60"),
        (NotificationEvent, "new_ticket", "date", "2026-01-15T10:30:00+24:00"),
        (NotificationEvent, "new_ticket", "date", "2026-13-15T10:30:00Z"),
        (NotificationEvent, "new_ticket", "date", "2026-01-15T10:30:00Z\n"),
        (NotificationEvent, "new_ticket", "date", "2026-01-15T10:30:00.\u0661\u0662\u0663+02:00"),
        (NotificationEvent, "new_ticket", "assessment_id", 5),
    ],
)
def test_models_do_not_coerce_what_the_schema_rejects(model: Any, fixture: str, field: str, value: Any) -> None:
    data = {**load(FIXTURES / f"{fixture}.json"), field: value}
    with pytest.raises(ValidationError):
        model.model_validate(data)
    if field == "date" and isinstance(value, str) and not value.endswith("\n"):  # schema side rejects it too
        assert not validator("notification_event.schema.json").is_valid(data)


def test_fixture_priorities_follow_p004_and_driving_ci_is_the_best_active_one() -> None:
    for event_type in EVENT_TYPES:
        data = load(FIXTURES / f"{event_type}.json")
        if data["score"] is None:
            continue
        final = data["score"]["final"]
        assert data["priority"] == ("immediate" if final >= 90 else "normal" if final >= 50 else "digest")
    data = load(FIXTURES / "partially_fixed.json")
    active = [a for a in data["assets"] if a["status"] != "fixed"]
    best = max(active, key=lambda a: a["score"])
    assert data["score"]["driving_ci"] == best["ci_id"]
    assert data["score"]["final"] == best["score"]


def test_whole_floats_are_valid_integers_like_in_json_schema() -> None:
    data = {**load(FIXTURES / "feedback.json"), "proposed_score": 80.0}
    assert validator("feedback.schema.json").is_valid(data)
    assert FeedbackInput.model_validate(data).proposed_score == 80


@pytest.mark.parametrize("date", ["2026-01-15T10:30:00Z", "2026-01-15T10:30:00.123+02:00", "2026-01-15t10:30:00z"])
def test_rfc3339_dates_are_accepted(date: str) -> None:
    data = {**load(FIXTURES / "new_ticket.json"), "date": date}
    assert NotificationEvent.model_validate(data).date == date


def test_fixtures_follow_the_default_bands() -> None:
    """TIC-03 / EVA-07: urgency and level come from the ticket score, which is the best active CI."""
    for event_type in EVENT_TYPES:
        data = load(FIXTURES / f"{event_type}.json")
        score = data["score"]
        if score is None or data["ticket"] is None:
            continue
        final = score["final"]
        assert data["ticket"]["urgency"] == (1 if final >= 90 else 2 if final >= 75 else 3 if final >= 50 else 4)
        assert score["level"] == (
            "critical" if final >= 90 else "high" if final >= 75 else "medium" if final >= 50 else "low"
        )
        assert final == score["base"] + score["judge_adjustment"]
        assert abs(score["judge_adjustment"]) > 4 or score["judge_adjustment"] == 0  # EVA-02 dead zone
        drivers = [a for a in data["assets"] if a["ci_id"] == score["driving_ci"]]
        if drivers and data["vulnerability"]["in_kev"] and drivers[0]["exposed"] and drivers[0]["status"] != "fixed":
            assert final >= 90  # EVA-03 floor
        active = [a["score"] for a in data["assets"] if a["status"] != "fixed"]
        if active:
            assert final == max(active)


GOOD_ID = "0b1f3c5e-7a2d-4e8f-9a6b-1c2d3e4f5a6b"


@pytest.mark.parametrize("feedback_id", [GOOD_ID, GOOD_ID.upper()])
def test_feedback_result_accepts_canonical_uuids_in_both_cases(feedback_id: str) -> None:
    data = {"feedback_id": feedback_id, "replaced_previous": False}
    validator("feedback_result.schema.json").validate(data)  # schema, with FormatChecker
    assert FeedbackResult.model_validate(data).feedback_id == feedback_id


@pytest.mark.parametrize(
    "feedback_id",
    [
        "not-a-uuid",
        GOOD_ID.replace("-", ""),  # missing hyphens
        GOOD_ID + "-",  # trailing hyphen
        "-" + GOOD_ID,
        GOOD_ID[:-1],
        GOOD_ID + "0",
        "{" + GOOD_ID + "}",
        "urn:uuid:" + GOOD_ID,
        GOOD_ID.replace("0", "g", 1),
        " " + GOOD_ID,
        GOOD_ID + "\n",  # `$` alone would let a trailing newline through; maxLength closes it
    ],
)
def test_feedback_result_rejects_malformed_uuids_on_both_sides(feedback_id: str) -> None:
    data = {"feedback_id": feedback_id, "replaced_previous": False}
    assert not validator("feedback_result.schema.json").is_valid(data)
    # Also without FormatChecker: `format` is only an annotation then, so pattern and maxLength must do the work.
    assert not Draft202012Validator(load(ROOT / "schemas" / "feedback_result.schema.json")).is_valid(data)
    with pytest.raises(ValidationError):
        FeedbackResult.model_validate(data)


def test_feedback_result_rejects_other_shape_errors() -> None:
    for bad in (
        {"feedback_id": GOOD_ID, "replaced_previous": "false"},
        {"feedback_id": GOOD_ID, "replaced_previous": False, "extra": 1},
        {"feedback_id": GOOD_ID},
    ):
        assert not validator("feedback_result.schema.json").is_valid(bad)
        with pytest.raises(ValidationError):
            FeedbackResult.model_validate(bad)
