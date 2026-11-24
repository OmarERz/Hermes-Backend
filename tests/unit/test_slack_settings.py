"""SLACK_* settings (NOT-07): tokens as secrets, channel ids checked, fail closed when something is missing."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from notifications_slack.settings import SlackSettings, team_key

pytestmark = pytest.mark.unit
FAKE_PASSWORD = "pw"  # noqa: S105 - fake value for tests
BOT = "xoxb-" + "1" * 12  # fake values for tests
APP = "xapp-" + "2" * 12


def settings(**values: object) -> SlackSettings:
    return SlackSettings(_env_file=None, _secrets_dir=None, **values)  # type: ignore[call-arg]


def test_nothing_configured_lists_what_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "SLACK_DATABASE_URL", "SLACK_DEFAULT_CHANNEL"):
        monkeypatch.delenv(name, raising=False)
    assert settings().problems() == [
        "SLACK_BOT_TOKEN",
        "SLACK_APP_TOKEN",
        "SLACK_DATABASE_URL",
        "SLACK_DEFAULT_CHANNEL",
    ]


def test_tokens_from_secret_files_are_secret(tmp_path: Path) -> None:
    (tmp_path / "slack_bot_token").write_text(BOT + "\n")
    (tmp_path / "slack_app_token").write_text(APP)
    (tmp_path / "slack_db_password").write_text("pw")
    loaded = SlackSettings(_env_file=None, _secrets_dir=tmp_path)  # type: ignore[call-arg]
    assert loaded.bot_token is not None
    assert loaded.bot_token.get_secret_value() == BOT
    assert BOT not in repr(loaded)
    assert sorted(loaded.secret_values()) == sorted([BOT, APP, "pw"])


def test_blank_secrets_count_as_unset(tmp_path: Path) -> None:
    (tmp_path / "slack_bot_token").write_text("   ")
    loaded = SlackSettings(_env_file=None, _secrets_dir=tmp_path)  # type: ignore[call-arg]
    assert loaded.bot_token is None


@pytest.mark.parametrize(("field", "value"), [("bot_token", APP), ("app_token", BOT)])
def test_tokens_of_the_wrong_kind_are_refused_without_echoing_them(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as error:
        settings(**{field: value})
    assert value not in str(error.value)


def test_channels_must_be_ids() -> None:
    with pytest.raises(ValidationError):
        settings(default_channel="#general")
    assert settings(default_channel=" C0123456789 ").default_channel == "C0123456789"
    assert settings(urgent_channel="").urgent_channel is None


def test_channel_map_from_json_matches_teams_without_case(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLACK_CHANNEL_MAP", '{"Infrastructure  Team": "C0INFRA001", "Apps": "C0APPS0001"}')
    loaded = settings()
    assert loaded.channel_map == {"infrastructure team": "C0INFRA001", "apps": "C0APPS0001"}
    assert team_key(" infrastructure TEAM ") == "infrastructure team"


@pytest.mark.parametrize(
    "mapping", [{"Apps": "#apps"}, {" ": "C0APPS0001"}, {"Apps": "C0APPS0001", "apps": "C0APPS0002"}]
)
def test_bad_channel_maps_are_refused(mapping: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        settings(channel_map=mapping)


def test_the_slack_module_password_is_required_with_the_database() -> None:
    url = "postgresql://slack_module@db/hermes"
    assert settings(database_url=url).problems()[-1] == "SLACK_DB_PASSWORD"
    assert "SLACK_DB_PASSWORD" not in settings(database_url=url, db_password=FAKE_PASSWORD).problems()
    assert "SLACK_DB_PASSWORD" not in settings(database_url="postgresql://slack_module:pw@db/hermes").problems()
    assert settings(database_url="not a url").problems()[-1] == "SLACK_DB_PASSWORD"
    assert "SLACK_DB_PASSWORD" not in settings().problems()  # the URL itself is what is missing


def test_limits() -> None:
    with pytest.raises(ValidationError):
        settings(digest_window_seconds=1)
    ready = settings(
        bot_token=BOT,
        app_token=APP,
        database_url="postgresql://slack_module@db/hermes",
        db_password=FAKE_PASSWORD,
        default_channel="C0DEFAULT1",
    )
    assert ready.problems() == []
