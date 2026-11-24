"""Configuration of the Slack module: `SLACK_*` variables (NOT-07); tokens and the database password as Docker secrets.

Tokens are `SecretStr` (never in `repr`, logs or errors). The service fails closed: `problems()` lists what is missing
and the entry point refuses to start until it is empty (prototype conflict C5: an empty secret never counts as set).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Final

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

DOCKER_SECRETS_DIR: Final = Path("/run/secrets")
# Slack conversation ids: C… (public channel) or G… (private channel created before 2021)
CHANNEL_ID: Final = re.compile(r"^[CG][A-Z0-9]{6,31}$")
_TOKEN_PREFIX: Final = {"bot_token": "xoxb-", "app_token": "xapp-"}


def _channel(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not CHANNEL_ID.fullmatch(value):
        raise ValueError("must be a Slack channel id such as C0123456789 (channel details, at the bottom)")
    return value


def team_key(name: str) -> str:
    """How a custodian team name is matched against SLACK_CHANNEL_MAP: trimmed and case-insensitive."""
    return " ".join(name.split()).casefold()


class SlackSettings(BaseSettings):
    """Settings of the Slack module. Field names map to `SLACK_<NAME>` (upper case) or secret files `slack_<name>`."""

    model_config = SettingsConfigDict(
        env_prefix="SLACK_",
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir=DOCKER_SECRETS_DIR if DOCKER_SECRETS_DIR.is_dir() else None,
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,  # a token pasted in the wrong variable must not reach a log
        env_ignore_empty=True,
    )

    bot_token: SecretStr | None = Field(default=None, description="Bot token (xoxb-...), secret slack_bot_token")
    app_token: SecretStr | None = Field(default=None, description="App-level token (xapp-...), secret slack_app_token")
    database_url: SecretStr | None = Field(
        default=None, description="PostgreSQL URL of the slack_module role, without the password"
    )
    db_password: SecretStr | None = Field(
        default=None, description="Password of slack_module, secret slack_db_password"
    )

    channel_map: dict[str, str] = Field(
        default_factory=dict,
        description='JSON object: custodian team name -> channel id, e.g. {"Infra": "C0123456789"}',
    )
    default_channel: str | None = Field(default=None, description="Channel of teams that are not in the map")
    urgent_channel: str | None = Field(default=None, description="Channel of immediate events; unset = team channel")
    restricted_channel: str | None = Field(
        default=None, description="Channel with the full detail of highly classified assets (NOT-08)"
    )

    digest_window_seconds: int = Field(default=120, ge=10, le=3600, description="How long a digest collects events")
    max_rate_wait_seconds: float = Field(
        default=30, ge=0, le=300, description="Longest wait for Slack's Retry-After inside one delivery"
    )
    retention_days: int = Field(default=90, ge=1, le=3650, description="Days a delivery record is kept")
    thread_retention_days: int = Field(default=365, ge=1, le=3650, description="Days an idle ticket thread is kept")

    @field_validator("bot_token", "app_token", "database_url", "db_password", mode="before")
    @classmethod
    def _blank_means_unset(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        if isinstance(value, SecretStr) and not value.get_secret_value().strip():
            return None
        return value

    @field_validator("bot_token", "app_token")
    @classmethod
    def _token_kind(cls, value: SecretStr | None, info: Any) -> SecretStr | None:
        prefix = _TOKEN_PREFIX[info.field_name]
        if value is not None and not value.get_secret_value().strip().startswith(prefix):
            raise ValueError(f"must start with {prefix}")
        return SecretStr(value.get_secret_value().strip()) if value is not None else None

    @field_validator("default_channel", "urgent_channel", "restricted_channel", mode="before")
    @classmethod
    def _channel_id(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return _channel(value) if isinstance(value, str) else value

    @field_validator("channel_map")
    @classmethod
    def _channel_map(cls, value: dict[str, str]) -> dict[str, str]:
        mapped: dict[str, str] = {}
        for team, channel in value.items():
            if not team.strip():
                raise ValueError("team names must not be blank")
            checked = _channel(channel)
            assert checked is not None  # noqa: S101 - _channel only returns None for None
            if team_key(team) in mapped:
                raise ValueError("a team appears twice (names are matched without case)")
            mapped[team_key(team)] = checked
        return mapped

    def problems(self) -> list[str]:
        """What is missing to run the Slack service, as variable names (empty = ready)."""
        missing = [
            name
            for name, value in (
                ("SLACK_BOT_TOKEN", self.bot_token),
                ("SLACK_APP_TOKEN", self.app_token),
                ("SLACK_DATABASE_URL", self.database_url),
                ("SLACK_DEFAULT_CHANNEL", self.default_channel),
            )
            if value is None
        ]
        if self.database_url is not None and self.db_password is None and not self._url_has_password():
            missing.append("SLACK_DB_PASSWORD")  # without it slack_module has no login (core provisioning)
        return missing

    def _url_has_password(self) -> bool:
        assert self.database_url is not None  # noqa: S101 - checked by the caller
        try:
            return bool(make_url(self.database_url.get_secret_value()).password)
        except ArgumentError:
            return False

    def secret_values(self) -> list[str]:
        """Every configured secret, for the log masking filter (SEG-24)."""
        return [
            value.get_secret_value()
            for value in (self.bot_token, self.app_token, self.database_url, self.db_password)
            if value is not None and value.get_secret_value()
        ]
