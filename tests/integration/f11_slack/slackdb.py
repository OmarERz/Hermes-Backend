"""The throwaway database of the Slack tests: both chains applied, login URLs of the roles the service uses."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SlackDatabase:
    superuser_url: str
    migrator_url: str
    slack_url: str  # the slack_module role, with a login password
    app_url: str
