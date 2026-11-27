"""Where each event goes (NOT-01: the Slack module decides channels, threads and grouping).

* Channel: the custodian team's channel (`SLACK_CHANNEL_MAP`) or `SLACK_DEFAULT_CHANNEL`; an `immediate` event goes
  to `SLACK_URGENT_CHANNEL` when it is set (NOT-03: it is posted on its own and at once, never in a digest).
* Audience (NOT-08): an event with a `highly_classified` asset also gets a full copy in `SLACK_RESTRICTED_CHANNEL`;
  the standard copy hides those assets' names. The restricted copy is never digested and never falls back to
  another channel.
* Thread (SLK-03): one thread per ticket, keyed by CVE + product + custodian (known even when the iTop id is still
  empty); a new top-level message only for `new_ticket`, `level_up` and `reopened`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Literal

from notifications_api import NotificationEvent
from notifications_slack.settings import SlackSettings, team_key

Audience = Literal["standard", "restricted"]
NEW_ROOT_TYPES: Final = frozenset({"new_ticket", "level_up", "reopened"})
FOLLOW_UP_TYPES: Final = frozenset({"partially_fixed", "fixed"})
RESTRICTED: Final = "highly_classified"
# Lower runs first in the send queue (SLK-08): immediate events before the rest, digests last.
PRIORITY_RANK: Final = {"immediate": 0, "normal": 1, "digest": 2}


@dataclass(frozen=True)
class Route:
    audience: Audience
    channel: str
    thread_key: str | None
    digestible: bool  # may wait for the channel's digest (never an immediate event, never the restricted copy)


def thread_key(event: NotificationEvent) -> str | None:
    """SHA-256 of `cve|product|custodian` (trimmed, case-insensitive): the ticket's natural key; None for alerts."""
    if event.ticket is None or event.vulnerability is None:
        return None
    parts = (event.vulnerability.cve, event.vulnerability.product, event.ticket.custodian)
    return hashlib.sha256("|".join(team_key(part) for part in parts).encode("utf-8")).hexdigest()


def is_restricted(event: NotificationEvent) -> bool:
    return any(asset.confidentiality == RESTRICTED for asset in event.assets)


@dataclass(frozen=True)
class Router:
    channel_map: dict[str, str]
    default_channel: str
    urgent_channel: str | None = None
    restricted_channel: str | None = None

    @classmethod
    def from_settings(cls, settings: SlackSettings) -> Router:
        if settings.default_channel is None:
            raise ValueError("SLACK_DEFAULT_CHANNEL is required")
        return cls(settings.channel_map, settings.default_channel, settings.urgent_channel, settings.restricted_channel)

    def team_channel(self, event: NotificationEvent) -> str:
        if event.ticket is not None:
            return self.channel_map.get(team_key(event.ticket.custodian), self.default_channel)
        return self.default_channel

    def routes(self, event: NotificationEvent) -> list[Route]:
        key = thread_key(event)
        immediate = event.priority == "immediate"
        channel = self.urgent_channel if immediate and self.urgent_channel else self.team_channel(event)
        routes = [Route("standard", channel, key, digestible=not immediate)]
        if self.restricted_channel and is_restricted(event):
            routes.append(Route("restricted", self.restricted_channel, key, digestible=False))
        return routes
