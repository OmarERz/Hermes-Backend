"""Every fixed advisory lock key is distinct: two features sharing one key block each other (a configuration write
used to wait for a whole pipeline cycle because both used 7_001_010)."""

from __future__ import annotations

import re
from pathlib import Path

from core.calibration import proposals
from core.configuration import profile, service
from core.ingestion import health, stories
from core.inventory import sync
from core.pipeline import locks
from core.scan import engine

KEYS = {
    "inventory sync": sync.SYNC_LOCK_KEY,
    "scan": engine.SCAN_LOCK_KEY,
    "configuration": service.LOCK_KEY,
    "profile": profile.PROFILE_LOCK,
    "peers": profile.PEER_LOCK,
    "calibration": proposals.LOCK_KEY,
    "pipeline": locks.PIPELINE_LOCK_KEY,
    "deduplication": stories.DEDUP_LOCK_KEY,
    "source health": health.HEALTH_LOCK_KEY,
}
SRC = Path(__file__).resolve().parents[2] / "src"
CONSTANT = re.compile(r"^\w*LOCK\w*(?::\s*Final)?\s*=\s*([\d_]+)\s*(?:#.*)?$", re.MULTILINE)


def test_the_advisory_lock_keys_are_distinct() -> None:
    assert len(set(KEYS.values())) == len(KEYS)


def test_every_numeric_lock_constant_is_listed() -> None:
    found = {int(value.replace("_", "")) for path in SRC.rglob("*.py") for value in CONSTANT.findall(path.read_text())}
    assert found == set(KEYS.values())
