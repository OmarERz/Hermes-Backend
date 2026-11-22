"""Synthetic analyst outputs and article text shared by the validation tests."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from core.validation.schema import ToolSchema

ROOT = Path(__file__).resolve().parents[3]
NEWS_SCHEMA = ToolSchema.load("news_analysis_tool.json", "1", ROOT / "schemas")
CVE_SCHEMA = ToolSchema.load("cve_analysis_tool.json", "1", ROOT / "schemas")

ARTICLE = (
    "Acme   Firewall appliances are\nbeing attacked through CVE-2026-1111. The vendor says there is no evidence\n"
    "of exploitation of CVE-2026-2222. The Lockbit group hit Globex Hospital in Mexico."
)

NEWS_OUTPUT: dict[str, Any] = {
    "news_id": "story-1",
    "event_types": ["active_exploitation"],
    "exploitation_level": "active",
    "is_retrospective": False,
    "is_roundup": False,
    "cves": [
        {"cve": "CVE-2026-1111", "exploitation_level": "active", "quote": "attacked through CVE-2026-1111"},
        {
            "cve": "CVE-2026-2222",
            "exploitation_level": "denied",
            "quote": "no evidence of exploitation of CVE-2026-2222",
        },
    ],
    "products": [
        {
            "vendor": "Acme",
            "product": "Firewall",
            "candidate_cpe": "acme:firewall",
            "affected_versions": "",
            "quote": "Acme Firewall appliances",
        }
    ],
    "actors": [{"name": "Lockbit", "aliases": [], "quote": "The Lockbit group"}],
    "malware": [],
    "victims": [
        {"name": "Globex Hospital", "sector": "healthcare", "country": "MX", "quote": "hit Globex Hospital in Mexico"}
    ],
    "vector": "",
    "conditions": [],
    "signals": {"public_poc": False, "no_patch": False, "ransomware_use": False, "mass_exploitation": False},
    "out_of_taxonomy": False,
    "summary": "Resumen sintético.",
    "confidence": 0.8,
}

CVE_TEXT = "The flaw allows remote code execution without authentication. It is a fork of Widget Core."

CVE_OUTPUT: dict[str, Any] = {
    "cve": "CVE-2026-1111",
    "inferred_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss_confidence": 0.7,
    "conditions": [{"type": "authentication", "description": "None needed", "quote": "without authentication"}],
    "components": [{"component": "Widget Core", "relationship": "fork_of", "quote": "a fork of Widget Core"}],
    "notes": "",
}


def news(**changes: Any) -> dict[str, Any]:
    output = copy.deepcopy(NEWS_OUTPUT)
    output.update(changes)
    return output


def cve(**changes: Any) -> dict[str, Any]:
    output = copy.deepcopy(CVE_OUTPUT)
    output.update(changes)
    return output
