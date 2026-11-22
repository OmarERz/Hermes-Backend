"""Reason catalog (L4, docs/07 §5), sensitivity profiles (D-032, docs/07 §12) and judge limits (JUE-02, L10).

The catalog mirrors `judge_reason_type` plus the `formula_reason_range` rows of the active formula version
(`load_reason_catalog`): the range of a downward reason is stored negative (e.g. -20..-5) and `other` as -10..10.

Profiles (docs/07 §12): the judge always proposes on the reference scale of the table; code multiplies the points
of an accepted reason and the bounds of its range by the profile factor, with decimal arithmetic and ROUND_HALF_UP
(half away from zero). So, with the minimal profile, +20 is accepted as +10 and the effective range of
`mass_exploitation` is 3..10; with the broad profile it is 8..30.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db.models import FormulaReasonRange, FormulaVersion, JudgeReasonType

MORE_CRITICAL_ASSET = "more_critical_asset"
OTHER = "other"
BOTH_MIN_MAGNITUDE = 3  # docs/07 §5: `other` is ±3 to ±10; the stored range (-10..10) cannot express the gap
DOUBLE_REVIEW_THRESHOLD_MIN = 10  # docs/07 §12: advanced mode only between 10 and 20 (P-005)
DOUBLE_REVIEW_THRESHOLD_MAX = 20
FINDING = "finding"
ALERT = "alert"


class CatalogError(ValueError):
    """The catalog, profile or limits are inconsistent."""


class Direction(StrEnum):
    UP = "up"
    DOWN = "down"
    BOTH = "both"

    def allows(self, direction: str) -> bool:
        return self is Direction.BOTH or self.value == direction


@dataclass(frozen=True)
class ReasonSpec:
    code: str
    direction: Direction
    min_points: int
    max_points: int
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.min_points > self.max_points:
            raise CatalogError(f"reason {self.code!r}: min_points above max_points")
        if self.direction is Direction.UP and self.min_points <= 0:
            raise CatalogError(f"reason {self.code!r}: an upward range must be positive")
        if self.direction is Direction.DOWN and self.max_points >= 0:
            raise CatalogError(f"reason {self.code!r}: a downward range must be negative")

    @property
    def applies_to_asset(self) -> bool:
        """Only `more_critical_asset` adds to one CI; every other reason adds to the whole group (D-035)."""
        return self.code == MORE_CRITICAL_ASSET

    @property
    def package_types(self) -> frozenset[str]:
        return frozenset({FINDING}) if self.applies_to_asset else frozenset({FINDING, ALERT})

    def bounds(self, profile: SensitivityProfile) -> tuple[int, int, int]:
        """Effective (min, max, minimum magnitude) of the range under a profile (docs/07 §12)."""
        magnitude = BOTH_MIN_MAGNITUDE if self.direction is Direction.BOTH else 0
        return profile.scale(self.min_points), profile.scale(self.max_points), profile.scale(magnitude)

    def in_range(self, points: int, profile: SensitivityProfile) -> bool:
        """Whether applied points fall in the effective range (out of range is allowed but forces L10)."""
        low, high, magnitude = self.bounds(profile)
        return low <= points <= high and abs(points) >= magnitude


# docs/07 §5 initial list (also seeded in src/core/db/seeds.py): code, direction, min, max.
DEFAULT_REASONS: tuple[ReasonSpec, ...] = (
    ReasonSpec("mass_exploitation", Direction.UP, 5, 20),
    ReasonSpec("ransomware", Direction.UP, 5, 20),
    ReasonSpec("zero_day", Direction.UP, 5, 20),
    ReasonSpec(MORE_CRITICAL_ASSET, Direction.UP, 4, 15),
    ReasonSpec("exploit_chain", Direction.UP, 5, 20),
    ReasonSpec("requires_authentication", Direction.DOWN, -20, -5),
    ReasonSpec("missing_configuration", Direction.DOWN, -30, -5),
    ReasonSpec("unverified_poc", Direction.DOWN, -10, -3),
    ReasonSpec(OTHER, Direction.BOTH, -10, 10),
)


@dataclass(frozen=True)
class ReasonCatalog:
    reasons: Mapping[str, ReasonSpec]

    @classmethod
    def from_specs(cls, specs: Iterable[ReasonSpec]) -> ReasonCatalog:
        reasons: dict[str, ReasonSpec] = {}
        for spec in specs:
            if spec.code in reasons:
                raise CatalogError(f"reason {spec.code!r} repeated")
            reasons[spec.code] = spec
        return cls(reasons=reasons)

    @classmethod
    def default(cls) -> ReasonCatalog:
        return cls.from_specs(DEFAULT_REASONS)

    def get(self, code: str) -> ReasonSpec | None:
        return self.reasons.get(code)


def load_reason_catalog(session: Session) -> ReasonCatalog:
    """Reasons and ranges of the active formula version (judge_reason_type + formula_reason_range, D-033)."""
    rows = session.execute(
        select(
            JudgeReasonType.code,
            JudgeReasonType.direction,
            FormulaReasonRange.min_points,
            FormulaReasonRange.max_points,
            FormulaReasonRange.enabled,
        )
        .join(FormulaReasonRange, FormulaReasonRange.reason_code == JudgeReasonType.code)
        .join(FormulaVersion, FormulaVersion.id == FormulaReasonRange.formula_version_id)
        .where(FormulaVersion.status == "active")
        .order_by(JudgeReasonType.code)
    ).all()
    if not rows:
        raise CatalogError("no active formula version with reason ranges")
    return ReasonCatalog.from_specs(
        ReasonSpec(code, Direction(direction), min_points, max_points, enabled)
        for code, direction, min_points, max_points, enabled in rows
    )


class ProfileName(StrEnum):
    MINIMAL = "minimal"
    NORMAL = "normal"
    BROAD = "broad"


@dataclass(frozen=True)
class SensitivityProfile:
    """docs/07 §12. L5, L6, L7, L8, L11, the floor and the double review itself never change with the profile."""

    name: ProfileName
    range_multiplier: Decimal
    allow_lowering: bool
    dead_zone: int
    mode2_min_confidence: Decimal

    @classmethod
    def named(cls, name: str) -> SensitivityProfile:
        try:
            return PROFILES[ProfileName(name)]
        except ValueError:
            raise CatalogError(f"unknown sensitivity profile {name!r}") from None

    def scale(self, points: int) -> int:
        """Points actually applied for an accepted reason: points * multiplier, half away from zero."""
        return int((Decimal(points) * self.range_multiplier).quantize(Decimal(1), rounding=ROUND_HALF_UP))


PROFILES: Mapping[ProfileName, SensitivityProfile] = {
    ProfileName.MINIMAL: SensitivityProfile(ProfileName.MINIMAL, Decimal("0.5"), False, 6, Decimal("0.8")),
    ProfileName.NORMAL: SensitivityProfile(ProfileName.NORMAL, Decimal(1), True, 4, Decimal("0.6")),
    ProfileName.BROAD: SensitivityProfile(ProfileName.BROAD, Decimal("1.5"), True, 2, Decimal("0.4")),
}


@dataclass(frozen=True)
class TokenCaps:
    """Per-review token caps (docs/09 §4). Provisional generous values until the test bench measures p99."""

    normal: int = 60_000
    complex: int = 120_000
    critical_multiplier: int = 2  # KEV, R1 or exposed CI may use up to 2x the normal cap


@dataclass(frozen=True)
class JudgeSettings:
    """Editable judge parameters (docs/11 §2) with their documented defaults."""

    model: str = "deepseek-v4-pro"  # ⚠️ docs/07: verify the exact model ID and watch retirement notices
    max_calls: int = 8  # JUE-02
    max_rejections: int = 3  # JUE-02
    format_retries: int = 2  # docs/09 §3
    double_review_threshold: int = 15  # TODO(P-005): calibrate so ~10% of reviews get a second one
    double_review_max_diff: int = 10  # L10
    critical_line: int = 90  # L10: crossing to or from Critical triggers the double review
    output_language: str = "es"  # JUE-MIT-08
    token_caps: TokenCaps = field(default_factory=TokenCaps)

    def __post_init__(self) -> None:
        if not DOUBLE_REVIEW_THRESHOLD_MIN <= self.double_review_threshold <= DOUBLE_REVIEW_THRESHOLD_MAX:
            raise CatalogError("double_review_threshold must be between 10 and 20")
        if self.max_calls < 1 or self.max_rejections < 1 or self.format_retries < 0 or self.double_review_max_diff < 0:
            raise CatalogError("judge limits must be positive")
