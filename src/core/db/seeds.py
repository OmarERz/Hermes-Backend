"""Seed data by scenario (docs/14 §5): `empty` (catalogs, formula v1, settings catalog), `demo` and `edge`.

Every scenario includes the catalogs and the active formula version with the defaults of docs/06 and docs/07
(D-034 weights, factor levels, urgency bands, decay, judge reason ranges) and the editable parameters of docs/11.
`demo` adds a small synthetic inventory with vulnerabilities; `edge` adds the boundary cases of docs/06 §8
(missing custodian, unclassified data, KEV on an exposed CI, CVE without CVSS). All data is synthetic.
Seeding is idempotent per scenario: it refuses to run twice on the same database.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.db import models as m
from core.db.ids import new_id

SCENARIOS = ("empty", "demo", "edge")
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

WEIGHTS = {"S": "0.25", "P": "0.30", "T": "0.20", "A": "0.15", "D": "0.10"}  # D-034
LEVELS: dict[str, list[tuple[str, str]]] = {  # (level_code, value) by rank, strongest first (A-10)
    "P": [("kev_or_exploited", "1.0"), ("public_poc", "0.75"), ("epss_p90", "0.5"), ("other", "0.2")],
    "T": [
        ("peer_exploited_with_vector", "1.0"),
        ("peer_attacked", "0.85"),
        ("sector_region_with_vector", "0.7"),
        ("trend_4_or_more_sources", "0.6"),
        ("sector_region", "0.5"),
        ("trend_2_to_3_sources", "0.4"),
        ("sector_only", "0.3"),
        ("trend_1_source", "0.2"),
        ("no_news", "0.0"),
    ],
    "A": [
        ("critical_exposed", "1.0"),
        ("critical_internal_or_normal_exposed", "0.8"),
        ("normal_internal_or_unknown", "0.5"),
        ("low", "0.3"),
    ],
    "D": [("highly_classified", "0.8"), ("classified", "0.5"), ("unclassified", "0.5"), ("public", "0.1")],
    "E": [("version_confirmed", "1.0"), ("version_unknown", "0.6")],
}
URGENCY_BANDS = {1: 90, 2: 75, 3: 50, 4: 0}  # TIC-03
DECAY = [(7, "1.0"), (30, "0.6"), (None, "0.3")]  # D-013
REASONS: list[tuple[str, str, int, int, str]] = [  # docs/07 §5: code, direction, min, max, description
    ("mass_exploitation", "up", 5, 20, "Explotación masiva con evidencia de los últimos 30 días"),
    ("ransomware", "up", 5, 20, "Uso en campañas de ransomware"),
    ("zero_day", "up", 5, 20, "Día cero sin versión corregida ni parche"),
    ("more_critical_asset", "up", 4, 15, "El texto de iTop muestra más criticidad que el campo estructurado"),
    ("exploit_chain", "up", 5, 20, "Forma parte de una cadena con otro CVE presente"),
    ("requires_authentication", "down", -20, -5, "Requiere autenticación que el CVSS no refleja"),
    ("missing_configuration", "down", -30, -5, "Falta la configuración vulnerable, según iTop"),
    ("unverified_poc", "down", -10, -3, "Prueba de concepto no verificada"),
    ("other", "both", -10, 10, "Otro motivo con explicación obligatoria"),
]
MATCH_TYPES = [
    ("cve_exact", "1.0", 1),
    ("product_version", "0.9", 2),
    ("product", "0.6", 3),
    ("os", "0.6", 4),
    ("vector", "0.6", 5),
]  # docs/06 COR-01
SECTORS = [
    ("transportation", "Transporte"),
    ("fintech", "Tecnología financiera"),
    ("retail", "Comercio"),
    ("healthcare", "Salud"),
    ("government", "Gobierno"),
]

# docs/11 §2 editable parameters: key, group, type, default, min, max, level, min_role, description
SETTINGS: list[tuple[str, str, str, Any, Any, Any, str, str, str]] = [
    ("judge_model", "judge", "text", "deepseek-v4-pro", None, None, "validated", "admin", "Modelo del juez"),
    (
        "analyst_model",
        "analysts",
        "text",
        "deepseek-flash",
        None,
        None,
        "validated",
        "admin",
        "Modelo de los analistas",
    ),
    (
        "sensitivity_profile",
        "judge",
        "enum",
        "normal",
        None,
        None,
        "validated",
        "admin",
        "Perfil de sensibilidad del juez",
    ),
    ("dead_zone", "judge", "int", 4, 0, 10, "validated", "admin", "Zona muerta del ajuste del juez"),
    ("mode2.min_confidence", "judge", "decimal", "0.6", "0", "1", "validated", "admin", "Confianza mínima del modo 2"),
    ("double_review_threshold", "judge", "int", 15, 10, 20, "validated", "admin", "Umbral de doble revisión"),
    ("double_review_max_diff", "judge", "int", 10, 0, 50, "validated", "admin", "Diferencia máxima en doble revisión"),
    (
        "event_priority.immediate",
        "notifications",
        "int",
        90,
        0,
        100,
        "validated",
        "admin",
        "Final mínima para immediate",
    ),
    ("event_priority.normal", "notifications", "int", 50, 0, 100, "validated", "admin", "Final mínima para normal"),
    ("recency_window_days", "scan", "int", 90, 1, 365, "validated", "admin", "Ventana de recencia del escaneo"),
    ("top_news_per_package", "correlation", "int", 5, 1, 20, "validated", "admin", "Noticias por paquete"),
    ("max_matches_per_news", "correlation", "int", 50, 1, 500, "validated", "admin", "Uniones máximas por noticia"),
    ("dedup.window_hours", "ingestion", "int", 72, 1, 720, "validated", "admin", "Ventana de deduplicación"),
    # Calibrated for multilingual-e5-small (docs/02 §4, 23 nov 2026): distinct security stories reach 0.86.
    ("dedup.similarity", "ingestion", "decimal", "0.90", "0", "1", "validated", "admin", "Similitud de deduplicación"),
    ("dedup.gray_zone", "ingestion", "decimal", "0.84", "0", "1", "validated", "admin", "Zona gris de deduplicación"),
    ("judge.max_calls", "judge", "int", 8, 1, 20, "validated", "admin", "Llamadas máximas del juez"),
    ("judge.max_rejections", "judge", "int", 3, 1, 10, "validated", "admin", "Motivos rechazados máximos"),
    ("retries.format", "llm", "int", 2, 0, 5, "validated", "admin", "Reintentos por formato"),
    ("retries.transport", "llm", "int", 3, 0, 10, "validated", "admin", "Reintentos por transporte"),
    ("circuit_breaker.failures", "llm", "int", 5, 1, 50, "validated", "admin", "Fallas para abrir el interruptor"),
    ("circuit_breaker.pause_min", "llm", "int", 10, 1, 120, "validated", "admin", "Pausa del interruptor (min)"),
    ("daily_budget_usd", "budget", "decimal", "5", "0", "1000", "validated", "admin", "Presupuesto diario (USD)"),
    ("critical_reserve", "budget", "decimal", "0.20", "0", "1", "validated", "admin", "Reserva para lo crítico"),
    ("complex_reasoning_mode", "judge", "bool", False, None, None, "validated", "admin", "Modo de razonamiento"),
    ("mode4_autonomous", "calibration", "bool", False, None, None, "validated", "admin", "Modo 4 autónomo"),
    (
        "mode4.weekly_limit",
        "calibration",
        "decimal",
        "0.10",
        "0",
        "1",
        "validated",
        "admin",
        "Límite semanal del modo 4",
    ),
    ("mode4.cooldown_weeks", "calibration", "int", 2, 0, 52, "validated", "admin", "Semanas de enfriamiento"),
    ("mode4.block_weeks", "calibration", "int", 8, 0, 52, "validated", "admin", "Semanas de bloqueo"),
    ("reliability.window_days", "sources", "int", 180, 30, 730, "validated", "admin", "Ventana de confiabilidad"),
    ("reliability.min_resolved", "sources", "int", 20, 1, 1000, "validated", "admin", "Afirmaciones mínimas"),
    (
        "reliability.raise",
        "sources",
        "decimal",
        "0.85",
        "0",
        "1",
        "validated",
        "admin",
        "Tasa para subir confiabilidad",
    ),
    ("reliability.lower", "sources", "decimal", "0.5", "0", "1", "validated", "admin", "Tasa para bajar confiabilidad"),
    ("default_team", "tickets", "text", "Seguridad", None, None, "validated", "admin", "Equipo por defecto (P-020)"),
    (
        "human_ticket_suggestions",
        "tickets",
        "bool",
        True,
        None,
        None,
        "free",
        "analyst",
        "Sugerencias en tickets humanos",
    ),
    ("source_health_hours", "sources", "int", 6, 1, 72, "free", "analyst", "Horas para alertar una fuente caída"),
    ("retention.clean_text_days", "retention", "int", 180, 1, 3650, "validated", "admin", "Retención del texto"),
    ("retention.review_days", "retention", "int", 365, 1, 3650, "validated", "admin", "Retención de paquetes"),
    ("retention.delivered_days", "retention", "int", 90, 1, 3650, "validated", "admin", "Retención de entregas"),
    ("notifications.consumer", "notifications", "enum", "log", None, None, "validated", "admin", "Consumidor"),
]
OPTIONS = {"sensitivity_profile": ["minimal", "normal", "broad"], "notifications.consumer": ["log", "slack"]}


def _id() -> uuid.UUID:
    return new_id()


def seed_catalogs(session: Session) -> None:
    for code, name in SECTORS:
        session.add(m.Sector(code=code, name=name))
    for code, direction, _lo, _hi, description in REASONS:
        session.add(
            m.JudgeReasonType(
                code=code, direction=direction, applies_to_asset=code == "more_critical_asset", description=description
            )
        )
    for code, strength, priority in MATCH_TYPES:
        session.add(m.CorrelationMatchType(code=code, strength=Decimal(strength), priority=priority))
    for key, group, vtype, default, lo, hi, level, role, description in SETTINGS:
        session.add(
            m.SettingDefinition(
                key=key,
                group_code=group,
                value_type=vtype,
                default_value=default,
                min_value=None if lo is None else Decimal(str(lo)),
                max_value=None if hi is None else Decimal(str(hi)),
                edit_level=level,
                min_role=role,
                description=description,
            )
        )
    session.flush()
    for key, options in OPTIONS.items():
        for option in options:
            session.add(m.SettingOption(setting_key=key, option_value=option))


def seed_formula(session: Session) -> uuid.UUID:
    version = m.FormulaVersion(
        id=_id(),
        version_no=1,
        status="draft",
        origin="seed",
        s_without_cvss=Decimal("0.8"),
        kev_exposed_floor=90,
        hysteresis_margin=5,
        hysteresis_evaluations=2,
        hysteresis_days=7,
        note="Valores por defecto de docs/06",
        created_at=NOW,
    )
    session.add(version)
    session.flush()
    for factor, weight in WEIGHTS.items():
        session.add(m.FormulaWeight(formula_version_id=version.id, factor=factor, weight=Decimal(weight)))
    for factor, levels in LEVELS.items():
        for rank, (code, value) in enumerate(levels, start=1):
            session.add(
                m.FormulaLevel(
                    formula_version_id=version.id,
                    factor=factor,
                    level_code=code,
                    rank=rank,
                    value=Decimal(value),
                    is_bonus=False,
                )
            )
    session.add(
        m.FormulaLevel(
            formula_version_id=version.id,
            factor="D",
            level_code="personal_data_bonus",
            rank=len(LEVELS["D"]) + 1,
            value=Decimal("0.2"),
            is_bonus=True,
        )
    )
    for urgency, min_score in URGENCY_BANDS.items():
        session.add(m.FormulaUrgencyBand(formula_version_id=version.id, urgency=urgency, min_score=min_score))
    for step, (max_age, multiplier) in enumerate(DECAY, start=1):
        session.add(
            m.FormulaDecayStep(
                formula_version_id=version.id, step_no=step, max_age_days=max_age, multiplier=Decimal(multiplier)
            )
        )
    for code, _direction, lo, hi, _description in REASONS:
        session.add(
            m.FormulaReasonRange(
                formula_version_id=version.id, reason_code=code, min_points=lo, max_points=hi, enabled=True
            )
        )
    session.flush()
    version.status = "active"
    version.activated_at = NOW
    session.flush()
    return version.id


def _inventory(session: Session, *, edge: bool) -> None:
    security = m.Team(id=_id(), itop_team_id="T-1", name="Seguridad", is_default=True, synced_at=NOW)
    infra = m.Team(id=_id(), itop_team_id="T-2", name="Infraestructura Linux", is_default=False, synced_at=NOW)
    owner = m.Person(id=_id(), itop_person_id="P-1", name="Dueña de Pagos", email="owner@example.test", synced_at=NOW)
    session.add_all([security, infra, owner])
    session.flush()
    payments = m.Asset(
        id=_id(),
        itop_ci_id="CI-1",
        itop_class="Server",
        name="srv-pagos-01",
        criticality="high",
        exposed=True,
        confidentiality="highly_classified",
        personal_data=True,
        owner_person_id=owner.id,
        custodian_team_id=infra.id,
        cpu="16 vCPU",
        ram="64 GB",
        synced_at=NOW,
    )
    intranet = m.Asset(
        id=_id(),
        itop_ci_id="CI-2",
        itop_class="VirtualMachine",
        name="vm-intranet-02",
        criticality="medium",
        exposed=False,
        confidentiality="classified",
        personal_data=False,
        owner_person_id=owner.id,
        custodian_team_id=infra.id,
        cpu="4 vCPU",
        ram="8 GB",
        synced_at=NOW,
    )
    session.add_all([payments, intranet])
    product = m.SoftwareProduct(id=_id(), itop_name="OpenSSL", first_seen_at=NOW)
    session.add(product)
    session.flush()
    session.add(
        m.CpeMapping(
            software_product_id=product.id,
            nvd_part="a",
            nvd_vendor="openssl",
            nvd_product="openssl",
            origin="manual",
            mapped_at=NOW,
        )
    )
    installs = [
        m.InstalledSoftware(
            id=_id(),
            itop_instance_id=f"SI-{i}",
            asset_id=asset.id,
            software_product_id=product.id,
            version="3.0.7",
            itop_class="OtherSoftware",  # F18.3: category, status and description as iTop gives them
            status=status,
            description="Biblioteca TLS del sistema",
            synced_at=NOW,
        )
        for i, (asset, status) in enumerate([(payments, "active"), (intranet, "inactive")], start=1)
    ]
    session.add_all(installs)
    support = m.SoftwareLicence(  # F18.3: one installation with its iTop licence, so the front has one without iTop
        id=_id(),
        itop_licence_id="LIC-1",
        software_product_id=product.id,
        name="Soporte OpenSSL",
        usage_limit="10 servidores",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 12, 31),
        perpetual=False,
        synced_at=NOW,
    )
    session.add(support)
    session.flush()
    installs[0].software_licence_id = support.id
    cve = m.Cve(
        id="CVE-2026-10001",
        description="Desbordamiento sintético para la demo",
        published_at=NOW - timedelta(days=10),
        cvss_version="3.1",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=Decimal("9.8"),
        cvss_source="nvd",
        fetched_at=NOW,
    )
    session.add(cve)
    session.flush()
    session.add(
        m.KevEntry(
            cve_id=cve.id,
            date_added=date(2026, 11, 15),
            required_action="Aplicar la actualización",
            known_ransomware_use=False,
        )
    )
    session.add(
        m.EpssScore(cve_id=cve.id, score_date=date(2026, 11, 21), epss=Decimal("0.91"), percentile=Decimal("0.99"))
    )
    run = m.Run(
        id=_id(),
        kind="scan",
        status="succeeded",
        progress=100,
        trigger_reason="manual",
        started_at=NOW,
        finished_at=NOW,
    )
    group = m.FindingGroup(id=_id(), cve_id=cve.id, software_product_id=product.id, created_at=NOW)
    session.add_all([run, group])
    session.flush()
    for inst in installs:
        _add_finding(session, group, inst, run)
    if edge:
        _edge_cases(session, product, payments, run)


def _add_finding(session: Session, group: m.FindingGroup, inst: m.InstalledSoftware, run: m.Run) -> None:
    finding = m.Finding(
        id=_id(), finding_group_id=group.id, installed_software_id=inst.id, match_source="nvd_cpe", created_at=NOW
    )
    session.add(finding)
    session.flush()
    session.add(
        m.FindingStatusChange(
            id=_id(), finding_id=finding.id, run_id=run.id, status="new", observed_version=inst.version, changed_at=NOW
        )
    )


def _edge_cases(session: Session, product: m.SoftwareProduct, payments: m.Asset, run: m.Run) -> None:
    """Boundary cases that still flow through evaluation (docs/04 §2, docs/06 §8)."""
    # A CI without custodian or classification: its finding goes to the default team with neutral context.
    orphan = m.Asset(
        id=_id(),
        itop_ci_id="CI-3",
        itop_class="Server",
        name="srv-sin-custodio",
        criticality="unknown",
        exposed=None,
        confidentiality="unclassified",
        personal_data=None,
        synced_at=NOW,
    )
    session.add(orphan)
    session.flush()
    orphan_install = m.InstalledSoftware(
        id=_id(),
        itop_instance_id="SI-3",
        asset_id=orphan.id,
        software_product_id=product.id,
        version="3.0.7",
        synced_at=NOW,
    )
    payments_install = session.scalars(
        select(m.InstalledSoftware).where(m.InstalledSoftware.asset_id == payments.id)
    ).one()
    session.add(orphan_install)
    # A CVE without CVSS: scored with the s_without_cvss fallback.
    no_cvss = m.Cve(id="CVE-2026-10002", description="CVE sin CVSS publicado", published_at=NOW, fetched_at=NOW)
    session.add(no_cvss)
    session.flush()
    group = m.FindingGroup(id=_id(), cve_id=no_cvss.id, software_product_id=product.id, created_at=NOW)
    session.add(group)
    session.flush()
    _add_finding(session, group, orphan_install, run)
    _add_finding(session, group, payments_install, run)
    # A product without a CPE mapping: the scan cannot match it and reports it as unmapped.
    session.add(m.SoftwareProduct(id=_id(), itop_name="Software sin mapeo CPE", first_seen_at=NOW))


def seed_demo_inventory(session: Session) -> bool:
    """The `demo` inventory on a database that already has its factory values; False if it is already there."""
    if session.scalar(select(m.Asset.id).where(m.Asset.itop_ci_id == "CI-1")) is not None:
        return False
    _inventory(session, edge=False)
    session.flush()
    return True


def seed(session: Session, scenario: str) -> None:
    """Load a scenario in the caller's transaction. Refuses a database that already has a formula version."""
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario {scenario!r}; expected one of {SCENARIOS}")
    if session.scalar(select(m.FormulaVersion.id).limit(1)) is not None:
        raise RuntimeError("The database is already seeded")
    seed_catalogs(session)
    seed_formula(session)
    loaders: dict[str, Callable[[Session], None]] = {
        "empty": lambda _s: None,
        "demo": lambda s: _inventory(s, edge=False),
        "edge": lambda s: _inventory(s, edge=True),
    }
    loaders[scenario](session)
    session.flush()
