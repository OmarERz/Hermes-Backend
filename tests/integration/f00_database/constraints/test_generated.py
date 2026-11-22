"""Catalog-driven checks on the migrated database: every table accepts a minimal valid row, and every
NOT NULL, foreign key, enum CHECK, range CHECK and single-column UNIQUE rejects invalid data.

Each test walks the whole catalog (one savepoint per case) and reports every failing case at once.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

import psycopg
import pytest
from dbsupport import Builder, Col, Tbl, check_deferred
from psycopg import errors

pytestmark = pytest.mark.integration

Conn = psycopg.Connection[Any]


def run_cases(conn: Conn, cases: Iterable[tuple[str, Callable[[], None]]]) -> list[str]:
    """Run each case in a savepoint that is always rolled back; a case passes when it returns normally."""
    failures: list[str] = []
    for label, case in cases:
        try:
            with conn.transaction(force_rollback=True):
                case()
        except AssertionError as exc:
            failures.append(f"{label}: {exc}")
        except psycopg.Error as exc:
            failures.append(f"{label}: unexpected {type(exc).__name__}: {exc}")
    return failures


def expect(exc: type[Exception] | tuple[type[Exception], ...], fn: Callable[[], object]) -> Callable[[], None]:
    """A case that passes only if fn raises exc (inside its own savepoint, so the outer one survives)."""

    def case() -> None:
        try:
            fn()
        except exc:
            return
        raise AssertionError(f"expected {exc}")

    return case


def columns(catalog: dict[str, Tbl], keep: Callable[[Col], bool]) -> list[tuple[str, Col]]:
    return [(t, c) for t in sorted(catalog) for c in catalog[t].cols.values() if keep(c)]


def arc_overrides(build: Builder, table: str, column: str) -> dict[str, Any]:
    """Make the row's exclusive-arc CHECK accept the FK column under test, so the FK is what fails."""
    if table == "review_package" and column == "alert_id":
        return {"kind": "alert"}
    if table == "review_package" and column == "story_id":
        return {"kind": "dismissal"}
    if table == "suppression" and column == "feedback_id":
        return {"created_by": None}
    if table in ("assessment", "error_queue"):
        return {column: None}
    if table == "judge_reason" and column == "asset_id":
        code = build.insert("judge_reason_type", code="more_critical_asset", applies_to_asset=True)["code"]
        return {"reason_code": code}
    return {}


def test_catalog_counts(catalog: dict[str, Tbl]) -> None:
    assert len(catalog) == 75
    assert sum(1 for t in catalog.values() for c in t.cols.values() if c.fk) == 118


def test_every_table_accepts_a_minimal_row(conn: Conn, build: Builder, catalog: dict[str, Tbl]) -> None:
    def case(table: str) -> Callable[[], None]:
        def run() -> None:
            build.insert(table)
            check_deferred(conn)

        return run

    assert run_cases(conn, ((t, case(t)) for t in sorted(catalog))) == []


def test_every_not_null_rejects_null(conn: Conn, build: Builder, catalog: dict[str, Tbl]) -> None:
    def case(table: str, column: str) -> Callable[[], None]:
        def run() -> None:
            vals = build.values(table)
            vals[column] = None
            with conn.transaction():
                build.insert_values(table, vals)

        return expect((errors.NotNullViolation, errors.CheckViolation), run)

    cases = columns(catalog, lambda c: c.not_null and not c.has_default)
    assert len(cases) > 300
    assert run_cases(conn, ((f"{t}.{c.name}", case(t, c.name)) for t, c in cases)) == []


def test_every_foreign_key_rejects_missing_parent(conn: Conn, build: Builder, catalog: dict[str, Tbl]) -> None:
    def case(table: str, col: Col) -> Callable[[], None]:
        def run() -> None:
            vals = build.values(table, **arc_overrides(build, table, col.name))
            assert col.fk is not None
            target_udt = catalog[col.fk[0]].cols[col.fk[1]].udt
            if target_udt == "uuid":
                vals[col.name] = conn.execute("SELECT uuidv7()").fetchone()[0]  # type: ignore[index]
            else:
                vals[col.name] = "CVE-2099-99999" if col.fk == ("cve", "id") else "missing-code"
            with conn.transaction():
                build.insert_values(table, vals)

        return expect(errors.ForeignKeyViolation, run)

    cases = columns(catalog, lambda c: c.fk is not None)
    assert len(cases) == 118
    assert run_cases(conn, ((f"{t}.{c.name}", case(t, c)) for t, c in cases)) == []


def test_every_enum_rejects_unknown_value(conn: Conn, build: Builder, catalog: dict[str, Tbl]) -> None:
    def case(table: str, column: str) -> Callable[[], None]:
        def run() -> None:
            vals = build.values(table)
            vals[column] = "not_a_valid_value"
            with conn.transaction():
                build.insert_values(table, vals)

        return expect(errors.CheckViolation, run)

    cases = columns(catalog, lambda c: c.enum is not None)
    assert len(cases) > 50
    assert run_cases(conn, ((f"{t}.{c.name}", case(t, c.name)) for t, c in cases)) == []


def test_every_range_rejects_out_of_range(conn: Conn, build: Builder, catalog: dict[str, Tbl]) -> None:
    def case(table: str, col: Col) -> Callable[[], None]:
        def run() -> None:
            vals = build.values(table)
            hi = col.hi or "0"
            vals[col.name] = str(float(hi) + 1) if "." in hi else str(int(hi) + 1)
            with conn.transaction():
                build.insert_values(table, vals)

        return expect(errors.CheckViolation, run)

    cases = columns(catalog, lambda c: c.lo is not None)
    assert len(cases) > 10
    assert run_cases(conn, ((f"{t}.{c.name}", case(t, c)) for t, c in cases)) == []


def test_every_single_column_unique_rejects_duplicates(conn: Conn, build: Builder, catalog: dict[str, Tbl]) -> None:
    def case(table: str, column: str) -> Callable[[], None]:
        def run() -> None:
            col = catalog[table].cols[column]
            if col.not_null:
                value = build.insert(table)[column]
            else:  # nullable UNIQUE: NULLs never collide, so set a real value
                value = build.scalar(table, col)
                build.insert(table, **{column: value})
            with conn.transaction():
                build.insert_values(table, build.values(table, **{column: value}))

        return expect(errors.UniqueViolation, run)

    cases = [(t, u[0]) for t in sorted(catalog) for u in catalog[t].unique if len(u) == 1]
    assert len(cases) > 15
    assert run_cases(conn, ((f"{t}.{c}", case(t, c)) for t, c in cases)) == []
