"""Helpers for the constraint suite of data model v1 (ported from the capa 2 validation).

`Builder` creates minimal valid rows for any table (parents included); `load_catalog` reads columns,
foreign keys, enum and range CHECKs from the migrated database; `check_deferred` fires deferred triggers.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Any, ClassVar

import psycopg
from psycopg import sql


@dataclass
class Col:
    name: str
    udt: str
    not_null: bool
    has_default: bool
    fk: tuple[str, str] | None = None
    enum: list[str] | None = None
    lo: str | None = None
    hi: str | None = None


@dataclass
class Tbl:
    name: str
    cols: dict[str, Col] = field(default_factory=dict)
    pk: list[str] = field(default_factory=list)
    unique: list[list[str]] = field(default_factory=list)


def load_catalog(conn: psycopg.Connection[Any]) -> dict[str, Tbl]:
    tables: dict[str, Tbl] = {}
    for tname, cname, udt, nullable, default in conn.execute(
        """SELECT c.table_name, c.column_name, c.udt_name, c.is_nullable, c.column_default
           FROM information_schema.columns c JOIN information_schema.tables t
             ON t.table_name = c.table_name AND t.table_schema = c.table_schema
           WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
           ORDER BY c.table_name, c.ordinal_position"""
    ):
        if tname == "alembic_version":  # migration bookkeeping, not part of model v1
            continue
        tables.setdefault(tname, Tbl(tname)).cols[cname] = Col(cname, udt, nullable == "NO", default is not None)
    for rel, contype, cols, frel, fcols, definition in conn.execute(
        """SELECT conrelid::regclass::text, contype,
                  ARRAY(SELECT attname FROM pg_attribute WHERE attrelid = conrelid AND attnum = ANY(conkey)
                        ORDER BY array_position(conkey, attnum)),
                  confrelid::regclass::text,
                  ARRAY(SELECT attname FROM pg_attribute WHERE attrelid = confrelid AND attnum = ANY(confkey)),
                  pg_get_constraintdef(oid)
           FROM pg_constraint WHERE connamespace = 'public'::regnamespace AND conrelid <> 0"""
    ):
        t = tables.get(rel)
        if t is None:
            continue
        if contype == "p":
            t.pk = list(cols)
        elif contype == "u":
            t.unique.append(list(cols))
        elif contype == "f" and len(cols) == 1:
            t.cols[cols[0]].fk = (frel, fcols[0])
        elif contype == "c" and len(cols) == 1:
            col = t.cols[cols[0]]
            m = re.search(r"ANY \(ARRAY\[(.*)\]\)", definition)
            if m and definition.count("ANY") == 1 and " OR " not in definition:
                col.enum = re.findall(r"'([^']*)'::", m.group(1)) or None
            lo = re.search(r">= \(?'?(-?[\d.]+)", definition)
            hi = re.search(r"<= \(?'?(-?[\d.]+)", definition)
            if lo and hi and " AND " in definition and " OR " not in definition:
                col.lo, col.hi = lo.group(1), hi.group(1)
    return tables


_counter = itertools.count(1)


class Builder:
    """Builds minimal valid rows for any table, creating required parents on the way."""

    # Values that keep table-level CHECKs and triggers satisfied.
    OVERRIDES: ClassVar[dict[str, dict[str, Any]]] = {
        "company_profile": {"id": 1},
        "cpe_mapping": {"nvd_part": "a", "nvd_vendor": "vendor", "nvd_product": "product"},
        "judge_reason_type": {"applies_to_asset": False},
        "team": {"is_default": False},
        "profile_sector": {"is_primary": False},
        "alert": {"relevance": "R2"},
        "formula_level": {"rank": 1, "value": "0.5"},
        "formula_weight": {"weight": "1"},
        "daily_metric": {"dimension": ""},
    }

    def __init__(self, conn: psycopg.Connection[Any], catalog: dict[str, Tbl]):
        self.conn = conn
        self.catalog = catalog

    def scalar(self, table: str, col: Col) -> Any:
        n = next(_counter)
        if col.enum:
            return col.enum[0]
        if col.lo is not None:
            return col.lo
        if table == "cve" and col.name == "id":
            return f"CVE-2026-{n:05d}"
        u = col.udt
        if u == "uuid":
            return self.conn.execute("SELECT uuidv7()").fetchone()[0]  # type: ignore[index]
        if u in ("text", "citext", "varchar"):
            return f"{col.name}-{n}@x" if u == "citext" else f"{col.name}-{n}"
        if u == "bpchar":
            return chr(65 + (n // 26) % 26) + chr(65 + n % 26)
        if u in ("int2", "int4", "int8"):
            return n % 30000 + 1  # distinct, so integer UNIQUE columns (version_no) never collide
        if u == "numeric":
            return "0.5"
        if u == "bool":
            return False
        if u == "jsonb":
            return psycopg.types.json.Jsonb({})
        if u == "timestamptz":
            return self.conn.execute("SELECT now()").fetchone()[0]  # type: ignore[index]
        if u == "date":
            return self.conn.execute("SELECT current_date").fetchone()[0]  # type: ignore[index]
        if u == "inet":
            return "10.0.0.1"
        raise AssertionError(f"no generator for {table}.{col.name} ({u})")

    def values(self, table: str, **overrides: Any) -> dict[str, Any]:
        """Return a valid value set (parents inserted) without inserting the row itself."""
        t = self.catalog[table]
        vals: dict[str, Any] = {}
        special = dict(self.OVERRIDES.get(table, {}))
        special.update(self.special(table, overrides))
        special.update(overrides)
        for col in t.cols.values():
            if col.name in special:
                vals[col.name] = special[col.name]
            elif col.fk and col.not_null:
                vals[col.name] = self.parent(col.fk)
            elif col.not_null:
                vals[col.name] = self.scalar(table, col)
        return vals

    def special(self, table: str, overrides: dict[str, Any]) -> dict[str, Any]:
        if table == "review_package" and "kind" not in overrides:
            return {"kind": "finding", "finding_group_id": self.insert("finding_group")["id"]}
        if table == "assessment" and "finding_group_id" not in overrides and "alert_id" not in overrides:
            return {"finding_group_id": self.insert("finding_group")["id"]}
        if table == "error_queue" and not {"story_id", "cve_id", "review_package_id"} & overrides.keys():
            return {"cve_id": self.insert("cve")["id"]}
        if table == "finding" and "finding_group_id" not in overrides:
            inst = self.insert("installed_software")
            group = self.insert("finding_group", software_product_id=inst["software_product_id"])
            return {"finding_group_id": group["id"], "installed_software_id": inst["id"]}
        if (
            table == "ticket"
            and overrides.get("status") not in (None, "pending_creation")
            and "itop_ticket_id" not in overrides
        ):
            return {
                "itop_ticket_id": f"itop-{next(_counter)}",
                **(
                    {"closed_at": self.scalar(table, self.catalog[table].cols["closed_at"])}
                    if overrides["status"] == "closed"
                    else {}
                ),
                **(
                    {"resolved_at": self.scalar(table, self.catalog[table].cols["resolved_at"])}
                    if overrides["status"] == "resolved"
                    else {}
                ),
            }
        if table == "ticket" and "itop_ticket_id" in overrides and "status" not in overrides:
            return {"status": "open"}
        if table == "ticket_finding" and "finding_id" not in overrides and "ticket_id" not in overrides:
            finding = self.insert("finding")
            group = self.conn.execute(
                "SELECT finding_group_id FROM finding WHERE id = %s", (finding["id"],)
            ).fetchone()[0]  # type: ignore[index]
            return {"finding_id": finding["id"], "ticket_id": self.insert("ticket", finding_group_id=group)["id"]}
        if table == "ticket_finding" and "finding_id" in overrides and "ticket_id" not in overrides:
            group = self.conn.execute(
                "SELECT finding_group_id FROM finding WHERE id = %s", (overrides["finding_id"],)
            ).fetchone()[0]  # type: ignore[index]
            return {"ticket_id": self.insert("ticket", finding_group_id=group)["id"]}
        if table == "suppression" and not {"feedback_id", "created_by"} & overrides.keys():
            return {"created_by": self.insert("app_user")["id"]}
        if table == "judge_reason" and "reason_code" not in overrides:
            return {"reason_code": self.insert("judge_reason_type")["code"]}
        return {}

    def parent(self, fk: tuple[str, str]) -> Any:
        target, tcol = fk
        if target == "company_profile":
            row = self.conn.execute("SELECT id FROM company_profile WHERE id = 1").fetchone()
            if row:
                return row[0]
        return self.insert(target)[tcol]

    def insert(self, table: str, **overrides: Any) -> dict[str, Any]:
        vals = self.values(table, **overrides)
        return self.insert_values(table, vals)

    def insert_values(self, table: str, vals: dict[str, Any]) -> dict[str, Any]:
        cols = list(vals)
        query = sql.SQL("INSERT INTO {} ({}) VALUES ({}) RETURNING *").format(
            sql.Identifier(table),
            sql.SQL(", ").join(map(sql.Identifier, cols)),
            sql.SQL(", ").join(sql.Placeholder() * len(cols)),
        )
        cur = self.conn.execute(query, [vals[c] for c in cols])
        row = cur.fetchone()
        assert cur.description is not None and row is not None
        return dict(zip([d.name for d in cur.description], row, strict=True))


def check_deferred(conn: psycopg.Connection[Any]) -> None:
    conn.execute("SET CONSTRAINTS ALL IMMEDIATE")
