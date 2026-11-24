"""The initial migrations build data model v1, go down cleanly, and match the models (DAT-03, F0 acceptance)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from dbprovision import MigratedDatabase, provisioned_database
from sqlalchemy import Engine, inspect, text
from sqlalchemy.engine import make_url

from core.db.base import Base
from core.db.provision import provision
from core.db.session import make_engine

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def fresh_db(postgres_url: str) -> Iterator[MigratedDatabase]:
    with provisioned_database(postgres_url, "migr") as db:
        yield db


def alembic_cfg(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["url"] = url
    return cfg


def counts(engine: Engine) -> tuple[int, int, int]:
    with engine.connect() as conn:
        tables = conn.execute(
            text("SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'")
        ).scalar_one()
        views = conn.execute(text("SELECT count(*) FROM pg_views WHERE schemaname = 'public'")).scalar_one()
        fks = conn.execute(
            text("SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace")
        ).scalar_one()
    return tables, views, fks


def test_upgrade_builds_model_v1(fresh_db: MigratedDatabase) -> None:
    command.upgrade(alembic_cfg(fresh_db.migrator_url), "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        assert counts(engine) == (76, 14, 120)
        with engine.connect() as conn:
            owner = conn.execute(text("SELECT tableowner FROM pg_tables WHERE tablename = 'finding'")).scalar_one()
            can_update = conn.execute(text("SELECT has_table_privilege('app', 'audit_log', 'UPDATE')")).scalar_one()
            can_insert = conn.execute(text("SELECT has_table_privilege('app', 'audit_log', 'INSERT')")).scalar_one()
            bookkeeping = conn.execute(
                text("SELECT has_table_privilege('app', 'alembic_version', 'UPDATE')")
            ).scalar_one()
        assert owner == "migrator"
        assert (can_update, can_insert, bookkeeping) == (False, True, False)
    finally:
        engine.dispose()


def test_downgrade_and_upgrade_again(fresh_db: MigratedDatabase) -> None:
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    engine = make_engine(fresh_db.superuser_url)
    try:
        assert counts(engine) == (0, 0, 0)
        with engine.connect() as conn:
            functions = conn.execute(
                text(
                    "SELECT count(*) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace "
                    "AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')"
                )
            ).scalar_one()
        assert functions == 0
        command.upgrade(cfg, "head")
        assert counts(engine) == (76, 14, 120)
    finally:
        engine.dispose()


def test_models_match_the_migrated_schema(fresh_db: MigratedDatabase) -> None:
    """Columns, types and nullability of the models equal the migrated database (autogenerate finds nothing)."""
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "head")
    command.check(cfg)
    engine = make_engine(fresh_db.superuser_url)
    try:
        inspector = inspect(engine)
        for table in Base.metadata.sorted_tables:
            db_columns = {c["name"]: c["nullable"] for c in inspector.get_columns(table.name)}
            assert db_columns == {c.name: c.nullable for c in table.columns}, table.name
    finally:
        engine.dispose()


def test_grants_follow_least_privilege(fresh_db: MigratedDatabase) -> None:
    command.upgrade(alembic_cfg(fresh_db.migrator_url), "head")
    engine = make_engine(fresh_db.superuser_url)
    checks = {
        "app reads a view": "SELECT has_table_privilege('app', 'ticket_score', 'SELECT')",
        "app cannot write a view": "SELECT NOT has_table_privilege('app', 'ticket_score', 'INSERT')",
        "app cannot delete review packages": "SELECT NOT has_table_privilege('app', 'review_package', 'DELETE')",
        "app runs trigger functions": "SELECT has_function_privilege('app', 'check_formula_weights()', 'EXECUTE')",
        "app cannot purge": "SELECT NOT has_function_privilege('app', 'purge_retention()', 'EXECUTE')",
        "retention purges": "SELECT has_function_privilege('retention', 'purge_retention()', 'EXECUTE')",
        "retention runs nothing else": (
            "SELECT NOT has_function_privilege('retention', 'normalize_text(text)', 'EXECUTE')"
        ),
        "retention has no direct writes": "SELECT NOT has_table_privilege('retention', 'raw_article', 'UPDATE')",
        "slack_module has no model access": "SELECT NOT has_table_privilege('slack_module', 'ticket', 'SELECT')",
        "public cannot create in the schema": "SELECT NOT has_schema_privilege('public', 'public', 'CREATE')",
    }
    try:
        with engine.connect() as conn:
            failed = [name for name, query in checks.items() if not conn.execute(text(query)).scalar_one()]
        assert failed == []
    finally:
        engine.dispose()


def test_downgrade_keeps_objects_of_other_roles(fresh_db: MigratedDatabase) -> None:
    """A slack_* table owned by the Slack team's role survives the downgrade (no DROP OWNED)."""
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE slack_message (id int PRIMARY KEY)"))
            conn.execute(text("ALTER TABLE slack_message OWNER TO slack_module"))
        command.downgrade(cfg, "base")
        assert "slack_message" in inspect(engine).get_table_names()
        with engine.connect() as conn:
            extensions = conn.execute(text("SELECT count(*) FROM pg_extension WHERE extname IN ('vector', 'citext')"))
            assert extensions.scalar_one() == 2
    finally:
        engine.dispose()


def test_retention_executes_only_the_purge(fresh_db: MigratedDatabase) -> None:
    command.upgrade(alembic_cfg(fresh_db.migrator_url), "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.connect() as conn:
            allowed = (
                conn.execute(
                    text(
                        "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
                        "WHERE r.rolname = 'migrator' AND has_function_privilege('retention', p.oid, 'EXECUTE')"
                    )
                )
                .scalars()
                .all()
            )
        assert allowed == ["purge_retention()"]
    finally:
        engine.dispose()


def test_provisioning_refuses_a_foreign_role(postgres_url: str) -> None:
    """A role named like Hermes' but not created by Hermes must not receive access."""
    admin = make_engine(postgres_url)
    with provisioned_database(postgres_url, "probe"):
        pass  # make sure the Hermes roles exist and are marked
    try:
        with admin.begin() as conn:
            conn.execute(text("COMMENT ON ROLE slack_module IS NULL"))
        with pytest.raises(Exception, match="not managed by Hermes"), provisioned_database(postgres_url, "foreign"):
            pass
    finally:
        with admin.begin() as conn:
            conn.execute(text("COMMENT ON ROLE slack_module IS 'hermes-managed'"))
        admin.dispose()


def test_downgrade_aborts_on_a_dependent_foreign_view(fresh_db: MigratedDatabase) -> None:
    """Without CASCADE, an external view on a Hermes view blocks the downgrade instead of being dropped."""
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE VIEW slack_ticket_scores AS SELECT * FROM ticket_score"))
        with pytest.raises(Exception, match="depend"):
            command.downgrade(cfg, "base")
        assert "slack_ticket_scores" in inspect(engine).get_view_names()
        # The whole downgrade rolled back: still at head, and the app keeps its grants and the purge.
        with engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0004"
            assert conn.execute(text("SELECT has_table_privilege('app', 'ticket', 'SELECT')")).scalar_one()
            assert conn.execute(text("SELECT to_regprocedure('purge_retention()') IS NOT NULL")).scalar_one()
    finally:
        engine.dispose()


def test_autogenerate_ignores_foreign_tables(fresh_db: MigratedDatabase) -> None:
    """A slack_* table missing from the models must not show up as a drop in autogenerate."""
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "head")
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE slack_delivery (id int PRIMARY KEY)"))
        command.check(cfg)
    finally:
        engine.dispose()


def test_scram_login_works_and_server_never_sees_plaintext(postgres_url: str) -> None:
    """The migrator logs in with the password whose SCRAM verifier was computed on the client."""
    with provisioned_database(postgres_url, "scram") as db:
        engine = make_engine(db.migrator_url)
        try:
            with engine.connect() as conn:
                assert conn.execute(text("SELECT current_user")).scalar_one() == "migrator"
        finally:
            engine.dispose()
        admin = make_engine(db.superuser_url)
        try:
            with admin.connect() as conn:
                stored = conn.execute(text("SELECT rolpassword FROM pg_authid WHERE rolname = 'migrator'")).scalar_one()
            assert stored.startswith("SCRAM-SHA-256$4096:")
        finally:
            admin.dispose()


def test_saslprep_password_logs_in(postgres_url: str) -> None:
    """A password that SASLprep changes (non-breaking space, compatibility characters) still logs in."""
    # NBSP and ROMAN NUMERAL NINE are normalized by SASLprep
    sasl_secret = "".join(["pa", "\u00a0", "ss", "\u2168", "word"])
    with provisioned_database(postgres_url, "saslprep") as db:
        provision(db.superuser_url, {"app": sasl_secret}, ROOT / "migrations" / "provision.sql")
        url = make_url(db.superuser_url).set(username="app", password=sasl_secret).render_as_string(hide_password=False)
        engine = make_engine(url)
        try:
            with engine.connect() as conn:
                assert conn.execute(text("SELECT current_user")).scalar_one() == "app"
        finally:
            engine.dispose()


def test_provision_is_atomic(postgres_url: str) -> None:
    """Invalid input changes nothing: no role password is touched when one entry is invalid."""
    with provisioned_database(postgres_url, "atomic") as db, pytest.raises(ValueError, match="Empty password"):
        provision(db.superuser_url, {"app": "new-one", "retention": ""}, ROOT / "migrations" / "provision.sql")


def test_functions_pin_a_trusted_search_path(fresh_db: MigratedDatabase) -> None:
    """Every function of 0001 has exactly pg_catalog, public, pg_temp; going back to 0002 restores the default."""
    cfg = alembic_cfg(fresh_db.migrator_url)
    command.upgrade(cfg, "head")
    query = text(
        "SELECT p.oid::regprocedure::text, p.proconfig FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
        "WHERE r.rolname = 'migrator' AND p.proname NOT IN ('purge_retention', 'retention_days')"
    )
    engine = make_engine(fresh_db.superuser_url)
    try:
        with engine.connect() as conn:
            pinned = dict(conn.execute(query).tuples().all())
        assert len(pinned) == 13
        assert all(config == ["search_path=pg_catalog, public, pg_temp"] for config in pinned.values()), pinned
        command.downgrade(cfg, "0002")
        with engine.connect() as conn:
            restored = dict(conn.execute(query).tuples().all())
        assert all(config is None for config in restored.values()), restored
    finally:
        engine.dispose()
