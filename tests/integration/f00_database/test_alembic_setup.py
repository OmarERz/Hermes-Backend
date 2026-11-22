"""Alembic needs an explicit migrator URL and its revision template produces runnable migrations."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from core.db.session import make_engine

ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.integration


def alembic_config() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def test_template_imports_sqlalchemy() -> None:
    template = (ROOT / "migrations" / "script.py.mako").read_text(encoding="utf-8")
    assert "import sqlalchemy as sa" in template


def test_requires_migration_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MIGRATION_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://app:pw@localhost/hermes")
    with pytest.raises(RuntimeError, match="MIGRATION_DATABASE_URL"):
        command.current(alembic_config())


def test_script_directory_loads() -> None:
    assert ScriptDirectory.from_config(alembic_config()).dir.endswith("migrations")


def test_generated_revision_upgrades_and_downgrades(postgres_url: str, tmp_path: Path) -> None:
    """A revision rendered from our template runs both ways through our env.py (DAT-03)."""
    shutil.copy(ROOT / "migrations" / "env.py", tmp_path / "env.py")
    shutil.copy(ROOT / "migrations" / "script.py.mako", tmp_path / "script.py.mako")
    (tmp_path / "versions").mkdir()
    cfg = alembic_config()
    cfg.set_main_option("script_location", str(tmp_path))
    cfg.attributes["url"] = postgres_url
    script = command.revision(cfg, message="probe", rev_id="probe0001")
    assert script is not None and not isinstance(script, list)
    path = Path(script.path)
    body = path.read_text(encoding="utf-8")
    body = body.replace(
        "def upgrade() -> None:\n    pass",
        'def upgrade() -> None:\n    op.create_table("alembic_probe", sa.Column("id", sa.Integer, primary_key=True))',
    ).replace("def downgrade() -> None:\n    pass", 'def downgrade() -> None:\n    op.drop_table("alembic_probe")')
    path.write_text(body, encoding="utf-8")

    engine = make_engine(postgres_url)
    try:
        command.upgrade(cfg, "head")
        assert "alembic_probe" in inspect(engine).get_table_names()
        command.downgrade(cfg, "base")
        assert "alembic_probe" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_autogenerate_refused_without_models(postgres_url: str, tmp_path: Path) -> None:
    """Until the models are wired in, autogenerate must fail rather than propose dropping tables."""
    shutil.copy(ROOT / "migrations" / "env.py", tmp_path / "env.py")
    shutil.copy(ROOT / "migrations" / "script.py.mako", tmp_path / "script.py.mako")
    (tmp_path / "versions").mkdir()
    cfg = alembic_config()
    cfg.set_main_option("script_location", str(tmp_path))
    cfg.attributes["url"] = postgres_url
    with pytest.raises(Exception, match="MetaData"):
        command.revision(cfg, message="auto", autogenerate=True)
