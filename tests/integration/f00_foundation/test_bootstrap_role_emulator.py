"""`python -m api.auth.bootstrap` end to end (make set-role, D-087): the Auth emulator stands in for the real Firebase
project and the database is migrated and reached as the app role, exactly as the command runs in the API container.

Needs Docker (the emulator and PostgreSQL containers); no network and no real Firebase project.
"""

from __future__ import annotations

import io
import secrets
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from dbprovision import provisioned_database
from firebase_admin import auth, initialize_app
from sqlalchemy import select
from sqlalchemy.engine import make_url
from testcontainers.core.config import testcontainers_config

from api.auth.bootstrap import main
from core.db.models import AppUser, AuditLog
from core.db.provision import provision
from core.db.session import make_engine

testcontainers_config.ryuk_disabled = True

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]
PROJECT = "demo-hermes"


@pytest.fixture
def app_database(postgres_url: str) -> Iterator[tuple[str, str]]:
    """(app role URL, superuser URL) of a migrated throwaway database."""
    with provisioned_database(postgres_url, "bootstrap") as db:
        cfg = Config(str(ROOT / "alembic.ini"))
        cfg.attributes["url"] = db.migrator_url
        command.upgrade(cfg, "head")
        password = secrets.token_urlsafe(16)
        provision(db.superuser_url, {"app": password}, ROOT / "migrations" / "provision.sql")
        app_url = make_url(db.superuser_url).set(username="app", password=password)
        yield app_url.render_as_string(hide_password=False), db.superuser_url


@pytest.fixture
def api_environment(
    emulator_host: str, app_database: tuple[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> str:
    """The API container's settings: the emulator, the demo project and the app role (no env file is read)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", emulator_host)
    monkeypatch.setenv("FIREBASE_PROJECT_ID", PROJECT)
    monkeypatch.setenv("DATABASE_URL", app_database[0])
    monkeypatch.setenv("CURSOR_SIGNING_KEY", secrets.token_urlsafe(40))
    return app_database[1]


def sign_up(host: str) -> tuple[str, str]:
    """A Firebase account created the way the front does it (Email/Password); returns (uid, e-mail)."""
    email = f"{secrets.token_hex(4)}@example.com"
    response = httpx.post(
        f"http://{host}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake",
        json={"email": email, "password": secrets.token_urlsafe(16), "returnSecureToken": True},
        timeout=30,
    )
    response.raise_for_status()
    return str(response.json()["localId"]), email


def run(email: str, role: str, *extra: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(["--email", email, "--role", role, *extra], out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_set_role_gives_the_first_admin_its_claim_and_copy(api_environment: str, emulator_host: str) -> None:
    uid, email = sign_up(emulator_host)

    # Email/Password sign-up does not prove the address: the first run only shows the account to confirm.
    unconfirmed, _, warnings = run(email, "admin")
    code, text, _ = run(email, "admin", "--confirm-uid", uid)
    again, text_again, _ = run(email, "admin", "--confirm-uid", uid)

    assert (unconfirmed, code, again) == (3, 0, 0)
    assert f"not verified in Firebase: account {uid}" in warnings and email not in warnings
    assert f"role admin set for {uid} (created in Hermes); sessions revoked" in text
    assert f"{uid} already has the role admin; nothing changed" in text_again
    admin_sdk = initialize_app(options={"projectId": PROJECT}, name=f"check-{secrets.token_hex(4)}")
    assert auth.get_user(uid, app=admin_sdk).custom_claims == {"role": "admin"}
    engine = make_engine(api_environment)
    try:
        with engine.connect() as conn:
            row = conn.execute(select(AppUser.role, AppUser.active).where(AppUser.firebase_uid == uid)).one()
            actions = conn.scalars(select(AuditLog.action).where(AuditLog.entity_id == uid).order_by(AuditLog.id)).all()
    finally:
        engine.dispose()
    assert tuple(row) == ("admin", True)
    assert actions == ["role_assignment_requested", "user_created", "role_assigned"]


def test_set_role_explains_an_unknown_email(api_environment: str) -> None:
    code, _, errors = run("nobody@example.com", "admin")
    assert code == 1
    assert "no Firebase account has that e-mail" in errors
