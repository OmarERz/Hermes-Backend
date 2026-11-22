"""Test ID tokens from the Firebase Auth emulator (D-069).

`python -m core.devtools.emulator token --role analyst` prints one ID token on stdout. It creates (or reuses)
one test user per role, sets the `role` custom claim through the emulator admin endpoint and signs in. It
refuses to run unless FIREBASE_AUTH_EMULATOR_HOST is set, so it can never reach real Firebase.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import Final

import httpx

ROLES: Final = ("admin", "analyst", "reader")
DEFAULT_PROJECT: Final = "demo-hermes"
TIMEOUT: Final = httpx.Timeout(10.0, connect=3.0)
# The emulator accepts any API key and any "Bearer owner" token as project owner.
API_KEY: Final = "fake-api-key"
OWNER_HEADERS: Final = {"Authorization": "Bearer owner"}
# Fixed password of the throwaway emulator users: they exist only inside the emulator container.
TEST_PASSWORD: Final = "emulator-test-password"  # noqa: S105


class EmulatorError(RuntimeError):
    """The emulator is missing or answered something unexpected."""


def _email(role: str) -> str:
    return f"{role}@hermes.test"


def _check(response: httpx.Response, action: str) -> dict[str, object]:
    if response.status_code != httpx.codes.OK:
        raise EmulatorError(f"emulator {action} failed with HTTP {response.status_code}")
    body: dict[str, object] = response.json()
    return body


def fetch_token(client: httpx.Client, project_id: str, role: str) -> str:
    """Create or reuse the user of `role`, set its role claim and return a fresh ID token."""
    if role not in ROLES:
        raise EmulatorError(f"unknown role {role!r}; expected one of {', '.join(ROLES)}")
    credentials = {"email": _email(role), "password": TEST_PASSWORD, "returnSecureToken": True}
    base = "/identitytoolkit.googleapis.com/v1"
    params = {"key": API_KEY}

    sign_up = client.post(f"{base}/accounts:signUp", params=params, json=credentials)
    if sign_up.status_code == httpx.codes.OK:
        local_id = str(sign_up.json()["localId"])
    else:
        sign_in = _check(
            client.post(f"{base}/accounts:signInWithPassword", params=params, json=credentials),
            "sign-in of the existing user",
        )
        local_id = str(sign_in["localId"])

    claims = json.dumps({"role": role})
    _check(
        client.post(
            f"{base}/projects/{project_id}/accounts:update",
            headers=OWNER_HEADERS,
            json={"localId": local_id, "customAttributes": claims},
        ),
        "custom claims update",
    )
    # A new sign-in is needed: the token minted at sign-up predates the claim.
    signed = _check(
        client.post(f"{base}/accounts:signInWithPassword", params=params, json=credentials),
        "sign-in",
    )
    return str(signed["idToken"])


def main(argv: Sequence[str] | None = None, transport: httpx.BaseTransport | None = None) -> int:
    parser = argparse.ArgumentParser(prog="core.devtools.emulator", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    token = sub.add_parser("token", help="print an ID token of the Firebase Auth emulator")
    token.add_argument("--role", choices=ROLES, required=True)
    args = parser.parse_args(argv)

    host = os.environ.get("FIREBASE_AUTH_EMULATOR_HOST", "").strip()
    if not host:
        sys.stderr.write("FIREBASE_AUTH_EMULATOR_HOST is not set: refusing to run against real Firebase\n")
        return 2
    project_id = os.environ.get("FIREBASE_PROJECT_ID", "").strip() or DEFAULT_PROJECT
    try:
        with httpx.Client(base_url=f"http://{host}", timeout=TIMEOUT, transport=transport) as client:
            id_token = fetch_token(client, project_id, args.role)
    except (EmulatorError, httpx.HTTPError, KeyError) as error:
        sys.stderr.write(f"could not get a test token from the emulator at {host}: {type(error).__name__}\n")
        return 1
    sys.stdout.write(id_token + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
