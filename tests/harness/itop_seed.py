"""Seed loader for the iTop test instance: a YAML file of objects -> iTop through its REST API.

    ITOP_URL=http://127.0.0.1:8080 ITOP_TOKEN=... PYTHONPATH=tests python -m harness.itop_seed docker/itop/stack.yaml
    ... --apply            write what is missing (without it: dry run, nothing is written)
    ... --apply --update   also rewrite the fields of objects that already exist

Adapted from the prototype's load_stack.py (English keys, httpx, typed). File format:

    objects:
      - class: Server                  # any iTop class
        name: web-frontend-01          # identifies the object (field `name`, or `key` when given)
        fields:                        # iTop field names exactly as the REST API expects them
          org_id: "@Organization:Demo-Lab"      # reference to another object: @Class:name
          internet_exposed: "yes"

Rules: objects are processed in file order; a reference must point to an object defined earlier in the file or
already in iTop; nothing is written when a reference is broken. Existing objects (same class and key) are left
alone unless --update. For test instances only: it refuses plain http to a non-local host.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx
import yaml

REST_PATH: Final = "/webservices/rest.php"
TIMEOUT: Final = httpx.Timeout(15.0, connect=5.0)
_IDENTIFIER: Final = re.compile(r"^\w+$")
_REF: Final = re.compile(r"^@(\w+):(.+)$", re.S)


class ItopError(RuntimeError):
    """iTop rejected an operation (non-zero `code`) or could not be reached."""


def quote(value: object) -> str:
    """An OQL string literal. Control characters are refused; quotes and backslashes are escaped."""
    text = str(value)
    if any(ord(ch) < 32 for ch in text):
        raise ValueError("control characters are not allowed in OQL values")
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def select_by(class_name: str, attribute: str, value: object) -> str:
    for name in (class_name, attribute):
        if not _IDENTIFIER.match(name):
            raise ValueError(f"invalid class or field name: {name!r}")
    return f"SELECT {class_name} WHERE {attribute} = {quote(value)}"


def _is_local(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ItopRest:
    """The few REST operations the seed needs. Authenticates with the `Auth-Token` header."""

    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None) -> None:
        parsed = httpx.URL(base_url)
        if parsed.scheme != "https" and not _is_local(parsed.host):
            raise ValueError("refusing to send the token over plain http to a non-local host")
        self._client = httpx.Client(
            base_url=base_url, headers={"Auth-Token": token}, timeout=TIMEOUT, transport=transport
        )

    def _call(self, operation: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(
                REST_PATH, params={"version": "1.3"}, data={"json_data": json.dumps(operation)}
            )
            response.raise_for_status()
            body: dict[str, Any] = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise ItopError(f"could not talk to iTop: {type(error).__name__}") from error
        if body.get("code") != 0:
            raise ItopError(str(body.get("message", "unknown error")))
        return body

    def find(self, class_name: str, attribute: str, value: object) -> str | None:
        body = self._call(
            {
                "operation": "core/get",
                "class": class_name,
                "key": select_by(class_name, attribute, value),
                "output_fields": "id",
            }
        )
        objects: dict[str, Any] = body.get("objects") or {}
        return str(next(iter(objects.values()))["key"]) if objects else None

    def create(self, class_name: str, fields: dict[str, Any]) -> str:
        body = self._call(
            {
                "operation": "core/create",
                "class": class_name,
                "fields": fields,
                "output_fields": "id",
                "comment": "seed",
            }
        )
        return str(next(iter(body["objects"].values()))["key"])

    def update(self, class_name: str, key: str, fields: dict[str, Any]) -> None:
        self._call({"operation": "core/update", "class": class_name, "key": key, "fields": fields, "comment": "seed"})


@dataclass
class Spec:
    class_name: str
    name: str
    key_field: str = "name"
    fields: dict[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> str:
        return f"@{self.class_name}:{self.name}"


@dataclass
class Plan:
    actions: list[tuple[str, Spec, str | None]] = field(default_factory=list)  # (create|exists|update, spec, id)
    errors: list[str] = field(default_factory=list)


def parse_file(path: Path) -> list[Spec]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = data.get("objects")
    if not isinstance(raw, list) or not raw:
        raise ValueError("the file needs a non-empty list `objects`")
    specs: list[Spec] = []
    for position, item in enumerate(raw, start=1):
        if not isinstance(item, dict) or not item.get("class") or not item.get("name"):
            raise ValueError(f"object #{position} needs `class` and `name`")
        unknown = set(item) - {"class", "name", "key", "fields"}
        if unknown:
            raise ValueError(f"object #{position} ({item['name']}): unknown keys {sorted(unknown)}")
        select_by(str(item["class"]), str(item.get("key", "name")), "")  # validates the identifiers
        specs.append(
            Spec(str(item["class"]), str(item["name"]), str(item.get("key", "name")), dict(item.get("fields") or {}))
        )
    refs = [spec.ref for spec in specs]
    duplicated = {r for r in refs if refs.count(r) > 1}
    if duplicated:
        raise ValueError(f"duplicated objects: {sorted(duplicated)}")
    return specs


def _refs_in(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if _REF.match(value) else []
    if isinstance(value, list):
        return [ref for item in value for ref in _refs_in(item)]
    if isinstance(value, dict):
        return [ref for item in value.values() for ref in _refs_in(item)]
    return []


def _resolve(value: Any, ids: dict[str, str]) -> Any:
    if isinstance(value, str):
        return ids.get(value, value)
    if isinstance(value, list):
        return [_resolve(item, ids) for item in value]
    if isinstance(value, dict):
        return {key: _resolve(item, ids) for key, item in value.items()}
    return value


class StackLoader:
    def __init__(self, itop: ItopRest) -> None:
        self.itop = itop

    def _lookup_ref(self, ref: str) -> str | None:
        match = _REF.match(ref)
        assert match  # only strings that matched _REF reach this point
        return self.itop.find(match.group(1), "name", match.group(2))

    def plan(self, specs: Sequence[Spec], *, update: bool = False) -> tuple[Plan, dict[str, str]]:
        """Decide create / exists / update per object and check every reference. Returns the plan and the real
        iTop ids already known (existing objects and referenced ones), keyed by `@Class:name`."""
        plan = Plan()
        ids: dict[str, str] = {}
        defined: set[str] = set()  # objects declared earlier in the file (they may not exist in iTop yet)
        for spec in specs:
            for ref in _refs_in(spec.fields):
                if ref in defined or ref in ids:
                    continue
                found = self._lookup_ref(ref)
                if found is None:
                    plan.errors.append(f"{spec.ref} points to {ref}, which is not in iTop nor earlier in the file")
                else:
                    ids[ref] = found
            existing = self.itop.find(spec.class_name, spec.key_field, spec.name)
            if existing:
                plan.actions.append(("update" if update else "exists", spec, existing))
                ids[spec.ref] = existing
            else:
                plan.actions.append(("create", spec, None))
            defined.add(spec.ref)
        return plan, ids

    def apply(self, plan: Plan, ids: dict[str, str]) -> None:
        for action, spec, existing in plan.actions:
            fields = _resolve(spec.fields, ids)
            if action == "create":
                ids[spec.ref] = self.itop.create(spec.class_name, {spec.key_field: spec.name, **fields})
            elif action == "update" and existing and fields:
                self.itop.update(spec.class_name, existing, fields)


def _from_environment() -> ItopRest | None:
    url, token = os.environ.get("ITOP_URL", ""), os.environ.get("ITOP_TOKEN", "")
    if not url or not token:
        sys.stderr.write("ITOP_URL and ITOP_TOKEN must be set (use the seed token of the test instance)\n")
        return None
    try:
        return ItopRest(url, token)
    except ValueError as error:
        sys.stderr.write(f"{error}\n")
        return None


def run(argv: Sequence[str] | None = None, itop: ItopRest | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness.itop_seed", description=__doc__.split("\n")[0])
    parser.add_argument("file", type=Path)
    parser.add_argument("--apply", action="store_true", help="write to iTop (without it nothing is written)")
    parser.add_argument("--update", action="store_true", help="also update the fields of existing objects")
    args = parser.parse_args(argv)
    try:
        specs = parse_file(args.file)
    except (OSError, ValueError, yaml.YAMLError) as error:
        sys.stderr.write(f"invalid file: {error}\n")
        return 2
    itop = itop or _from_environment()
    if itop is None:
        return 2
    loader = StackLoader(itop)
    try:
        plan, ids = loader.plan(specs, update=args.update)
        labels = {"create": "+ create  ", "exists": "= exists  ", "update": "~ update  "}
        for action, spec, _ in plan.actions:
            sys.stdout.write(f"{labels[action]} {spec.class_name} '{spec.name}'\n")
        if plan.errors:
            sys.stderr.write("nothing was written, fix these references:\n")
            sys.stderr.writelines(f"  - {error}\n" for error in plan.errors)
            return 1
        if not args.apply:
            sys.stdout.write("dry run: nothing was written; repeat with --apply\n")
            return 0
        loader.apply(plan, ids)
    except ItopError as error:
        sys.stderr.write(f"iTop failed: {error}\n(what was created stays; running the file again resumes)\n")
        return 1
    sys.stdout.write("done\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
