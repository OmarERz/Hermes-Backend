"""Inventory loader for iTop (F16.2): a YAML file of CMDB objects -> iTop through its REST API, with a report.

    make itop-load INVENTORY=<file>                    dry run: what would be created, updated or left alone
    make itop-load INVENTORY=<file> APPLY=1            create what is missing
    make itop-load INVENTORY=<file> APPLY=1 UPDATE=1   also bring existing objects to the file's values
    make itop-map-cpe INVENTORY=<file>                 set each product's CPE through the Hermes API (after a sync)

It lives in the test harness on purpose: it writes CMDB objects straight to iTop, which ARQ-01 (and its Semgrep rule)
allows only in the outbox and in tests/. It is not part of the backend packages and never runs in the images.

`make itop-load` hands the loader the iTop URL and a token of the hermes-seed administrator, which only exists while
the loader runs (docker/itop/provision.php). By hand:
    ITOP_URL=... ITOP_TOKEN=... PYTHONPATH=tests uv run python -m harness.itop_load FILE [--apply] [--update]
    HERMES_API_URL=... HERMES_API_TOKEN=... PYTHONPATH=tests uv run python -m harness.itop_load FILE --map-cpe

File format (YAML; PyYAML is a development dependency: the loader runs on the operator's machine, not in the images):

    env:                                    # optional: ids for the Hermes env file, printed at the end
      ITOP_ORG_ID: "@Organization:Demo-Lab"
    cpe:                                    # optional: product (Software name) -> CPE name for --map-cpe;
      PostgreSQL: "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"    # null = no CPE on purpose
    objects:
      - class: Server                       # any iTop class
        name: web-frontend-01               # value of the identity key's first field
        key: name                           # optional: a field or a list of fields; Software: [name, version]
        ref: web-01                         # optional: how references name it; default: the key values, spaced
        fields:                             # iTop field names exactly as the REST API expects them
          org_id: "@Organization:Demo-Lab"  # a reference: @Class:ref
          internet_exposed: "yes"
          cpu: "8"                          # any field: description, cpu, ram, a product's `type` (category),
          ram: "32 GB"                      # an installation's `status` and `softwarelicence_id`...

Rules: objects are processed in file order; a reference points to an object defined earlier in the file or, for a
class identified by a single field, to one already in iTop; nothing is written when a reference is broken. An object
whose identity key matches an existing one is left alone, or with --update gets only the fields whose value differs
(a link list differs when the set of linked objects differs). Values are data: names and descriptions are sent as
they are and never interpreted. Plain http is accepted only for local hosts (the iTop and API containers or this
machine: localhost or a loopback IP); anything else needs https.
"""

from __future__ import annotations

import argparse
import datetime
import html
import ipaddress
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

import httpx

from core.itop import oql
from core.itop.oql import FIRST_PRINTABLE

REST_PATH: Final = "/webservices/rest.php"
TIMEOUT: Final = httpx.Timeout(15.0, connect=5.0)
# Identity key per class when the file does not say: two catalogue entries may share a name (one per version).
DEFAULT_KEYS: Final[dict[str, tuple[str, ...]]] = {"Software": ("name", "version")}
HTTP_ERROR: Final = 400
LOCAL_HOSTS: Final = frozenset({"localhost"})  # plus loopback IPs: the loader runs on this machine, not in a container
ITEM_KEYS: Final = frozenset({"class", "name", "key", "ref", "fields"})
FILE_KEYS: Final = frozenset({"objects", "env", "cpe"})
_REF: Final = re.compile(r"^@(\w+):(.+)$", re.S)
_ENV_NAME: Final = re.compile(r"^[A-Z][A-Z0-9_]*$")
# cpe:2.3:part:vendor:product followed by the other eight components (the API needs a full CPE name).
_CPE_NAME: Final = re.compile(r"^cpe:2\.3:[ao](?::(?:[^:\\\s]|\\.)+){2}(?::(?:[^:\\\s]|\\.)*){8}$")
_ACTION_LABELS: Final = {
    "create": "+ create   ",
    "update": "~ update   ",
    "unchanged": "= unchanged",
    "exists": "= exists   ",
}

Kind = Literal["create", "update", "unchanged", "exists"]


class LoaderError(RuntimeError):
    """iTop or the Hermes API refused an operation or could not be reached (the message names no credential)."""


def _is_local(host: str) -> bool:
    if host in LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _client(base_url: str, headers: dict[str, str], transport: httpx.BaseTransport | None) -> httpx.Client:
    parsed = httpx.URL(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.host:
        raise ValueError(f"not an http(s) URL: {base_url!r}")
    if parsed.scheme != "https" and not _is_local(parsed.host):
        raise ValueError("refusing to send a token over plain http to a non-local host")
    return httpx.Client(base_url=base_url, headers=headers, timeout=TIMEOUT, transport=transport)


class ItopRest:
    """The few REST operations the loader needs, authenticated with the `Auth-Token` header."""

    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None) -> None:
        self._client = _client(base_url, {"Auth-Token": token}, transport)

    def _call(self, operation: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(
                REST_PATH, params={"version": "1.3"}, data={"json_data": json.dumps(operation)}
            )
            response.raise_for_status()
            body: dict[str, Any] = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise LoaderError(f"could not talk to iTop: {type(error).__name__}") from error
        if body.get("code") != 0:
            raise LoaderError(str(body.get("message", "unknown error")))
        return body

    def find(self, class_name: str, key: Mapping[str, str]) -> str | None:
        query = oql.select(class_name, *(oql.eq(name, value) for name, value in key.items()))
        body = self._call({"operation": "core/get", "class": class_name, "key": query, "output_fields": "id"})
        objects: dict[str, Any] = body.get("objects") or {}
        if len(objects) > 1:
            raise LoaderError(f"{len(objects)} {class_name} objects match {dict(key)}: make the key more specific")
        return str(next(iter(objects.values()))["key"]) if objects else None

    def read(self, class_name: str, object_id: str, names: Sequence[str]) -> dict[str, Any]:
        operation = {
            "operation": "core/get",
            "class": class_name,
            "key": int(object_id),
            "output_fields": ",".join(names),
        }
        objects: dict[str, Any] = self._call(operation).get("objects") or {}
        if not objects:
            raise LoaderError(f"{class_name} {object_id} disappeared from iTop")
        fields: dict[str, Any] = next(iter(objects.values())).get("fields") or {}
        return fields

    def create(self, class_name: str, fields: dict[str, Any]) -> str:
        operation = {"operation": "core/create", "class": class_name, "fields": fields, "output_fields": "id"}
        body = self._call({**operation, "comment": "inventory loader"})
        return str(next(iter(body["objects"].values()))["key"])

    def update(self, class_name: str, object_id: str, fields: dict[str, Any]) -> None:
        operation = {"operation": "core/update", "class": class_name, "key": int(object_id), "fields": fields}
        self._call({**operation, "comment": "inventory loader"})


class HermesApi:
    """The two Hermes API routes of the CPE step, with an analyst's bearer token."""

    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None) -> None:
        self._client = _client(base_url, {"Authorization": f"Bearer {token}"}, transport)

    def _send(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        try:
            response = self._client.request(method, path, json=body)
        except httpx.HTTPError as error:
            raise LoaderError(f"could not talk to the Hermes API: {type(error).__name__}") from error
        if response.status_code in {401, 403}:
            raise LoaderError("the Hermes API refused the token (it needs the analyst role or higher)")
        if response.status_code >= HTTP_ERROR:
            try:
                message = str(response.json().get("message", ""))
            except ValueError:
                message = ""
            raise LoaderError(f"the Hermes API answered {response.status_code} to {method} {path}: {message}".strip())
        return response.json()

    def pending_products(self) -> dict[str, str]:
        """Products waiting for a CPE: name -> product id (GET /api/pending/inventory, `software_without_cpe`)."""
        body = self._send("GET", "/api/pending/inventory")
        return {str(item["name"]): str(item["ci_id"]) for item in body.get("software_without_cpe") or []}

    def set_cpe(self, product_id: str, cpe: str) -> None:
        self._send("PUT", f"/api/mappings/{product_id}", {"cpe": cpe})


@dataclass(frozen=True)
class Spec:
    """One object of the file: its identity key (field -> value, in order), its reference and its other fields."""

    class_name: str
    key: dict[str, str]
    ref: str
    fields: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"@{self.class_name}:{self.ref}"


@dataclass
class Inventory:
    specs: list[Spec]
    env: dict[str, str] = field(default_factory=dict)
    cpe: dict[str, str | None] = field(default_factory=dict)


@dataclass
class Action:
    kind: Kind
    spec: Spec
    object_id: str | None = None
    changed: list[str] = field(default_factory=list)


def _check_values(value: Any, what: str) -> None:
    """Refuse what YAML turns into something other than text by itself (an unquoted date, yes/no, true/false) and
    control characters: iTop wants the text the file shows, and a date would not even reach it as JSON."""
    if isinstance(value, dict):
        for name, item in value.items():
            _check_values(item, f"{what}.{name}")
    elif isinstance(value, list):
        for item in value:
            _check_values(item, what)
    elif isinstance(value, (bool, datetime.date)):
        raise TypeError(f'{what}: YAML read {value!r} as a {type(value).__name__}: quote it ("{value}")')
    elif isinstance(value, str) and any(ord(ch) < FIRST_PRINTABLE and ch not in "\t\n" for ch in value):
        raise ValueError(f"{what}: control characters are not allowed")


def _text(value: Any, what: str) -> str:
    if isinstance(value, (dict, list)) or value is None or value == "":
        raise ValueError(f"{what} must be a non-empty text")
    _check_values(value, what)
    if "\n" in str(value) or "\t" in str(value):
        raise ValueError(f"{what}: control characters are not allowed")
    return str(value)


def _spec(position: int, item: Any) -> Spec:
    if not isinstance(item, dict) or not item.get("class") or item.get("name") in (None, ""):
        raise ValueError(f"object #{position} needs `class` and `name`")
    unknown = set(item) - ITEM_KEYS
    if unknown:
        raise ValueError(f"object #{position} ({item['name']}): unknown keys {sorted(unknown)}")
    class_name = oql.require_identifier(str(item["class"]))
    raw_key = item.get("key", DEFAULT_KEYS.get(class_name, ("name",)))
    key_fields = (raw_key,) if isinstance(raw_key, str) else tuple(raw_key)
    if not key_fields or not all(isinstance(name, str) for name in key_fields):
        raise ValueError(f"object #{position}: `key` must be a field name or a list of field names")
    fields = item.get("fields") or {}
    if not isinstance(fields, dict):
        raise TypeError(f"object #{position}: `fields` must be a mapping")
    fields = dict(fields)
    key = {oql.require_identifier(key_fields[0]): _text(item["name"], f"object #{position}: `name`")}
    for name in key_fields[1:]:
        if name not in fields:
            raise ValueError(f"object #{position} ({item['name']}): key field `{name}` needs a value in `fields`")
        key[oql.require_identifier(name)] = _text(fields.pop(name), f"object #{position}: `{name}`")
    for name in fields:
        oql.require_identifier(name)
    _check_values(fields, f"object #{position} ({item['name']}) fields")
    ref = _text(item["ref"], f"object #{position}: `ref`") if "ref" in item else " ".join(key.values())
    return Spec(class_name, key, ref, fields)


def parse_inventory(path: Path) -> Inventory:
    """Read and check the file; raises OSError, ValueError or TypeError with what is wrong, before sending."""
    import yaml  # noqa: PLC0415  (development dependency: only the loader needs it)

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as error:
        raise ValueError(f"not valid YAML: {error}") from error
    if not isinstance(data, dict):
        raise TypeError("the file must be a mapping with a list `objects`")
    unknown = set(data) - FILE_KEYS
    if unknown:
        raise ValueError(f"unknown top-level keys {sorted(unknown)}")
    raw = data.get("objects")
    if not isinstance(raw, list) or not raw:
        raise ValueError("the file needs a non-empty list `objects`")
    specs = [_spec(position, item) for position, item in enumerate(raw, start=1)]
    labels = [spec.label for spec in specs]
    duplicated = {label for label in labels if labels.count(label) > 1}
    if duplicated:
        raise ValueError(f"duplicated objects: {sorted(duplicated)} (give them a different `ref` or key)")
    identities = [(spec.class_name, tuple(spec.key.items())) for spec in specs]
    twins = sorted({f"{c} {dict(k)}" for c, k in identities if identities.count((c, k)) > 1})
    if twins:
        raise ValueError(f"objects with the same identity key: {twins} (iTop would get two of them: change the key)")
    env = data.get("env") or {}
    if not isinstance(env, dict) or not all(
        isinstance(k, str) and _ENV_NAME.match(k) and isinstance(v, str) and _REF.match(v) for k, v in env.items()
    ):
        raise ValueError("`env` maps variable names (UPPER_CASE) to references (@Class:ref)")
    cpe = data.get("cpe") or {}
    if not isinstance(cpe, dict):
        raise TypeError("`cpe` maps product names to CPE names")
    for product, name in cpe.items():
        if name is not None and not (isinstance(name, str) and _CPE_NAME.match(name)):
            raise ValueError(f"`cpe` of {product!r}: not a full CPE 2.3 name (cpe:2.3:a:vendor:product:*:...)")
    return Inventory(specs, dict(env), {str(k): v for k, v in cpe.items()})


def refs_in(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if _REF.match(value) else []
    if isinstance(value, list):
        return [ref for item in value for ref in refs_in(item)]
    if isinstance(value, dict):
        return [ref for item in value.values() for ref in refs_in(item)]
    return []


def resolve(value: Any, ids: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        return ids.get(value, value)
    if isinstance(value, list):
        return [resolve(item, ids) for item in value]
    if isinstance(value, dict):
        return {key: resolve(item, ids) for key, item in value.items()}
    return value


def same(current: Any, wanted: Any) -> bool:
    """Whether iTop's value already is the file's: text compared as text (an HTML field comes back wrapped in one
    paragraph, with entities; an unset external key comes back as 0); a link list compared as the set of the file's
    sub-fields (iTop returns more of them, the link ids, and the links its impact analysis computed, which nobody
    writes)."""
    if isinstance(wanted, list):
        if not isinstance(current, list):
            return False
        names = sorted({name for item in wanted if isinstance(item, dict) for name in item})

        def projection(items: list[Any]) -> list[tuple[str, ...]]:
            return sorted(
                tuple(str(item.get(n, "")) for n in names)
                for item in items
                if isinstance(item, dict) and item.get("impact_code") != "computed"
            )

        return projection(current) == projection(wanted)
    if isinstance(wanted, dict):
        return False
    text, target = ("" if current is None else str(current)), ("" if wanted is None else str(wanted))
    if text == "0" and target == "":  # iTop returns an unset external key as 0
        return True
    return html.unescape(text) in {target, f"<p>{target}</p>"}


class Loader:
    def __init__(self, itop: ItopRest) -> None:
        self.itop = itop
        self.ids: dict[str, str] = {}  # `@Class:ref` -> iTop id, for objects known to exist
        self.done: list[Action] = []  # what apply() already went through, reported if it stops halfway

    def lookup(self, ref: str) -> str | None:
        """The iTop id of a reference to an object not defined in the file (single-field identity only)."""
        if ref in self.ids:
            return self.ids[ref]
        match = _REF.match(ref)
        if not match:
            return None
        class_name, value = match.groups()
        key_fields = DEFAULT_KEYS.get(class_name, ("name",))
        if len(key_fields) > 1:
            return None
        found = self.itop.find(class_name, {key_fields[0]: value})
        if found is not None:
            self.ids[ref] = found
        return found

    def changed_fields(self, spec: Spec, object_id: str) -> list[str]:
        if not spec.fields:
            return []
        current = self.itop.read(spec.class_name, object_id, list(spec.fields))
        wanted = resolve(spec.fields, self.ids)
        return [name for name in spec.fields if not same(current.get(name), wanted[name])]

    def plan(self, specs: Sequence[Spec], *, update: bool = False) -> tuple[list[Action], list[str]]:
        """create / update / unchanged / exists per object, and every broken reference (then nothing is written)."""
        actions: list[Action] = []
        errors: list[str] = []
        defined: set[str] = set()  # declared earlier in the file (they may not exist in iTop yet)
        for spec in specs:
            for ref in refs_in(spec.fields):
                if ref in defined or ref in self.ids or self.lookup(ref) is not None:
                    continue
                match = _REF.match(ref)
                identity = DEFAULT_KEYS.get(match.group(1) if match else "", ("name",))
                hint = f" ({' + '.join(identity)} identify it: define it in the file)" if len(identity) > 1 else ""
                errors.append(f"{spec.label} points to {ref}, which is not in iTop nor earlier in the file{hint}")
            existing = self.itop.find(spec.class_name, spec.key)
            if existing is None:
                actions.append(Action("create", spec))
            else:
                self.ids[spec.label] = existing
                if update:
                    changed = self.changed_fields(spec, existing)
                    actions.append(Action("update" if changed else "unchanged", spec, existing, changed))
                else:
                    actions.append(Action("exists", spec, existing))
            defined.add(spec.label)
        return actions, errors

    def apply(self, actions: Sequence[Action]) -> None:
        self.done.clear()
        for action in actions:
            spec = action.spec
            if action.kind == "create":
                fields = resolve(spec.fields, self.ids)
                self.ids[spec.label] = self.itop.create(spec.class_name, {**spec.key, **fields})
            elif action.kind == "update" and action.object_id:
                # diffed again now that the objects created before it have ids
                changed = self.changed_fields(spec, action.object_id)
                fields = resolve(spec.fields, self.ids)
                if changed:
                    self.itop.update(spec.class_name, action.object_id, {name: fields[name] for name in changed})
            self.done.append(action)


def _report(actions: Sequence[Action], *, applied: bool) -> None:
    for action in actions:
        detail = f": {', '.join(action.changed)}" if action.changed else ""
        name = " / ".join(action.spec.key.values())
        sys.stdout.write(f"{_ACTION_LABELS[action.kind]} {action.spec.class_name} '{name}'{detail}\n")
    counts = {kind: sum(1 for a in actions if a.kind == kind) for kind in _ACTION_LABELS}
    verb = ("created", "updated") if applied else ("to create", "to update")
    sys.stdout.write(
        f"summary: {counts['create']} {verb[0]}, {counts['update']} {verb[1]}, {counts['unchanged']} unchanged, "
        f"{counts['exists']} already in iTop (not compared; --update compares them)\n"
    )


def _report_env(loader: Loader, env: Mapping[str, str]) -> None:
    if not env:
        return
    sys.stdout.write("for the Hermes env file (README, Guía de operación §9):\n")
    for name, ref in env.items():
        found = loader.lookup(ref)
        sys.stdout.write(f"  {name}={found}\n" if found else f"  {name}=  # {ref} is not in iTop yet\n")


def map_cpe(inventory: Inventory, api: HermesApi) -> int:
    """PUT /api/mappings/{product} for every product of the file still waiting for a CPE in Hermes."""
    pending = api.pending_products()
    mapped = 0
    for product, cpe in sorted(inventory.cpe.items()):
        if cpe is None:
            sys.stdout.write(f"- no CPE    {product} (on purpose: it stays in the pending screen)\n")
        elif product in pending:
            api.set_cpe(pending[product], cpe)
            mapped += 1
            sys.stdout.write(f"+ mapped    {product} -> {cpe}\n")
        else:
            sys.stdout.write(f"? skipped   {product}: not waiting for a CPE (already mapped, or not synced yet)\n")
    for product in sorted(set(pending) - set(inventory.cpe)):
        sys.stdout.write(f"! pending   {product}: no CPE for it in the file\n")
    sys.stdout.write(
        f"summary: {mapped} mapped; a product appears in Hermes after an inventory sync (a scan does one)\n"
    )
    return 0


def _from_environment(url_name: str, token_name: str, default_url: str = "") -> tuple[str, str]:
    url, token = os.environ.get(url_name, default_url), os.environ.get(token_name, "")
    if not url or not token:
        raise ValueError(f"{url_name} and {token_name} must be set")
    return url, token


def run(argv: Sequence[str] | None = None, itop: ItopRest | None = None, api: HermesApi | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness.itop_load", description=(__doc__ or "").split("\n")[0])
    parser.add_argument("file", type=Path)
    parser.add_argument("--apply", action="store_true", help="write to iTop (without it nothing is written)")
    parser.add_argument("--update", action="store_true", help="also update the fields of existing objects that differ")
    parser.add_argument("--map-cpe", action="store_true", help="only set the file's CPEs through the Hermes API")
    args = parser.parse_args(argv)
    try:
        inventory = parse_inventory(args.file)
    except (OSError, ValueError, TypeError) as error:
        sys.stderr.write(f"invalid file: {error}\n")
        return 2
    try:
        if args.map_cpe:
            api = api or HermesApi(*_from_environment("HERMES_API_URL", "HERMES_API_TOKEN", "http://127.0.0.1:8000"))
            return map_cpe(inventory, api)
        itop = itop or ItopRest(*_from_environment("ITOP_URL", "ITOP_TOKEN"))
    except ValueError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    except LoaderError as error:
        sys.stderr.write(f"failed: {error}\n")
        return 1
    return _load(Loader(itop), inventory, apply=args.apply, update=args.update)


def _load(loader: Loader, inventory: Inventory, *, apply: bool, update: bool) -> int:
    try:
        actions, errors = loader.plan(inventory.specs, update=update)
        if errors:
            _report(actions, applied=False)
            sys.stderr.write("nothing was written, fix these references:\n")
            sys.stderr.writelines(f"  - {error}\n" for error in errors)
            return 1
        if apply:
            loader.apply(actions)
        _report(actions, applied=apply)
        if not apply:
            sys.stdout.write("dry run: nothing was written; repeat with --apply\n")
        _report_env(loader, inventory.env)
    except LoaderError as error:
        if apply and loader.done:
            sys.stdout.write("written before iTop failed:\n")
            _report(loader.done, applied=True)
        sys.stderr.write(f"iTop failed: {error}\n(what was written stays; running the file again resumes)\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
