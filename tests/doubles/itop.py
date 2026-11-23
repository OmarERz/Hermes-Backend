"""In-memory double of iTop's REST API (`POST /webservices/rest.php?version=1.3`) over an httpx transport.

Adapted from the prototype's fake (docs/prototipo/analisis.md §3): English, typed, httpx-based and with the
ticket state machine corrected (`ev_assign` is valid from new, escalated_tto, approved and pending, §5.4).

It implements the subset of OQL the backend emits:
    SELECT Class [WHERE cond AND cond ...]     cond: field = 'x' | field != 'x' | field IN (...) | field NOT IN (...)
and the operations core/get, core/create, core/update, core/apply_stimulus and list_operations. Classes inherit
like in iTop: selecting FunctionalCI returns servers, virtual machines, software instances and solutions.

It encodes MY reading of iTop's behaviour: passing tests against it proves the client logic, not that a real
iTop behaves the same (the Docker test instance of F0.7 covers that).

Switches: `down` makes every request fail like an unreachable host; `before_write` is a hook called before each
write operation to simulate a race (another actor changing the object in between).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx

FIXTURES: Final = Path(__file__).resolve().parents[1] / "fixtures" / "itop"
DEFAULT_FIXTURE: Final = FIXTURES / "inventory.json"

Fields = dict[str, Any]

ITOP_SERVER_URL: Final = "http://itop.test"
ENDPOINT: Final = "/webservices/rest.php"

# Parent class -> direct subclasses (the slice of iTop's hierarchy the backend reads).
CHILDREN: Final[dict[str, tuple[str, ...]]] = {
    "FunctionalCI": ("PhysicalDevice", "VirtualDevice", "SoftwareInstance", "ApplicationSolution"),
    "PhysicalDevice": ("Server",),
    "VirtualDevice": ("VirtualHost", "VirtualMachine"),
    "VirtualHost": ("Hypervisor", "Farm"),
    "SoftwareInstance": ("DBServer", "WebServer", "Middleware", "OtherSoftware"),
    "Ticket": ("UserRequest",),
}

ENUMS: Final[dict[str, set[str]]] = {
    "status": {"production", "implementation", "stock", "obsolete", "active", "inactive"},
    "business_criticity": {"high", "medium", "low"},
    "internet_exposed": {"yes", "no"},
    "confidentiality": {"public", "classified", "highly_classified", "unclassified"},
    "personal_data": {"yes", "no", "unknown"},
}
REQUIRED: Final[dict[str, tuple[str, ...]]] = {
    "Server": ("name", "org_id"),
    "VirtualMachine": ("name", "org_id"),
    "ApplicationSolution": ("name", "org_id"),
    "SoftwareInstance": ("name", "org_id", "system_id"),  # system_id is mandatory on instances (§5.6)
    "UserRequest": ("org_id", "caller_id", "title", "description"),
}

# ev_assign is accepted only from these states (§5.4); the others map stimulus -> (allowed from, target).
ASSIGN_FROM: Final = frozenset({"new", "escalated_tto", "approved", "pending"})
TRANSITIONS: Final[dict[str, tuple[frozenset[str], str]]] = {
    "ev_assign": (ASSIGN_FROM, "assigned"),
    "ev_reassign": (frozenset({"assigned"}), "assigned"),
    "ev_pending": (frozenset({"assigned"}), "pending"),
    "ev_resolve": (frozenset({"assigned"}), "resolved"),
    "ev_reopen": (frozenset({"resolved"}), "assigned"),
    "ev_close": (frozenset({"resolved"}), "closed"),
}
STIMULUS_REQUIRES: Final[dict[str, tuple[str, ...]]] = {
    "ev_assign": ("team_id", "agent_id"),
    "ev_reassign": ("team_id", "agent_id"),
    "ev_resolve": ("service_id", "resolution_code", "solution"),
}

CODE_OK: Final = 0
CODE_UNAUTHORIZED: Final = 1
CODE_UNKNOWN_OPERATION: Final = 3
CODE_ERROR: Final = 100


@dataclass(frozen=True)
class RecordedCall:
    """One REST operation as received (credentials are never recorded)."""

    operation: str
    payload: Fields
    auth: str  # "token" or "basic"


@dataclass
class ItopDouble:
    """iTop REST double. Use `double.client()` (or `double.transport`) wherever the code takes an httpx client."""

    token: str | None = "test-token"  # noqa: S105  (a fake credential for the double)
    user: str = "svc"
    password: str = "pw"  # noqa: S105
    down: bool = False
    before_write: Callable[[Fields], None] | None = None
    data: dict[str, dict[str, Fields]] = field(default_factory=dict)
    calls: list[RecordedCall] = field(default_factory=list)
    # iTop refuses a write without `comment` (F12.3); opt-in so the double's own older scenarios keep working.
    require_comment: bool = False
    write_comments: list[str] = field(default_factory=list)  # the `comment` of each write (iTop's userinfo)
    _next_id: int = 1000

    def __post_init__(self) -> None:
        self.transport = httpx.MockTransport(self._handle_request)

    # --- setup ------------------------------------------------------------------------------------------
    @classmethod
    def from_fixture(cls, path: Path = DEFAULT_FIXTURE, **kwargs: Any) -> ItopDouble:
        double = cls(**kwargs)
        loaded: dict[str, list[Fields]] = json.loads(path.read_text(encoding="utf-8"))
        for class_name, rows in loaded.items():
            for row in rows:
                double.add(class_name, **row)
        return double

    def add(self, class_name: str, id: int, **fields: Any) -> None:  # noqa: A002  (iTop's own field name)
        self.data.setdefault(class_name, {})[str(id)] = {"id": str(id), **fields}
        self._next_id = max(self._next_id, id)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=self.transport, base_url=ITOP_SERVER_URL, timeout=httpx.Timeout(5.0))

    # --- recording helpers --------------------------------------------------------------------------------
    @property
    def operations(self) -> list[str]:
        return [call.operation for call in self.calls]

    @property
    def writes(self) -> list[RecordedCall]:
        return [c for c in self.calls if c.operation in {"core/create", "core/update", "core/apply_stimulus"}]

    # --- HTTP shape ---------------------------------------------------------------------------------------
    def _handle_request(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("itop double is down", request=request)
        if request.method != "POST" or request.url.path != ENDPOINT:
            return httpx.Response(404, text="not found")
        form = dict(httpx.QueryParams(request.content.decode()))
        auth = self._authenticate(request, form)
        if auth is None:
            return httpx.Response(200, json={"code": CODE_UNAUTHORIZED, "message": "Error: Invalid login"})
        op: Fields = json.loads(form["json_data"])
        self.calls.append(RecordedCall(str(op.get("operation")), op, auth))
        return httpx.Response(200, json=self.handle(op))

    def _authenticate(self, request: httpx.Request, form: dict[str, str]) -> str | None:
        if self.token is not None and request.headers.get("Auth-Token") == self.token:
            return "token"
        if form.get("auth_user") == self.user and form.get("auth_pwd") == self.password:
            return "basic"
        return None

    # --- operations ---------------------------------------------------------------------------------------
    def handle(self, op: Fields) -> Fields:
        name = op["operation"]
        if name == "list_operations":
            verbs = ["core/get", "core/create", "core/update", "core/apply_stimulus", "list_operations"]
            return {"code": CODE_OK, "message": "", "operations": [{"verb": v} for v in verbs]}
        if name == "core/get":
            return self._get(op)
        refusal = self._write_refusal(name, op)
        if refusal is not None:
            return refusal
        self.write_comments.append(str(op.get("comment", "")))
        if self.before_write:
            self.before_write(op)
        if name == "core/create":
            return self._create(op)
        if name == "core/update":
            return self._update(op)
        return self._stimulus(op)

    def _write_refusal(self, name: str, op: Fields) -> Fields | None:
        if name not in {"core/create", "core/update", "core/apply_stimulus"}:
            return {"code": CODE_UNKNOWN_OPERATION, "message": f"Error: unknown operation '{name}'"}
        if self.require_comment and not op.get("comment"):
            # Like iTop 3.2.2 (checked live, F12.3): every write needs `comment`, which becomes the change's userinfo.
            return {"code": CODE_ERROR, "message": "Error: Missing parameter 'comment'"}
        return None

    def _classes_of(self, class_name: str) -> list[str]:
        result = [class_name]
        for child in CHILDREN.get(class_name, ()):
            result.extend(self._classes_of(child))
        return result

    def _rows(self, class_name: str, key: Any) -> list[tuple[str, Fields]] | None:
        pairs = [(c, row) for c in self._classes_of(class_name) for row in self.data.get(c, {}).values()]
        if isinstance(key, int) or (isinstance(key, str) and key.isdigit()):
            return [(c, r) for c, r in pairs if r["id"] == str(key)]
        if isinstance(key, dict):
            return [(c, r) for c, r in pairs if all(str(r.get(k, "")) == str(v) for k, v in key.items())]
        match = re.match(r"^SELECT\s+(\w+)(?:\s+WHERE\s+(.*))?$", str(key).strip(), re.S)
        if not match or match.group(1) != class_name:
            return None
        for cond in split_and(match.group(2) or ""):
            parsed = re.match(r"^(\w+)\s+(NOT IN|IN|!=|=)\s+(.*)$", cond, re.S)
            if not parsed:
                return None
            attr, comparator, rest = parsed.groups()
            values = parse_literals(rest)
            if not values:
                return None
            if comparator == "=":
                pairs = [(c, r) for c, r in pairs if str(r.get(attr, "")) == values[0]]
            elif comparator == "!=":
                pairs = [(c, r) for c, r in pairs if str(r.get(attr, "")) != values[0]]
            elif comparator == "IN":
                pairs = [(c, r) for c, r in pairs if str(r.get(attr, "")) in values]
            else:
                pairs = [(c, r) for c, r in pairs if str(r.get(attr, "")) not in values]
        return pairs

    @staticmethod
    def _object(class_name: str, row: Fields, wanted: set[str] | None = None) -> Fields:
        fields = {k: v for k, v in row.items() if wanted is None or k in wanted}
        return {"code": CODE_OK, "message": "", "class": class_name, "key": row["id"], "fields": fields}

    def _get(self, op: Fields) -> Fields:
        found = self._rows(op["class"], op["key"])
        if found is None:
            return {"code": CODE_ERROR, "message": f"Error: OQL not supported by the double: {op['key']}"}
        output = op.get("output_fields")
        wanted = None if output in (None, "*") else set(str(output).split(","))
        objects = {f"{c}::{r['id']}": self._object(c, r, wanted) for c, r in found}
        return {"code": CODE_OK, "message": f"Found: {len(objects)}", "objects": objects or None}

    def _validate(self, class_name: str, fields: Fields, *, creating: bool) -> str | None:
        if creating:
            missing = [f for f in self._required(class_name) if not fields.get(f)]
            if missing:
                return f"Error: Required fields missing: {', '.join(missing)}"
        if class_name not in self._classes_of("FunctionalCI"):
            return None  # the enums below are CI attributes; ticket states have their own machine
        for attr, allowed in ENUMS.items():
            value = fields.get(attr)
            if value not in (None, "") and value not in allowed:
                return f"Error: unexpected value for attribute '{attr}': {value}"
        return None

    def _required(self, class_name: str) -> tuple[str, ...]:
        """Required fields of the class, including those declared on its ancestors."""
        required: list[str] = []
        for declared_on, fields in REQUIRED.items():
            if class_name in self._classes_of(declared_on):
                required.extend(fields)
        return tuple(dict.fromkeys(required))

    def _create(self, op: Fields) -> Fields:
        class_name: str = op["class"]
        fields = dict(op["fields"])
        links = fields.pop("functionalcis_list", []) if class_name == "UserRequest" else []
        error = self._validate(class_name, fields, creating=True)
        if error:
            return {"code": CODE_ERROR, "message": error}
        self._next_id += 1
        object_id = self._next_id
        if class_name == "UserRequest":
            fields.setdefault("ref", f"R-{object_id:06d}")
            fields.setdefault("status", "new")
            fields.setdefault("agent_id", "")
            fields.setdefault("team_id", "")
        self.add(class_name, object_id, **fields)
        self._set_links(str(object_id), links)
        row = self.data[class_name][str(object_id)]
        return {
            "code": CODE_OK,
            "message": "",
            "objects": {f"{class_name}::{object_id}": self._object(class_name, row)},
        }

    def _set_links(self, ticket_id: str, links: list[Fields]) -> None:
        """Replace the ticket's whole CI list (a linkedset write replaces, it never merges; §5.7)."""
        table = self.data.setdefault("lnkFunctionalCIToTicket", {})
        for link_id in [i for i, r in table.items() if r["ticket_id"] == ticket_id]:
            del table[link_id]
        for link in links:
            self._next_id += 1
            self.add(
                "lnkFunctionalCIToTicket",
                self._next_id,
                ticket_id=ticket_id,
                functionalci_id=str(link["functionalci_id"]),
                impact_code=link.get("impact_code", "manual"),
            )

    def _one(self, op: Fields) -> tuple[str, Fields] | Fields:
        found = self._rows(op["class"], op["key"])
        if not found:
            return {"code": CODE_ERROR, "message": "Error: No item found"}
        return found[0]

    def _update(self, op: Fields) -> Fields:
        target = self._one(op)
        if isinstance(target, dict):
            return target
        class_name, row = target
        fields = dict(op["fields"])
        links = fields.pop("functionalcis_list", None) if class_name == "UserRequest" else None
        error = self._validate(class_name, fields, creating=False)
        if error:
            return {"code": CODE_ERROR, "message": error}
        row.update(fields)
        if links is not None:
            self._set_links(row["id"], links)
        return {
            "code": CODE_OK,
            "message": "",
            "objects": {f"{class_name}::{row['id']}": self._object(class_name, row)},
        }

    def _stimulus(self, op: Fields) -> Fields:
        target = self._one(op)
        if isinstance(target, dict):
            return target
        class_name, row = target
        stimulus: str = op["stimulus"]
        if class_name != "UserRequest" or stimulus not in TRANSITIONS:
            return {"code": CODE_ERROR, "message": f"Error: Invalid stimulus: '{stimulus}' on {class_name}"}
        allowed_from, target_state = TRANSITIONS[stimulus]
        if row.get("status") not in allowed_from:
            return {
                "code": CODE_ERROR,
                "message": f"Error: Invalid stimulus: '{stimulus}' on the object in state '{row.get('status')}'",
            }
        fields = dict(op.get("fields") or {})
        merged = {**row, **fields}
        missing = [f for f in STIMULUS_REQUIRES.get(stimulus, ()) if not merged.get(f)]
        if missing:
            return {"code": CODE_ERROR, "message": f"Error: Required fields missing: {', '.join(missing)}"}
        if "agent_id" in STIMULUS_REQUIRES.get(stimulus, ()) and not self._is_member(merged):
            return {"code": CODE_ERROR, "message": "Error: the agent does not belong to the team"}
        row.update(fields)
        row["status"] = target_state
        return {
            "code": CODE_OK,
            "message": "",
            "objects": {f"{class_name}::{row['id']}": self._object(class_name, row)},
        }

    def _is_member(self, ticket: Fields) -> bool:
        links = self.data.get("lnkPersonToTeam", {}).values()
        return any(
            link["person_id"] == str(ticket["agent_id"]) and link["team_id"] == str(ticket["team_id"]) for link in links
        )


def parse_literals(text: str) -> list[str]:
    """Values of an OQL right-hand side: quoted strings (with backslash escapes) or bare numbers/words."""
    values: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "'":
            j, out = i + 1, []
            while j < len(text) and text[j] != "'":
                if text[j] == "\\":
                    j += 1
                out.append(text[j])
                j += 1
            values.append("".join(out))
            i = j + 1
        elif ch.isalnum():
            j = i
            while j < len(text) and (text[j].isalnum() or text[j] in "_.-"):
                j += 1
            values.append(text[i:j])
            i = j
        else:
            i += 1
    return values


def split_and(where: str) -> list[str]:
    """Split a WHERE clause on top-level ANDs (outside quotes and parentheses)."""
    parts: list[str] = []
    depth, quoted, current, i = 0, False, "", 0
    while i < len(where):
        ch = where[i]
        if ch == "\\" and quoted:
            current += where[i : i + 2]
            i += 2
            continue
        if ch == "'":
            quoted = not quoted
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")":
            depth -= 1
        if not quoted and depth == 0 and where[i : i + 5].upper() == " AND ":
            parts.append(current)
            current = ""
            i += 5
            continue
        current += ch
        i += 1
    parts.append(current)
    return [p.strip() for p in parts if p.strip()]
