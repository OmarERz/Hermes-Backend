"""F18.4: a ticket of the list carries the numeric iTop id its filters take, as an optional (compatible) field."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.routes.models import Ticket, TicketUpdateFilters, filter_ticket_id

LISTED = {
    "itop_id": "R-000777",
    "url": "https://itop.example.test/pages/UI.php?operation=details&class=UserRequest&id=777",
    "cve": "CVE-2026-10001",
    "custodian": "Infraestructura Linux",
    "urgency": 1,
    "status": "Abierto",
    "fixed_cis": 1,
    "total_cis": 2,
}


def test_the_numeric_id_is_optional_so_older_payloads_still_validate() -> None:
    assert Ticket.model_validate(LISTED).ticket_itop_id is None
    assert Ticket.model_validate({**LISTED, "ticket_itop_id": "777"}).ticket_itop_id == "777"


def test_the_listed_numeric_id_is_what_the_filter_accepts_and_the_reference_is_not() -> None:
    listed = Ticket.model_validate({**LISTED, "ticket_itop_id": "777"})
    assert TicketUpdateFilters.model_validate({"ticket_itop_id": listed.ticket_itop_id}).ticket_itop_id == "777"
    with pytest.raises(ValidationError):
        TicketUpdateFilters.model_validate({"ticket_itop_id": listed.itop_id})


def test_only_an_id_the_filters_take_is_listed_for_them() -> None:
    assert filter_ticket_id("777") == "777"
    assert filter_ticket_id("123456789012") == "123456789012"
    for not_numeric in (None, "", "DEMO-1", "R-000777", "1234567890123", "77 ", "7\n"):
        assert filter_ticket_id(not_numeric) is None, not_numeric
