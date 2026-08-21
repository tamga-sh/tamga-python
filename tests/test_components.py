"""Tests for component creation and listing."""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import UUID

import httpx
import pytest

from tamga.client import TamgaClient
from tamga.errors import FingerprintTakenError

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000060")
COMPONENT_ID = UUID("018f2f3a-0000-7000-8000-000000000061")


def _component_data(component_id: UUID = COMPONENT_ID) -> dict:
    return {
        "id": str(component_id),
        "type": "components",
        "attributes": {
            "fingerprint": "cpu-fp-1",
            "name": "CPU",
            "machine_id": str(MACHINE_ID),
        },
    }


def test_create_component(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"{ACCOUNT_PATH}/components"
        body = json.loads(request.content)
        assert body["data"]["attributes"]["fingerprint"] == "cpu-fp-1"
        assert body["data"]["attributes"]["name"] == "CPU"
        assert body["data"]["attributes"]["machine_id"] == str(MACHINE_ID)
        return httpx.Response(201, json={"data": _component_data()})

    client = make_client(handler)
    component = client.components.create(MACHINE_ID, "cpu-fp-1", "CPU")
    assert component.id == COMPONENT_ID
    assert component.machine_id == MACHINE_ID


def test_create_component_duplicate_fingerprint_conflict(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                "errors": [
                    {
                        "id": "e1",
                        "status": "409",
                        "code": "FINGERPRINT_TAKEN",
                        "title": "Conflict",
                        "detail": "duplicate fingerprint",
                        "source": None,
                    }
                ]
            },
        )

    client = make_client(handler)
    with pytest.raises(FingerprintTakenError):
        client.components.create(MACHINE_ID, "cpu-fp-1", "CPU")


def test_list_components_sends_the_server_max_page_size_by_default(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # With no `limit` the server applies its own default of 25 rows and exposes
    # no total or cursor metadata, so a truncated listing was indistinguishable
    # from a complete one. Sending the max explicitly makes a full page
    # detectable and yields a usable cursor.
    seen: dict = {}
    full_page = [
        _component_data(UUID(int=0x018F2F3A_0000_7000_8000_000000000300 + i)) for i in range(100)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        seen["limit"] = request.url.params.get("limit")
        return httpx.Response(200, json={"data": full_page})

    client = make_client(handler)
    page = client.components.list(MACHINE_ID)

    assert seen["limit"] == "100"
    assert page.next_after == str(full_page[-1]["id"])


def test_list_components_pagination(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    first_id = UUID("018f2f3a-0000-7000-8000-000000000062")
    second_id = UUID("018f2f3a-0000-7000-8000-000000000063")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{ACCOUNT_PATH}/machines/{MACHINE_ID}/components"
        after = request.url.params.get("page[after]")
        if after is None:
            return httpx.Response(200, json={"data": [_component_data(first_id)]})
        assert after == str(first_id)
        return httpx.Response(200, json={"data": [_component_data(second_id)]})

    client = make_client(handler)
    page1 = client.components.list(MACHINE_ID, limit=1)
    assert [c.id for c in page1.items] == [first_id]
    assert page1.next_after == str(first_id)

    page2 = client.components.list(MACHINE_ID, limit=1, after=page1.next_after)
    assert [c.id for c in page2.items] == [second_id]
