"""Tests for entitlements list/get and LicenseResource.has_entitlement caching (Section J)."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import httpx

from tamga.client import TamgaClient

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000080")
ENTITLEMENT_ID = UUID("018f2f3a-0000-7000-8000-000000000081")


def _entitlement_data(entitlement_id: UUID, code: str, name: str) -> dict:
    return {
        "id": str(entitlement_id),
        "type": "entitlements",
        "attributes": {
            "code": code,
            "name": name,
            "metadata": {},
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-01T00:00:00Z",
        },
    }


def test_list_entitlements_pagination(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    first_id = UUID("018f2f3a-0000-7000-8000-000000000082")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{ACCOUNT_PATH}/licenses/{LICENSE_ID}/entitlements"
        return httpx.Response(200, json={"data": [_entitlement_data(first_id, "PRO", "Pro tier")]})

    client = make_client(handler)
    page = client.entitlements.list(LICENSE_ID)
    assert len(page.items) == 1
    assert page.items[0].code == "PRO"
    assert page.items[0].name == "Pro tier"


def test_get_single_entitlement(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == (
            f"{ACCOUNT_PATH}/licenses/{LICENSE_ID}/entitlements/{ENTITLEMENT_ID}"
        )
        return httpx.Response(
            200, json={"data": _entitlement_data(ENTITLEMENT_ID, "PRO", "Pro tier")}
        )

    client = make_client(handler)
    entitlement = client.entitlements.get(LICENSE_ID, ENTITLEMENT_ID)
    assert entitlement.id == ENTITLEMENT_ID
    assert entitlement.code == "PRO"


def test_has_entitlement_matches_on_code_not_name(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def entitlements_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": [_entitlement_data(ENTITLEMENT_ID, "PRO", "Pro tier")]}
        )

    def validate_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": str(LICENSE_ID),
                    "type": "licenses",
                    "attributes": {},
                },
                "meta": {
                    "ts": "2024-01-01T00:00:00Z",
                    "valid": True,
                    "detail": "ok",
                    "code": "VALID",
                },
            },
        )

    def handler(request: httpx.Request) -> httpx.Response:
        if "entitlements" in request.url.path:
            return entitlements_handler(request)
        return validate_handler(request)

    client = make_client(handler)
    result = client.licenses.validate_by_key("KEY")
    license_resource = result.license
    assert license_resource is not None

    assert license_resource.has_entitlement("PRO") is True
    assert license_resource.has_entitlement("Pro tier") is False  # never match on name


def test_entitlement_cache_populated_once_and_refresh_forces_refetch(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    call_count = {"n": 0}

    def entitlements_handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(
            200, json={"data": [_entitlement_data(ENTITLEMENT_ID, "PRO", "Pro tier")]}
        )

    def validate_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {"id": str(LICENSE_ID), "type": "licenses", "attributes": {}},
                "meta": {
                    "ts": "2024-01-01T00:00:00Z",
                    "valid": True,
                    "detail": "ok",
                    "code": "VALID",
                },
            },
        )

    def handler(request: httpx.Request) -> httpx.Response:
        if "entitlements" in request.url.path:
            return entitlements_handler(request)
        return validate_handler(request)

    client = make_client(handler)
    result = client.licenses.validate_by_key("KEY")
    license_resource = result.license
    assert license_resource is not None

    license_resource.has_entitlement("PRO")
    license_resource.has_entitlement("PRO")
    assert call_count["n"] == 1  # cached after first fetch

    license_resource.refresh_entitlements()
    assert call_count["n"] == 2  # explicit refresh forces a re-fetch
