"""Tests for entitlements list/get and LicenseResource.has_entitlement caching."""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import httpx

from tamga.client import TamgaClient

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000080")
ENTITLEMENT_ID = UUID("018f2f3a-0000-7000-8000-000000000081")


def _entitlement_data(
    entitlement_id: UUID, code: str, name: str, inherited: bool | None = None
) -> dict:
    attributes: dict = {
        "code": code,
        "name": name,
        "metadata": {},
        "created": "2024-01-01T00:00:00Z",
        "updated": "2024-01-01T00:00:00Z",
    }
    if inherited is not None:
        attributes["inherited"] = inherited
    return {
        "id": str(entitlement_id),
        "type": "entitlements",
        "attributes": attributes,
    }


def test_list_entitlements_sends_an_explicit_page_size_and_no_cursor(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    first_id = UUID("018f2f3a-0000-7000-8000-000000000082")
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{ACCOUNT_PATH}/licenses/{LICENSE_ID}/entitlements"
        seen["limit"] = request.url.params.get("limit")
        seen["after"] = request.url.params.get("page[after]")
        return httpx.Response(200, json={"data": [_entitlement_data(first_id, "PRO", "Pro tier")]})

    client = make_client(handler)
    page = client.entitlements.list(LICENSE_ID)
    assert len(page.items) == 1
    assert page.items[0].code == "PRO"
    assert page.items[0].name == "Pro tier"
    # Without an explicit limit the server silently applies its own default of
    # 25 rows, which is indistinguishable from a complete listing.
    assert seen["limit"] == "100"
    # `page[after]` is inert on this route, so the SDK does not send it.
    assert seen["after"] is None
    assert page.next_after is None


def test_list_entitlements_never_advertises_a_next_cursor(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # A full page is not evidence of a next page here: the server ignores
    # `page[after]` on this route, so "page 2" would be page 1 again.
    full_page = [
        _entitlement_data(
            UUID(int=0x018F2F3A_0000_7000_8000_000000000100 + i), f"FEAT_{i}", f"Feature {i}"
        )
        for i in range(100)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": full_page})

    client = make_client(handler)
    page = client.entitlements.list(LICENSE_ID, limit=100)
    assert len(page.items) == 100
    assert page.next_after is None


def test_list_all_terminates_when_the_server_repeats_the_same_page(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # The regression this exists for: `page[after]` is accepted and ignored on
    # the entitlements route, so the old cursor loop re-fetched an identical
    # full page forever — an unbounded loop that hung the process and grew the
    # accumulator until it ran out of memory. Serve the same full page to every
    # request; `list_all` must still return.
    full_page = [
        _entitlement_data(
            UUID(int=0x018F2F3A_0000_7000_8000_000000000200 + i), f"FEAT_{i}", f"Feature {i}"
        )
        for i in range(100)
    ]
    request_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        request_count["n"] += 1
        assert request_count["n"] <= 2, "list_all must not loop on this endpoint"
        return httpx.Response(200, json={"data": full_page})

    client = make_client(handler)
    items = client.entitlements.list_all(LICENSE_ID)

    assert request_count["n"] == 1
    assert len(items) == 100


def test_inherited_flag_is_surfaced(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # An inherited entitlement comes from the policy: it cannot be detached and
    # the item route 404s for it, so dropping the flag left callers unable to
    # tell the two kinds apart.
    direct_id = UUID("018f2f3a-0000-7000-8000-000000000090")
    inherited_id = UUID("018f2f3a-0000-7000-8000-000000000091")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    _entitlement_data(direct_id, "PRO", "Pro tier", inherited=False),
                    _entitlement_data(inherited_id, "BASE", "Base tier", inherited=True),
                ]
            },
        )

    client = make_client(handler)
    page = client.entitlements.list(LICENSE_ID)
    assert [e.inherited for e in page.items] == [False, True]


def test_inherited_defaults_to_none_when_the_server_omits_it(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # Only the license-scoped listing carries the flag; absent means "unknown",
    # not "direct".
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": _entitlement_data(ENTITLEMENT_ID, "PRO", "Pro tier")}
        )

    client = make_client(handler)
    entitlement = client.entitlements.get(LICENSE_ID, ENTITLEMENT_ID)
    assert entitlement.inherited is None


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
