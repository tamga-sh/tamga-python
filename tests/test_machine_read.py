"""Tests for the machine read/update routes and idempotent re-activation."""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import UUID

import httpx
import pytest

from tamga.client import MAX_PAGE_SIZE, TamgaClient
from tamga.errors import FingerprintTakenError, MachineOverLimitError, NotFoundError
from tamga.models.machine import HeartbeatStatus
from tamga.models.validation import ValidationCode

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000050")
MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000051")
OTHER_MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000052")

FINGERPRINT = "fp-abc"


def _machine_data(
    machine_id: UUID = MACHINE_ID,
    fingerprint: str = FINGERPRINT,
    heartbeat_status: str = "NOT_STARTED",
    **extra: object,
) -> dict:
    attributes: dict = {"fingerprint": fingerprint, "heartbeat_status": heartbeat_status}
    attributes.update(extra)
    return {"id": str(machine_id), "type": "machines", "attributes": attributes}


def _page_meta(number: int, total: int, size: int = MAX_PAGE_SIZE) -> dict:
    total_pages = 0 if total <= 0 else (total + size - 1) // size
    return {"page": {"number": number, "size": size, "total": total, "totalPages": total_pages}}


# ── GET /machines/{id} ────────────────────────────────────────────────────────


def test_get_machine_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"{ACCOUNT_PATH}/machines/{MACHINE_ID}"
        return httpx.Response(200, json={"data": _machine_data()})

    client = make_client(handler)
    assert client.machines.get(MACHINE_ID).id == MACHINE_ID


def test_get_machine_is_the_read_path_that_can_report_dead(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """A read never rewrote `last_heartbeat_at`, so `DEAD` is reachable here."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": _machine_data(heartbeat_status="DEAD")})

    client = make_client(handler)
    assert client.machines.get(MACHINE_ID).heartbeat_status is HeartbeatStatus.DEAD


def test_get_machine_missing_raises_not_found(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errors": [{"code": "NOT_FOUND", "detail": "gone"}]})

    client = make_client(handler)
    with pytest.raises(NotFoundError):
        client.machines.get(MACHINE_ID)


# ── GET /machines (offset pagination) ─────────────────────────────────────────


def test_list_machines_sends_offset_pagination_not_a_keyset_cursor(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{ACCOUNT_PATH}/machines"
        assert request.url.params["page[number]"] == "2"
        assert request.url.params["page[size]"] == "100"
        assert "page[after]" not in request.url.params
        assert "limit" not in request.url.params
        return httpx.Response(200, json={"data": [_machine_data()], "meta": _page_meta(2, 150)})

    client = make_client(handler)
    page = client.machines.list(page_number=2)

    assert [m.id for m in page.items] == [MACHINE_ID]
    assert page.page_number == 2
    assert page.page_size == MAX_PAGE_SIZE
    assert page.total == 150
    assert page.total_pages == 2
    assert page.has_next_page is False


def test_list_machines_reports_a_next_page_from_server_metadata(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Unlike the keyset routes, the page count is told to us, not inferred."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [_machine_data()], "meta": _page_meta(1, 150)})

    client = make_client(handler)
    page = client.machines.list()
    assert page.has_next_page is True
    # One item on the page, yet more pages exist — the `len(items) == limit`
    # heuristic the keyset routes rely on would have said otherwise.
    assert len(page.items) == 1


def test_list_machines_forwards_filters(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["filter[q]"] == FINGERPRINT
        assert request.url.params["filter[license]"] == str(LICENSE_ID)
        assert request.url.params["filter[platform]"] == "linux"
        return httpx.Response(200, json={"data": [], "meta": _page_meta(1, 0)})

    client = make_client(handler)
    page = client.machines.list(search=FINGERPRINT, license_id=LICENSE_ID, platform="linux")
    assert page.items == []
    assert page.total_pages == 0
    assert page.has_next_page is False


def test_list_machines_survives_a_response_with_no_page_metadata(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Missing metadata must stop a pagination loop, not spin it."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [_machine_data()]})

    client = make_client(handler)
    page = client.machines.list()
    assert len(page.items) == 1
    assert page.has_next_page is False


# ── PATCH /machines/{id} ──────────────────────────────────────────────────────


def test_update_machine_sends_only_the_supplied_attributes(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "PATCH"
        assert request.url.path == f"{ACCOUNT_PATH}/machines/{MACHINE_ID}"
        body = json.loads(request.content)
        assert body["data"]["type"] == "machines"
        assert body["data"]["attributes"] == {"name": "renamed", "cores": 8}
        return httpx.Response(200, json={"data": _machine_data(name="renamed", cores=8)})

    client = make_client(handler)
    machine = client.machines.update(MACHINE_ID, name="renamed", cores=8)
    assert machine.name == "renamed"
    assert machine.cores == 8


def test_update_machine_forwards_every_supported_field(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["data"]["attributes"] == {
            "name": "box",
            "ip": "10.0.0.7",
            "hostname": "box.local",
            "platform": "linux",
            "cores": 4,
            "memory": 16384,
            "disk": 512000,
            "metadata": {"tier": "prod"},
        }
        return httpx.Response(200, json={"data": _machine_data()})

    client = make_client(handler)
    client.machines.update(
        MACHINE_ID,
        name="box",
        ip="10.0.0.7",
        hostname="box.local",
        platform="linux",
        cores=4,
        # Megabytes, as everywhere else on this resource.
        memory=16384,
        disk=512000,
        metadata={"tier": "prod"},
    )


def test_update_machine_with_no_fields_sends_an_empty_attributes_object(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Every column is COALESCEd server-side, so an empty patch is a no-op, not a wipe."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["data"]["attributes"] == {}
        return httpx.Response(200, json={"data": _machine_data()})

    client = make_client(handler)
    assert client.machines.update(MACHINE_ID).id == MACHINE_ID


# ── find_by_fingerprint ───────────────────────────────────────────────────────


def test_find_by_fingerprint_matches_exactly_and_discards_substring_hits(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """`filter[q]` is a substring ILIKE over name/hostname/fingerprint, not an equality filter."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["filter[q]"] == FINGERPRINT
        return httpx.Response(
            200,
            json={
                "data": [
                    # Matched on `name`, not on an equal fingerprint.
                    _machine_data(OTHER_MACHINE_ID, fingerprint="fp-abc-2", name=FINGERPRINT),
                    _machine_data(MACHINE_ID, fingerprint=FINGERPRINT),
                ],
                "meta": _page_meta(1, 2),
            },
        )

    client = make_client(handler)
    found = client.machines.find_by_fingerprint(FINGERPRINT, license_id=LICENSE_ID)
    assert found is not None
    assert found.id == MACHINE_ID


def test_find_by_fingerprint_returns_none_when_no_exact_match_exists(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [_machine_data(OTHER_MACHINE_ID, fingerprint="fp-abcdef")],
                "meta": _page_meta(1, 1),
            },
        )

    client = make_client(handler)
    assert client.machines.find_by_fingerprint(FINGERPRINT, license_id=LICENSE_ID) is None


def test_find_by_fingerprint_always_scopes_the_search_to_one_license(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """A machine carries no license id, so this filter is the only thing that scopes it."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["filter[license]"] == str(LICENSE_ID)
        return httpx.Response(200, json={"data": [], "meta": _page_meta(1, 0)})

    client = make_client(handler)
    assert client.machines.find_by_fingerprint(FINGERPRINT, license_id=LICENSE_ID) is None


def test_find_by_fingerprint_requires_a_license(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """An unscoped search returns rows the caller cannot attribute, so it is unexpressible."""
    client = make_client(lambda request: httpx.Response(200, json={"data": []}))
    with pytest.raises(TypeError, match="license_id"):
        client.machines.find_by_fingerprint(FINGERPRINT)  # type: ignore[call-arg]


def test_find_by_fingerprint_walks_pages_until_the_server_says_it_is_done(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    requested_pages: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page_number = request.url.params["page[number]"]
        requested_pages.append(page_number)
        if page_number == "1":
            return httpx.Response(
                200,
                json={
                    "data": [_machine_data(OTHER_MACHINE_ID, fingerprint="fp-abc-other")],
                    "meta": _page_meta(1, 2, size=1),
                },
            )
        return httpx.Response(
            200,
            json={"data": [_machine_data()], "meta": _page_meta(2, 2, size=1)},
        )

    client = make_client(handler)
    found = client.machines.find_by_fingerprint(FINGERPRINT, license_id=LICENSE_ID)
    assert found is not None
    assert found.id == MACHINE_ID
    assert requested_pages == ["1", "2"]


def test_find_by_fingerprint_cannot_loop_forever_on_dishonest_page_metadata(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """A server that always claims another page must not hang the caller."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "data": [_machine_data(OTHER_MACHINE_ID, fingerprint="nope")],
                # totalPages is enormous and never reached.
                "meta": {"page": {"number": 1, "size": 1, "total": 10**9, "totalPages": 10**9}},
            },
        )

    client = make_client(handler)
    assert (
        client.machines.find_by_fingerprint(FINGERPRINT, license_id=LICENSE_ID, max_pages=3) is None
    )
    assert calls == 3


def test_find_by_fingerprint_rejects_a_blank_fingerprint(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The server ignores a blank search term, which would scan the whole account."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": [], "meta": _page_meta(1, 0)})

    client = make_client(handler)
    with pytest.raises(ValueError, match="non-empty"):
        client.machines.find_by_fingerprint("   ", license_id=LICENSE_ID)
    assert calls == 0


# ── activate_machine_idempotent ───────────────────────────────────────────────


def test_idempotent_activation_returns_the_new_machine_on_the_happy_path(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/machines"):
            return httpx.Response(201, json={"data": _machine_data()})
        if request.url.path.endswith("/actions/validate"):
            return httpx.Response(
                200,
                json={
                    "data": {"id": str(LICENSE_ID), "type": "licenses", "attributes": {}},
                    "meta": {
                        "ts": "2026-01-01T00:00:00Z",
                        "valid": True,
                        "detail": "ok",
                        "code": "VALID",
                    },
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler)
    assert client.machines.activate_machine_idempotent(LICENSE_ID, FINGERPRINT).id == MACHINE_ID


def test_idempotent_activation_recovers_the_existing_machine_after_a_conflict(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.path}")
        if request.method == "POST":
            return httpx.Response(
                409,
                json={"errors": [{"code": "FINGERPRINT_TAKEN", "detail": "already activated"}]},
            )
        assert request.url.params["filter[license]"] == str(LICENSE_ID)
        return httpx.Response(200, json={"data": [_machine_data()], "meta": _page_meta(1, 1)})

    client = make_client(handler)
    machine = client.machines.activate_machine_idempotent(LICENSE_ID, FINGERPRINT)

    assert machine.id == MACHINE_ID
    assert seen == [f"POST {ACCOUNT_PATH}/machines", f"GET {ACCOUNT_PATH}/machines"]


def test_idempotent_activation_never_deletes_the_machine_it_recovered(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The recovery path must not run the rollback: that row is not ours to delete."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method != "DELETE", "recovered a pre-existing machine, then deleted it"
        if request.method == "POST":
            return httpx.Response(
                409,
                json={"errors": [{"code": "FINGERPRINT_TAKEN", "detail": "taken"}]},
            )
        return httpx.Response(200, json={"data": [_machine_data()], "meta": _page_meta(1, 1)})

    client = make_client(handler)
    assert client.machines.activate_machine_idempotent(LICENSE_ID, FINGERPRINT).id == MACHINE_ID


def test_idempotent_activation_reraises_a_cross_license_conflict(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The conflicting machine is on another license, so it must not be handed back.

    All three uniqueness strategies include the caller's own license in their
    duplicate check, so an empty license-scoped lookup after a 409 means the
    conflict came from a *different* license under `UNIQUE_PER_POLICY` or
    `UNIQUE_PER_ACCOUNT`. Returning that machine would let this license
    heartbeat and check out a seat it never paid for, with `machines_count`
    staying at zero — the exact seat-sharing those wider scopes exist to
    prevent — and the caller could not detect it, since the resource carries no
    license id.
    """
    license_filters: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                409,
                json={"errors": [{"code": "FINGERPRINT_TAKEN", "detail": "taken"}]},
            )
        # The machine exists in the account — just not on this license, so a
        # server honouring `filter[license]` returns nothing.
        license_filters.append(request.url.params["filter[license]"])
        assert request.url.params["filter[q]"] == FINGERPRINT
        return httpx.Response(200, json={"data": [], "meta": _page_meta(1, 0)})

    client = make_client(handler)
    with pytest.raises(FingerprintTakenError) as excinfo:
        client.machines.activate_machine_idempotent(LICENSE_ID, FINGERPRINT)

    assert excinfo.value.code == "FINGERPRINT_TAKEN"
    assert "another" in excinfo.value.detail
    assert isinstance(excinfo.value.__cause__, FingerprintTakenError)
    assert license_filters == [str(LICENSE_ID)]


def test_idempotent_activation_lets_a_limit_rejection_through_untouched(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """Only FINGERPRINT_TAKEN triggers recovery; everything else propagates."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        return httpx.Response(
            422,
            json={"errors": [{"code": "MACHINE_LIMIT_EXCEEDED", "detail": "at the machine limit"}]},
        )

    client = make_client(handler)
    with pytest.raises(MachineOverLimitError) as excinfo:
        client.machines.activate_machine_idempotent(LICENSE_ID, FINGERPRINT)

    assert excinfo.value.validation_code is ValidationCode.TOO_MANY_MACHINES
    assert excinfo.value.rolled_back is False
