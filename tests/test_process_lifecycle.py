"""Tests for process deletion, listing, and scheduler disposal.

Nothing server-side reaps process rows, so a process that merely stops pinging
keeps its slot against the policy's `max_processes` forever. These cover the
half of the lifecycle the SDK has to perform explicitly.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

import httpx
import pytest

from tamga.client import MAX_PAGE_SIZE, ProcessHeartbeatScheduler, TamgaClient
from tamga.errors import ForbiddenError, NotFoundError

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000051")
PROCESS_ID = UUID("018f2f3a-0000-7000-8000-000000000080")


def _process_data(process_id: UUID = PROCESS_ID, pid: str = "4242") -> dict:
    return {
        "id": str(process_id),
        "type": "processes",
        "attributes": {"pid": pid, "machine_id": str(MACHINE_ID)},
    }


def test_delete_process_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        assert request.url.path == f"{ACCOUNT_PATH}/processes/{PROCESS_ID}"
        return httpx.Response(204)

    client = make_client(handler)
    assert client.processes.delete(PROCESS_ID) is None


def test_delete_process_surfaces_a_missing_row(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The raw endpoint does not swallow a 404 — only `dispose` does."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errors": [{"code": "NOT_FOUND", "detail": "gone"}]})

    client = make_client(handler)
    with pytest.raises(NotFoundError):
        client.processes.delete(PROCESS_ID)


def test_list_machine_processes_is_keyset_paginated(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{ACCOUNT_PATH}/machines/{MACHINE_ID}/processes"
        assert request.url.params["limit"] == str(MAX_PAGE_SIZE)
        assert request.url.params["page[after]"] == "cursor-1"
        assert "page[number]" not in request.url.params
        return httpx.Response(200, json={"data": [_process_data()]})

    client = make_client(handler)
    page = client.processes.list(MACHINE_ID, after="cursor-1")
    assert [p.id for p in page.items] == [PROCESS_ID]
    # A short page is the last page.
    assert page.next_after is None


def test_list_machine_processes_synthesizes_a_cursor_on_a_full_page(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["limit"] == "2"
        return httpx.Response(
            200,
            json={
                "data": [
                    _process_data(),
                    _process_data(UUID("018f2f3a-0000-7000-8000-000000000081"), pid="4243"),
                ]
            },
        )

    client = make_client(handler)
    page = client.processes.list(MACHINE_ID, limit=2)
    assert page.next_after == "018f2f3a-0000-7000-8000-000000000081"


def test_dispose_stops_the_loop_and_deletes_the_row(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    deleted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "DELETE"
        deleted.append(request.url.path)
        return httpx.Response(204)

    client = make_client(handler)
    scheduler = ProcessHeartbeatScheduler(
        processes=client.processes, process_id=PROCESS_ID, interval=timedelta(seconds=1)
    )
    scheduler.dispose()

    assert deleted == [f"{ACCOUNT_PATH}/processes/{PROCESS_ID}"]
    assert scheduler._stop is True


def test_dispose_treats_an_already_deleted_row_as_success(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errors": [{"code": "NOT_FOUND", "detail": "gone"}]})

    client = make_client(handler)
    scheduler = ProcessHeartbeatScheduler(processes=client.processes, process_id=PROCESS_ID)
    scheduler.dispose()  # must not raise
    assert scheduler._stop is True


def test_dispose_propagates_anything_other_than_a_missing_row(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """A 403 means the slot is still held; silence would hide a leak."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": [{"code": "FORBIDDEN", "detail": "nope"}]})

    client = make_client(handler)
    scheduler = ProcessHeartbeatScheduler(processes=client.processes, process_id=PROCESS_ID)
    with pytest.raises(ForbiddenError):
        scheduler.dispose()


def test_scheduler_context_manager_disposes_on_normal_exit(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return httpx.Response(204)

    client = make_client(handler)
    with ProcessHeartbeatScheduler(processes=client.processes, process_id=PROCESS_ID) as scheduler:
        assert scheduler.process_id == PROCESS_ID

    assert calls == ["DELETE"]


def test_scheduler_context_manager_disposes_on_a_raised_body_without_swallowing_it(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """A crash is exactly when the row would otherwise be orphaned."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return httpx.Response(204)

    client = make_client(handler)
    with pytest.raises(RuntimeError, match="boom"):  # noqa: SIM117
        with ProcessHeartbeatScheduler(processes=client.processes, process_id=PROCESS_ID):
            raise RuntimeError("boom")

    assert calls == ["DELETE"]


def test_stop_alone_does_not_free_the_slot(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """The distinction between `stop` and `dispose` is the whole point of `dispose`."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        return httpx.Response(204)

    client = make_client(handler)
    scheduler = ProcessHeartbeatScheduler(processes=client.processes, process_id=PROCESS_ID)
    scheduler.stop()
    assert calls == []
