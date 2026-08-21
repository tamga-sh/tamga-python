"""Tests for machine management: create/delete/activate/heartbeat."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from uuid import UUID

import httpx
import pytest

from tamga.client import HeartbeatScheduler, TamgaClient
from tamga.errors import (
    CoreLimitExceededError,
    FingerprintTakenError,
    MachineLimitExceededError,
    MachineOverLimitError,
    NotFoundError,
    TamgaError,
)
from tamga.models.machine import HeartbeatStatus
from tamga.models.validation import ValidationCode

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000050")
MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000051")


def _machine_data(heartbeat_status: str = "NOT_STARTED") -> dict:
    return {
        "id": str(MACHINE_ID),
        "type": "machines",
        "attributes": {"fingerprint": "fp-abc", "heartbeat_status": heartbeat_status},
    }


def test_create_machine_happy_path(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == f"{ACCOUNT_PATH}/machines"
        body = json.loads(request.content)
        assert body["data"]["attributes"]["fingerprint"] == "fp-abc"
        assert body["data"]["relationships"]["license"]["data"]["id"] == str(LICENSE_ID)
        return httpx.Response(201, json={"data": _machine_data()})

    client = make_client(handler)
    machine = client.machines.create(LICENSE_ID, "fp-abc")
    assert machine.id == MACHINE_ID
    assert machine.fingerprint == "fp-abc"
    assert machine.heartbeat_status == HeartbeatStatus.NOT_STARTED


def test_create_machine_duplicate_fingerprint_raises_typed_error(
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
                        "detail": "fingerprint already exists",
                        "source": None,
                    }
                ]
            },
        )

    client = make_client(handler)
    with pytest.raises(FingerprintTakenError):
        client.machines.create(LICENSE_ID, "fp-abc")


def test_activate_machine_rollback_on_too_many_machines(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.url.path == f"{ACCOUNT_PATH}/machines" and request.method == "POST":
            return httpx.Response(201, json={"data": _machine_data()})
        if "actions/validate" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "data": _machine_data(),
                    "meta": {
                        "ts": "2024-01-01T00:00:00Z",
                        "valid": False,
                        "detail": "too many machines",
                        "code": "TOO_MANY_MACHINES",
                    },
                },
            )
        if request.method == "DELETE":
            return httpx.Response(204)
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler)
    with pytest.raises(MachineOverLimitError, match="TOO_MANY_MACHINES") as excinfo:
        client.machines.activate_machine(LICENSE_ID, "fp-abc")

    assert excinfo.value.validation_code == ValidationCode.TOO_MANY_MACHINES
    assert excinfo.value.rolled_back is True
    assert any(c.startswith("DELETE") for c in calls), "machine should have been rolled back"


def test_machine_timestamps_are_parsed(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # Every timestamp the server sends used to be dropped on the floor, which
    # left a Python caller with no way to build the liveness logic the module
    # docs describe: `heartbeat_status` alone cannot say *when* the last ping
    # was, and `memory`/`disk` are megabytes, not bytes.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": str(MACHINE_ID),
                    "type": "machines",
                    "attributes": {
                        "fingerprint": "fp-abc",
                        "heartbeat_status": "ALIVE",
                        "memory": 16384,
                        "disk": 512000,
                        "last_heartbeat_at": "2024-01-01T00:05:00Z",
                        "next_heartbeat_at": "2024-01-01T00:15:00Z",
                        "last_check_out_at": "2024-01-01T00:00:30Z",
                        "created": "2024-01-01T00:00:00Z",
                        "updated": "2024-01-01T00:05:00Z",
                    },
                }
            },
        )

    client = make_client(handler)
    machine = client.machines.ping_heartbeat(MACHINE_ID)

    assert machine.last_heartbeat_at == datetime(2024, 1, 1, 0, 5, tzinfo=timezone.utc)
    assert machine.next_heartbeat_at == datetime(2024, 1, 1, 0, 15, tzinfo=timezone.utc)
    assert machine.last_check_out_at == datetime(2024, 1, 1, 0, 0, 30, tzinfo=timezone.utc)
    assert machine.created == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert machine.updated == datetime(2024, 1, 1, 0, 5, tzinfo=timezone.utc)
    # Megabytes on the wire — 16 GB of RAM is 16384, not 17179869184.
    assert machine.memory == 16384


def test_machine_timestamps_default_to_none_when_absent(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    client = make_client(lambda r: httpx.Response(200, json={"data": _machine_data("ALIVE")}))
    machine = client.machines.ping_heartbeat(MACHINE_ID)
    assert machine.last_heartbeat_at is None
    assert machine.created is None


def test_create_machine_over_limit_raises_the_typed_limit_error(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # Creation is not limit-free: the server checks the policy's machine limit
    # before inserting the row. `status` is the string "422" on the wire.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={
                "errors": [
                    {
                        "id": "e1",
                        "status": "422",
                        "code": "MACHINE_LIMIT_EXCEEDED",
                        "title": "Unprocessable Entity",
                        "detail": "machine limit exceeded for this license",
                        "source": {"pointer": "/data/relationships/license"},
                    }
                ]
            },
        )

    client = make_client(handler)
    with pytest.raises(MachineLimitExceededError) as excinfo:
        client.machines.create(LICENSE_ID, "fp-abc")

    assert excinfo.value.status == 422
    assert excinfo.value.code == "MACHINE_LIMIT_EXCEEDED"
    assert excinfo.value.pointer == "/data/relationships/license"


def test_activate_machine_create_time_422_does_not_delete(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # Under a strict overage strategy the limit stops the create itself, so no
    # row exists. Issuing the rollback DELETE anyway would target a machine id
    # this client never received.
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "POST" and request.url.path == f"{ACCOUNT_PATH}/machines":
            return httpx.Response(
                422,
                json={
                    "errors": [
                        {
                            "id": "e1",
                            "status": "422",
                            "code": "CORE_LIMIT_EXCEEDED",
                            "title": "Unprocessable Entity",
                            "detail": "core limit exceeded",
                        }
                    ]
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler)
    with pytest.raises(MachineOverLimitError, match="TOO_MANY_CORES") as excinfo:
        client.machines.activate_machine(LICENSE_ID, "fp-abc", cores=64)

    # The create-time code is normalized to its ValidationCode equivalent, and
    # the original typed error stays attached as the cause.
    assert excinfo.value.validation_code == ValidationCode.TOO_MANY_CORES
    assert excinfo.value.code == "CORE_LIMIT_EXCEEDED"
    assert excinfo.value.status == 422
    # Nothing was created, so nothing was rolled back — this is the field that
    # tells the two rejection paths apart.
    assert excinfo.value.rolled_back is False
    assert isinstance(excinfo.value.__cause__, CoreLimitExceededError)
    assert calls == [f"POST {ACCOUNT_PATH}/machines"]
    assert not any(c.startswith("DELETE") for c in calls), "nothing was created to roll back"


def test_activate_machine_under_overage_still_rolls_back_at_validate(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # The create-time limit check runs through the policy's overage strategy,
    # so under ALLOW_ACCESS / ALLOW_1_25X_OVERAGE the create succeeds and the
    # limit only shows up in the validate response. The row exists here, so the
    # rollback DELETE must still run.
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "POST" and request.url.path == f"{ACCOUNT_PATH}/machines":
            return httpx.Response(201, json={"data": _machine_data()})
        if "actions/validate" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "data": {"id": str(LICENSE_ID), "type": "licenses", "attributes": {}},
                    "meta": {
                        "ts": "2024-01-01T00:00:00Z",
                        "valid": False,
                        "detail": "too many machines",
                        "code": "TOO_MANY_MACHINES",
                    },
                },
            )
        if request.method == "DELETE":
            return httpx.Response(204)
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = make_client(handler)
    with pytest.raises(MachineOverLimitError, match="rolled back") as excinfo:
        client.machines.activate_machine(LICENSE_ID, "fp-abc")

    # Same type as the create-time rejection, but `rolled_back` records that a
    # row really did exist and had to be deleted.
    assert excinfo.value.rolled_back is True
    assert excinfo.value.validation_code == ValidationCode.TOO_MANY_MACHINES
    assert calls[0] == f"POST {ACCOUNT_PATH}/machines"
    assert calls[-1] == f"DELETE {ACCOUNT_PATH}/machines/{MACHINE_ID}"


def _over_limit_client(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> TamgaClient:
    """A client whose machine-create is refused with a create-time limit 422."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={
                "errors": [
                    {
                        "id": "e1",
                        "status": "422",
                        "code": "MACHINE_LIMIT_EXCEEDED",
                        "title": "Unprocessable Entity",
                        "detail": "machine limit exceeded for this license",
                    }
                ]
            },
        )

    return make_client(handler)


def test_over_limit_error_is_still_caught_by_a_bare_value_error_handler(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # DO NOT DELETE, and do not drop `ValueError` from MachineOverLimitError's
    # bases to make this pass differently. Both activation paths used to raise a
    # bare ValueError; every integrator handler written against that must keep
    # working, which is the whole reason the exception inherits from both. This
    # test is the tripwire on that promise.
    caught: list[ValueError] = []
    try:
        _over_limit_client(make_client).machines.activate_machine(LICENSE_ID, "fp-abc")
    except ValueError as exc:  # deliberately the broad, pre-existing handler shape
        caught.append(exc)

    assert len(caught) == 1
    assert isinstance(caught[0], MachineOverLimitError)


def test_over_limit_error_is_caught_by_the_documented_tamga_error_handler(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # The point of the change. This SDK documents `except TamgaError:` as the
    # way to catch everything it raises against the server, and a bare
    # ValueError silently escaped it — filing "the license is at its seat limit"
    # in the same bucket as "this .lic file is corrupt", which the offline
    # parsers genuinely do raise ValueError for.
    with pytest.raises(TamgaError) as excinfo:
        _over_limit_client(make_client).machines.activate_machine(LICENSE_ID, "fp-abc")

    assert isinstance(excinfo.value, MachineOverLimitError)
    assert excinfo.value.validation_code == ValidationCode.TOO_MANY_MACHINES


def test_over_limit_error_mro_keeps_both_bases_reachable() -> None:
    # A layout conflict between the two bases would surface as a TypeError at
    # class-definition time; assert the resolved order explicitly so a future
    # reordering of the bases cannot quietly change which __init__ wins.
    assert MachineOverLimitError.__mro__[:4] == (
        MachineOverLimitError,
        TamgaError,
        ValueError,
        Exception,
    )


def test_ping_heartbeat_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == (f"{ACCOUNT_PATH}/machines/{MACHINE_ID}/actions/ping-heartbeat")
        return httpx.Response(200, json={"data": _machine_data("ALIVE")})

    client = make_client(handler)
    machine = client.machines.ping_heartbeat(MACHINE_ID)
    assert machine.heartbeat_status == HeartbeatStatus.ALIVE


def test_reset_heartbeat_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == (f"{ACCOUNT_PATH}/machines/{MACHINE_ID}/actions/reset-heartbeat")
        return httpx.Response(200, json={"data": _machine_data("NOT_STARTED")})

    client = make_client(handler)
    machine = client.machines.reset_heartbeat(MACHINE_ID)
    assert machine.heartbeat_status == HeartbeatStatus.NOT_STARTED


def test_heartbeat_scheduler_default_interval_is_200_seconds(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    client = make_client(lambda r: httpx.Response(200, json={"data": _machine_data()}))
    scheduler = HeartbeatScheduler(machines=client.machines, machine_id=MACHINE_ID)
    assert scheduler.interval == timedelta(seconds=200)


@pytest.mark.parametrize("interval", [timedelta(0), timedelta(seconds=-300)])
def test_heartbeat_scheduler_clamps_a_non_positive_interval_to_the_default(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    interval: timedelta,
) -> None:
    # `for_policy` cannot produce a non-positive interval: a policy whose
    # `heartbeat_duration` is zero or negative -- which the column permits,
    # carrying no positivity constraint -- is read as unset and falls back to
    # the 600s window, so to this same 200s ping. Building the dataclass by
    # hand is a documented public path that bypassed that guarantee entirely.
    client = make_client(lambda r: httpx.Response(200, json={"data": _machine_data()}))
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=interval
    )
    assert scheduler.interval == timedelta(seconds=200)


def test_heartbeat_scheduler_does_not_busy_loop_on_a_zero_interval(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The parametrized test above pins the attribute; this pins the consequence
    # that actually matters -- what `run_forever` waits between pings. A zero
    # interval is not a fast heartbeat but an unthrottled one: `ping-heartbeat`
    # issued as fast as the loop turns, from every machine running that code,
    # every request individually valid and correctly authenticated, so nothing
    # about the traffic looks wrong from either end.
    slept: list[float] = []
    ping_count = {"n": 0}
    scheduler_box: dict[str, HeartbeatScheduler] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        ping_count["n"] += 1
        if ping_count["n"] >= 2:
            scheduler_box["scheduler"].stop()
        return httpx.Response(200, json={"data": _machine_data()})

    client = make_client(handler)
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=timedelta(0)
    )
    scheduler_box["scheduler"] = scheduler
    monkeypatch.setattr("tamga.client.time.sleep", lambda seconds: slept.append(seconds))
    scheduler.run_forever()

    assert slept == [200.0, 200.0], "a hand-built zero interval must not become sleep(0)"


def test_heartbeat_scheduler_raises_a_500ms_interval_to_one_second(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    # NOT verbatim. A caller who writes `timedelta(milliseconds=500)` and means
    # it gets one second, and this test exists to be tripped over rather than
    # discovered in production. An earlier revision of this suite asserted the
    # opposite -- that a positive interval is honoured however short -- on the
    # reasoning that flooring it in Python alone would put this SDK out of step
    # with a fleet that clamped only the non-positive case. The floor is now the
    # fleet-wide rule, landed first in tamga-js.
    #
    # What settles it is that `time.sleep` *honours* a sub-second request, so
    # there is no runtime threshold to key a narrower rule to. Measured on
    # CPython 3.13, a bare sleep loop turns ~1,368,000/sec at `sleep(0)`,
    # ~163,000/sec at `sleep(0.000001)` and ~696/sec at `sleep(0.001)` -- the
    # last honoured to within 1.4x of what was asked. A guard aimed only at what
    # the runtime refuses to honour would catch `timedelta(0)` and pass
    # `timedelta(microseconds=1)`, a positive interval issuing 163,000 pings a
    # second. That is a rule about where a number came from, not what it does.
    #
    # The range is reachable by ordinary mistake: `interval` is a `timedelta`
    # while `policy.heartbeat_duration` counts *seconds*, so converting by hand
    # in the wrong direction lands in it.
    client = make_client(lambda r: httpx.Response(200, json={"data": _machine_data()}))
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=timedelta(milliseconds=500)
    )
    assert scheduler.interval == timedelta(seconds=1)


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        (timedelta(microseconds=1), timedelta(seconds=1)),
        (timedelta(milliseconds=500), timedelta(seconds=1)),
        (timedelta(milliseconds=999), timedelta(seconds=1)),
        # The floor itself, and everything above it, is honoured verbatim.
        (timedelta(seconds=1), timedelta(seconds=1)),
        (timedelta(milliseconds=1001), timedelta(milliseconds=1001)),
        (timedelta(seconds=40), timedelta(seconds=40)),
    ],
)
def test_heartbeat_scheduler_floors_every_positive_sub_second_interval(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    requested: timedelta,
    expected: timedelta,
) -> None:
    # Pins both edges of the floor, so "sub-second is raised" cannot quietly
    # become "everything short is rewritten". Note the two substitutions differ
    # and that is deliberate: non-positive lands on the 200s default (above),
    # positive-but-short lands on one second. Zero expresses no wish about rate
    # -- it is an unset value or a units error -- while 500ms expresses one, and
    # the floor is the smallest correction that respects it.
    client = make_client(lambda r: httpx.Response(200, json={"data": _machine_data()}))
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=requested
    )
    assert scheduler.interval == expected


def test_heartbeat_scheduler_does_not_spin_on_a_sub_second_interval(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The attribute tests above pin the value; this pins the consequence that
    # actually matters -- what `run_forever` waits between pings. Unlike the
    # zero case, `time.sleep(0.0005)` would have been honoured, which is exactly
    # why the value never reaches it.
    slept: list[float] = []
    ping_count = {"n": 0}
    scheduler_box: dict[str, HeartbeatScheduler] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        ping_count["n"] += 1
        if ping_count["n"] >= 2:
            scheduler_box["scheduler"].stop()
        return httpx.Response(200, json={"data": _machine_data()})

    client = make_client(handler)
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=timedelta(milliseconds=500)
    )
    scheduler_box["scheduler"] = scheduler
    monkeypatch.setattr("tamga.client.time.sleep", lambda seconds: slept.append(seconds))
    scheduler.run_forever()

    assert slept == [1.0, 1.0], "a hand-built 500ms interval must not become sleep(0.5)"


def test_heartbeat_scheduler_keeps_pinging_after_a_dead_observation(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A defensive test, deliberately mocking a response this particular route
    # cannot send. A ping writes `last_heartbeat_at = NOW()` and derives the
    # status from that same timestamp, so it always answers ALIVE or
    # RESURRECTED. (DEAD itself is perfectly real and readable — a checked-out
    # machine file reports it — just never from a ping.) The loop used to
    # `break` on DEAD anyway: unreachable here, and permanent if it ever fired,
    # since nothing restarted it. So the rule under test is the general one —
    # no status ends the loop — and feeding it the one status that used to be
    # fatal is the sharpest way to hold that.
    ping_count = {"n": 0}
    scheduler_box: dict[str, HeartbeatScheduler] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        ping_count["n"] += 1
        if ping_count["n"] >= 3:
            scheduler_box["scheduler"].stop()
        # Every ping reports DEAD; the loop must not read the status at all.
        return httpx.Response(200, json={"data": _machine_data("DEAD")})

    client = make_client(handler)
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=timedelta(seconds=0)
    )
    scheduler_box["scheduler"] = scheduler
    monkeypatch.setattr("tamga.client.time.sleep", lambda _seconds: None)
    scheduler.run_forever()

    assert ping_count["n"] == 3, "no heartbeat status may end the loop"


def test_heartbeat_scheduler_surfaces_a_404_from_the_ping(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A 404 on the ping is the *only* signal that the machine row is really
    # gone, and it is what a caller keys re-activation off. It must reach them.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={
                "errors": [
                    {
                        "id": "e1",
                        "status": "404",
                        "code": "NOT_FOUND",
                        "title": "Not Found",
                        "detail": "machine not found",
                    }
                ]
            },
        )

    client = make_client(handler)
    scheduler = HeartbeatScheduler(
        machines=client.machines, machine_id=MACHINE_ID, interval=timedelta(seconds=0)
    )
    monkeypatch.setattr("tamga.client.time.sleep", lambda _seconds: None)
    with pytest.raises(NotFoundError):
        scheduler.run_forever()
