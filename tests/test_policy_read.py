"""Tests for the policy/license read routes and the heartbeat window they carry."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

import httpx
import pytest

from tamga.client import HeartbeatScheduler, TamgaClient, heartbeat_interval_for_policy
from tamga.errors import ForbiddenError, NotFoundError
from tamga.models.policy import (
    DEFAULT_HEARTBEAT_DURATION_SECONDS,
    CheckInInterval,
    HeartbeatCullStrategy,
    HeartbeatResurrectionStrategy,
    OverageStrategy,
    PolicyResource,
)

ACCOUNT_PATH = "/v1/accounts/018f2f3a-0000-7000-8000-000000000001"

LICENSE_ID = UUID("018f2f3a-0000-7000-8000-000000000050")
MACHINE_ID = UUID("018f2f3a-0000-7000-8000-000000000051")
POLICY_ID = UUID("018f2f3a-0000-7000-8000-000000000060")


def _policy_data(**attribute_overrides: object) -> dict:
    attributes: dict = {
        "product_id": "018f2f3a-0000-7000-8000-000000000070",
        "name": "Standard",
        "overage_strategy": "NO_OVERAGE",
        "heartbeat_cull_strategy": "DEACTIVATE_DEAD",
        "heartbeat_resurrection_strategy": "NO_REVIVE",
        "check_in_interval": "day",
        "require_check_in": True,
        "scheme": "ED25519_SIGN",
        "expiration_strategy": "RESTRICT_ACCESS",
        "renewal_basis": "FROM_EXPIRY",
        "authentication_strategy": "LICENSE",
        "require_heartbeat": True,
        "heartbeat_duration": 120,
        "machine_uniqueness_strategy": "UNIQUE_PER_ACCOUNT",
        "max_machines": 5,
    }
    attributes.update(attribute_overrides)
    return {"id": str(POLICY_ID), "type": "policies", "attributes": attributes}


def test_get_license_policy_request_shape_and_parsing(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"{ACCOUNT_PATH}/licenses/{LICENSE_ID}/policy"
        return httpx.Response(200, json={"data": _policy_data()})

    client = make_client(handler)
    policy = client.licenses.get_policy(LICENSE_ID)

    assert policy.id == POLICY_ID
    assert policy.heartbeat_duration == 120
    assert policy.require_heartbeat is True
    assert policy.machine_uniqueness_strategy == "UNIQUE_PER_ACCOUNT"
    assert policy.check_in_interval is CheckInInterval.DAY
    assert policy.overage_strategy is OverageStrategy.NO_OVERAGE


def test_policy_id_comes_off_the_resource_envelope_not_the_attributes(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """JSON:API carries `id` beside `attributes`, never inside it."""

    def handler(request: httpx.Request) -> httpx.Response:
        data = _policy_data()
        assert "id" not in data["attributes"]
        return httpx.Response(200, json={"data": data})

    client = make_client(handler)
    assert client.licenses.get_policy(LICENSE_ID).id == POLICY_ID


def test_get_policy_direct_route_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"{ACCOUNT_PATH}/policies/{POLICY_ID}"
        return httpx.Response(200, json={"data": _policy_data()})

    client = make_client(handler)
    assert client.policies.get(POLICY_ID).heartbeat_duration == 120


def test_get_policy_direct_route_403s_under_license_key_auth(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    """`GET /policies/{id}` needs `policy.read`, which a license credential lacks."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"errors": [{"code": "FORBIDDEN", "detail": "not permitted"}]},
        )

    client = make_client(handler)
    with pytest.raises(ForbiddenError):
        client.policies.get(POLICY_ID)


def test_get_license_request_shape(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"{ACCOUNT_PATH}/licenses/{LICENSE_ID}"
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": str(LICENSE_ID),
                    "type": "licenses",
                    "attributes": {"status": "ACTIVE", "machines_count": 2},
                }
            },
        )

    client = make_client(handler)
    license_resource = client.licenses.get(LICENSE_ID)
    assert license_resource.id == LICENSE_ID
    assert license_resource.attributes["machines_count"] == 2


def test_get_license_missing_raises_not_found(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"errors": [{"code": "NOT_FOUND", "detail": "gone"}]})

    client = make_client(handler)
    with pytest.raises(NotFoundError):
        client.licenses.get(LICENSE_ID)


def _policy(heartbeat_duration: int | None) -> PolicyResource:
    return PolicyResource(
        id=POLICY_ID,
        overage_strategy=OverageStrategy.NO_OVERAGE,
        heartbeat_cull_strategy=HeartbeatCullStrategy.DEACTIVATE_DEAD,
        heartbeat_resurrection_strategy=HeartbeatResurrectionStrategy.NO_REVIVE,
        check_in_interval=None,
        require_check_in=False,
        scheme=None,
        expiration_strategy="RESTRICT_ACCESS",
        renewal_basis="FROM_EXPIRY",
        authentication_strategy="LICENSE",
        heartbeat_duration=heartbeat_duration,
    )


@pytest.mark.parametrize(
    ("heartbeat_duration", "expected_window"),
    [
        (None, DEFAULT_HEARTBEAT_DURATION_SECONDS),
        (120, 120),
        (0, DEFAULT_HEARTBEAT_DURATION_SECONDS),
        (-5, DEFAULT_HEARTBEAT_DURATION_SECONDS),
    ],
)
def test_effective_window_falls_back_only_when_unset_or_nonsensical(
    heartbeat_duration: int | None, expected_window: int
) -> None:
    assert _policy(heartbeat_duration).effective_heartbeat_window_seconds == expected_window


def test_interval_for_a_default_policy_matches_the_historical_200_second_default() -> None:
    assert heartbeat_interval_for_policy(_policy(None)) == timedelta(seconds=200)


def test_interval_shortens_with_the_policy_window() -> None:
    assert heartbeat_interval_for_policy(_policy(120)) == timedelta(seconds=40)


def test_interval_never_collapses_to_zero() -> None:
    """A two-second window floor-divides to 0s, which would be a busy loop."""
    assert heartbeat_interval_for_policy(_policy(2)) == timedelta(seconds=1)


def test_scheduler_for_policy_uses_the_policy_derived_interval(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
) -> None:
    client = make_client(lambda request: httpx.Response(200, json={"data": {}}))
    scheduler = HeartbeatScheduler.for_policy(client.machines, MACHINE_ID, _policy(120))
    assert scheduler.interval == timedelta(seconds=40)
    assert scheduler.machine_id == MACHINE_ID
    assert scheduler.machines is client.machines


@pytest.mark.parametrize("heartbeat_duration", [0, -5])
def test_both_construction_paths_agree_on_a_non_positive_window(
    make_client: Callable[[Callable[[httpx.Request], httpx.Response]], TamgaClient],
    heartbeat_duration: int,
) -> None:
    """The scheduler's own clamp must not disagree with the policy-derived one.

    This is why the constructor falls back rather than raising. `for_policy`
    substitutes the 600s default for a non-positive `heartbeat_duration`, so a
    constructor that rejected the same input would make the two paths report
    different things about one policy.
    """
    client = make_client(lambda request: httpx.Response(200, json={"data": {}}))
    derived = HeartbeatScheduler.for_policy(
        client.machines, MACHINE_ID, _policy(heartbeat_duration)
    )
    by_hand = HeartbeatScheduler(
        machines=client.machines,
        machine_id=MACHINE_ID,
        interval=timedelta(seconds=heartbeat_duration),
    )
    assert by_hand.interval == derived.interval == timedelta(seconds=200)


def test_policy_defaults_stay_backwards_compatible_for_positional_construction() -> None:
    """The three new fields are appended with defaults, so old call sites still work."""
    policy = _policy(None)
    assert policy.heartbeat_duration is None
    assert policy.require_heartbeat is False
    assert policy.machine_uniqueness_strategy == "UNIQUE_PER_LICENSE"
