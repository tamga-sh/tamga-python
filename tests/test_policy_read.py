"""Tests for the policy/license read routes and the heartbeat window they carry."""

from __future__ import annotations

import math
from collections.abc import Callable
from datetime import timedelta
from uuid import UUID

import httpx
import pytest

from tamga.client import (
    HEARTBEAT_PINGS_PER_WINDOW,
    MIN_HEARTBEAT_INTERVAL,
    HeartbeatScheduler,
    TamgaClient,
    heartbeat_interval_for_policy,
)
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


# ---------------------------------------------------------------------------
# The floor and the divisor, in one place, against the server's real rule.
#
# `MIN_HEARTBEAT_INTERVAL` and `HEARTBEAT_PINGS_PER_WINDOW` interact, and
# neither constant mentions the other or is reachable from it. Below a
# three-second window the floor binds and the divisor's stated promise -- "two
# consecutive pings can be lost" -- stops holding. This block names the
# `heartbeat_duration` value in every case, so the interaction is read off a
# table rather than re-derived from two constants in different places.
#
# The server's rule is NOT `age > window`. From
# `tamga-api/src/features/machines/model.rs::heartbeat_status_within`:
#
#     let age_secs = (Utc::now() - hb_ts).num_seconds();
#     let within_window = age_secs <= window_secs;
#
# `num_seconds()` returns *whole* seconds and truncates
# (`Duration::milliseconds(1999).num_seconds() == 1`), so a machine first reads
# DEAD at an age of `window_secs + 1` seconds. Every window carries one free
# second on top of its nominal value.
# ---------------------------------------------------------------------------


def _dead_at_age_seconds(window_secs: int) -> int:
    """The first whole-second age at which a read reports DEAD."""
    return window_secs + 1


def _losses_tolerated(window_secs: int, interval: timedelta) -> int:
    """Consecutive pings that can be lost before a read sees DEAD.

    After `m` misses the age reaches `(m + 1) * interval`. A result of -1 means
    the window is not held even when no ping is lost at all.
    """
    return math.ceil(_dead_at_age_seconds(window_secs) / interval.total_seconds()) - 2


def test_truncation_gives_every_window_a_free_second() -> None:
    # ⚠️ STANDING CAVEAT -- this is the test that fails first if it stops being
    # true. Everything the 1s floor rests on is here: the server compares
    # *truncated whole seconds*, so a 1s window is served comfortably by a 1s
    # ping (two seconds of slack, not zero). If the server ever compared
    # sub-second, `_dead_at_age_seconds` would collapse to the window itself,
    # and two things change at once: `heartbeat_duration: 0` becomes unserveable
    # at ANY ping rate rather than merely unchased, and `heartbeat_duration: 1`
    # becomes the genuine boundary case it is sometimes mistaken for today --
    # its row in the table below would drop from 0 tolerated losses to -1.
    #
    # Do not restate the rule as "DEAD once the age passes the window". That
    # pessimistic reading makes the floor look broken on short windows when it
    # is not, and it is what a window-aware floor was once proposed to fix.
    assert _dead_at_age_seconds(1) == 2
    assert _dead_at_age_seconds(2) == 3
    assert _dead_at_age_seconds(600) == 601
    assert _dead_at_age_seconds(1) > 1


@pytest.mark.parametrize(
    ("heartbeat_duration", "expected_interval", "expected_losses"),
    [
        # duration -> interval the scheduler pings at -> consecutive losses it
        # survives, judged against the window the *server* enforces.
        (600, timedelta(seconds=200), 2),  # fallback window: divisor governs
        (3, timedelta(seconds=1), 2),  # first window where floor and divisor agree
        (2, timedelta(seconds=1), 1),  # floor binds: promise degraded to 1 loss
        (1, timedelta(seconds=1), 0),  # floor binds hardest: steady state only
        # `0` is the one window that cannot be held, and Python reaches that
        # verdict by a different route than the rest of the fleet. The server's
        # own `COALESCE(p.heartbeat_duration, 600)` substitutes only for NULL,
        # so a stored `0` really is a zero-second window and reads DEAD at an
        # age of 1s. `PolicyResource.effective_heartbeat_window_seconds`
        # deliberately treats non-positive as unset, so this SDK never derives
        # an interval from a zero window at all -- it pings every 200s at a
        # machine the server has already judged. The floor is not what fails
        # here; nothing at or above it could hold this window either.
        (0, timedelta(seconds=200), -1),
    ],
)
def test_the_floor_and_the_divisor_against_the_servers_liveness_rule(
    heartbeat_duration: int,
    expected_interval: timedelta,
    expected_losses: int,
) -> None:
    interval = heartbeat_interval_for_policy(_policy(heartbeat_duration))
    assert interval == expected_interval
    assert interval >= MIN_HEARTBEAT_INTERVAL
    assert _losses_tolerated(heartbeat_duration, interval) == expected_losses

    if expected_losses >= 0:
        # Steady state holds the window: the age never reaches the server's DEAD
        # threshold between two successful pings.
        assert interval.total_seconds() < _dead_at_age_seconds(heartbeat_duration)


def test_heartbeat_duration_zero_is_the_one_window_the_floor_is_not_chasing() -> None:
    # Its entire grace *is* the free second that truncation grants, so the floor
    # lands exactly on it. A sub-second ping would in fact hold it -- ~333ms
    # keeps the age at 0 whole seconds -- and this SDK deliberately does not do
    # that: it would buy one nonsensical policy value by pinning the request
    # rate to `num_seconds()` truncation, an implementation artifact rather than
    # a protocol guarantee. See `test_truncation_gives_every_window_a_free_second`
    # for what changes if that artifact ever goes away.
    assert _dead_at_age_seconds(0) == 1
    assert _losses_tolerated(0, MIN_HEARTBEAT_INTERVAL) == -1
    assert _losses_tolerated(0, timedelta(milliseconds=333)) >= 0


def test_a_negative_window_is_unserveable_at_any_ping_rate() -> None:
    # `age_secs <= -30` is false for every non-negative age, so a negative
    # window reads DEAD unconditionally. There is nothing for any floor to
    # chase, and no interval to pick.
    assert _dead_at_age_seconds(-30) < 0


def test_the_divisor_still_governs_every_window_the_floor_does_not_reach() -> None:
    # The floor only binds below `HEARTBEAT_PINGS_PER_WINDOW` seconds. At and
    # above that the divisor alone decides, and the two-loss promise is intact.
    assert heartbeat_interval_for_policy(_policy(HEARTBEAT_PINGS_PER_WINDOW)) == (
        MIN_HEARTBEAT_INTERVAL
    )
    for duration in (HEARTBEAT_PINGS_PER_WINDOW, 60, 120, 600):
        interval = heartbeat_interval_for_policy(_policy(duration))
        assert _losses_tolerated(duration, interval) == HEARTBEAT_PINGS_PER_WINDOW - 1


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
