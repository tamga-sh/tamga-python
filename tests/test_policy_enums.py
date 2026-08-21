"""Tests for policy-derived enums and PolicyResource parsing gotchas."""

from __future__ import annotations

from dataclasses import fields
from uuid import UUID

import pytest

from tamga.models.policy import (
    AUTHENTICATION_STRATEGIES,
    EXPIRATION_STRATEGIES,
    HeartbeatCullStrategy,
    HeartbeatResurrectionStrategy,
    LicenseScheme,
    OverageStrategy,
    PolicyResource,
)
from tamga.models.validation import ValidationCode

POLICY_ID = UUID("018f2f3a-0000-7000-8000-000000000090")


def test_unknown_validation_code_deserializes_leniently() -> None:
    code = ValidationCode("SOME_BRAND_NEW_CODE_FROM_A_NEWER_SERVER")
    assert code == ValidationCode.UNKNOWN


def test_deny_access_falls_back_to_no_overage() -> None:
    policy = PolicyResource.from_api(
        {
            "id": str(POLICY_ID),
            "overage_strategy": "DENY_ACCESS",
            "require_check_in": False,
        }
    )
    assert policy.overage_strategy == OverageStrategy.NO_OVERAGE


def test_no_resurrection_falls_back_to_no_revive() -> None:
    policy = PolicyResource.from_api(
        {
            "id": str(POLICY_ID),
            "heartbeat_resurrection_strategy": "NO_RESURRECTION",
            "require_check_in": False,
        }
    )
    assert policy.heartbeat_resurrection_strategy == HeartbeatResurrectionStrategy.NO_REVIVE


def test_real_overage_strategy_variant_is_parsed_correctly() -> None:
    policy = PolicyResource.from_api(
        {
            "id": str(POLICY_ID),
            "overage_strategy": "ALLOW_2X_OVERAGE",
            "require_check_in": False,
        }
    )
    assert policy.overage_strategy == OverageStrategy.ALLOW_2X_OVERAGE


def test_policy_parses_successfully_when_max_memory_and_max_disk_absent() -> None:
    policy = PolicyResource.from_api(
        {
            "id": str(POLICY_ID),
            "require_check_in": False,
            "max_machines": 5,
            # max_memory / max_disk intentionally absent — no policy
            # serializer emits either, even though both are enforced.
        }
    )
    assert policy.max_machines == 5


def test_phantom_limits_are_not_dataclass_fields() -> None:
    # The point of the removal: they are gone from the typed surface — the
    # field list, __init__, asdict(), and what a type checker sees.
    names = {f.name for f in fields(PolicyResource)}
    assert "max_memory" not in names
    assert "max_disk" not in names
    assert "max_machines" in names


@pytest.mark.parametrize("name", ["max_memory", "max_disk"])
def test_reading_a_phantom_limit_warns_and_still_returns_none(name: str) -> None:
    # A ^1.0 consumer auto-upgrades into 1.1.0. Reading one of these must not
    # become an AttributeError under them — it returns the same None it always
    # did, and says why.
    policy = PolicyResource.from_api({"id": str(POLICY_ID), "require_check_in": False})

    with pytest.warns(DeprecationWarning, match=f"PolicyResource.{name} is deprecated"):
        value = getattr(policy, name)

    assert value is None


def test_phantom_limit_warning_names_the_removal_version() -> None:
    policy = PolicyResource.from_api({"id": str(POLICY_ID), "require_check_in": False})

    with pytest.warns(DeprecationWarning) as caught:
        _ = policy.max_memory

    assert "2.0.0" in str(caught[0].message)
    assert "TOO_MUCH_MEMORY" in str(caught[0].message)


def test_an_unrelated_missing_attribute_still_raises_attribute_error() -> None:
    # The shim must not turn every typo on this class into a silent None.
    policy = PolicyResource.from_api({"id": str(POLICY_ID), "require_check_in": False})

    with pytest.raises(AttributeError, match="max_machiens"):
        _ = policy.max_machiens  # type: ignore[attr-defined]


def test_constructing_with_a_phantom_limit_is_rejected() -> None:
    # The one break a ^1.0 consumer can hit: hand-construction. Loud, and at
    # the call site that asserted the field could hold a value.
    with pytest.raises(TypeError, match="max_memory"):
        PolicyResource(  # type: ignore[call-arg]
            id=POLICY_ID,
            overage_strategy=OverageStrategy.NO_OVERAGE,
            heartbeat_cull_strategy=HeartbeatCullStrategy.DEACTIVATE_DEAD,
            heartbeat_resurrection_strategy=HeartbeatResurrectionStrategy.NO_REVIVE,
            check_in_interval=None,
            require_check_in=False,
            scheme=None,
            expiration_strategy="RESTRICT_ACCESS",
            renewal_basis="FROM_EXPIRY",
            authentication_strategy="TOKEN",
            max_memory=1024,
        )


def test_a_server_that_started_emitting_the_limits_is_ignored_not_fatal() -> None:
    # from_api must keep tolerating the attributes if the server ever adds
    # them to the serializer: unknown keys are dropped, not raised on.
    policy = PolicyResource.from_api(
        {
            "id": str(POLICY_ID),
            "require_check_in": False,
            "max_memory": 2048,
            "max_disk": 4096,
        }
    )

    with pytest.warns(DeprecationWarning):
        assert policy.max_memory is None


def test_policy_defaults_heartbeat_cull_strategy_and_scheme() -> None:
    policy = PolicyResource.from_api({"id": str(POLICY_ID), "require_check_in": True})
    assert policy.heartbeat_cull_strategy == HeartbeatCullStrategy.DEACTIVATE_DEAD
    assert policy.scheme is None
    assert policy.require_check_in is True


def test_policy_parses_real_scheme_value() -> None:
    policy = PolicyResource.from_api(
        {"id": str(POLICY_ID), "require_check_in": False, "scheme": "ED25519_SIGN"}
    )
    assert policy.scheme == LicenseScheme.ED25519_SIGN


def test_expiration_strategies_include_revoke_access() -> None:
    # REVOKE_ACCESS is the one expiration strategy that changes *authentication*
    # rather than just the validation code: an expired license under it stops
    # authenticating and the server answers 401 LICENSE_EXPIRED.
    assert sorted(EXPIRATION_STRATEGIES) == [
        "ALLOW_ACCESS",
        "MAINTAIN_ACCESS",
        "RESTRICT_ACCESS",
        "REVOKE_ACCESS",
    ]


def test_authentication_strategies_include_none() -> None:
    # NONE behaves like TOKEN at the auth gate: license-key auth is rejected
    # with 401 LICENSE_NOT_ALLOWED under either. Only LICENSE and MIXED accept
    # it, and the column defaults to TOKEN — so license-key auth is off unless
    # someone turned it on.
    assert sorted(AUTHENTICATION_STRATEGIES) == ["LICENSE", "MIXED", "NONE", "TOKEN"]


def test_policy_parses_the_new_strategy_values() -> None:
    policy = PolicyResource.from_api(
        {
            "id": "018f2f3a-0000-7000-8000-0000000000a0",
            "expiration_strategy": "REVOKE_ACCESS",
            "authentication_strategy": "NONE",
        }
    )
    assert policy.expiration_strategy == "REVOKE_ACCESS"
    assert policy.authentication_strategy == "NONE"
