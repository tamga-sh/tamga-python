"""Tests for policy-derived enums and PolicyResource parsing gotchas."""

from __future__ import annotations

from uuid import UUID

from tamga.models.policy import (
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
            # max_memory / max_disk intentionally absent — server's GET
            # response omits these even though both are enforced.
        }
    )
    assert policy.max_machines == 5
    assert policy.max_memory is None
    assert policy.max_disk is None


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
