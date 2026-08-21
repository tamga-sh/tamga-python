"""Data models for the Tamga SDK.

JSON:API resources, validation results, and policy-derived enums. See the Tamga
API protocol specification for the wire-level protocol these models mirror.
"""

from __future__ import annotations

from tamga.models.health import HealthStatus
from tamga.models.license import LicenseFileResource, LicenseResource, LicenseScope
from tamga.models.machine import (
    ComponentResource,
    HeartbeatStatus,
    MachineFileResource,
    MachineResource,
    ProcessResource,
)
from tamga.models.policy import (
    DEFAULT_HEARTBEAT_DURATION_SECONDS,
    MACHINE_UNIQUENESS_STRATEGIES,
    CheckInInterval,
    Entitlement,
    HeartbeatCullStrategy,
    HeartbeatResurrectionStrategy,
    LicenseScheme,
    OverageStrategy,
    PolicyResource,
)
from tamga.models.release import ReleaseResource
from tamga.models.signing_key import (
    ACTIVE_STATUS,
    ED25519_ALGORITHM,
    ED25519_PUBLIC_KEY_LENGTH,
    RETIRED_STATUS,
    SigningKey,
)
from tamga.models.validation import ValidationCode, ValidationMeta, ValidationResult

__all__ = [
    "ACTIVE_STATUS",
    "DEFAULT_HEARTBEAT_DURATION_SECONDS",
    "ED25519_ALGORITHM",
    "ED25519_PUBLIC_KEY_LENGTH",
    "MACHINE_UNIQUENESS_STRATEGIES",
    "RETIRED_STATUS",
    "CheckInInterval",
    "ComponentResource",
    "Entitlement",
    "HeartbeatCullStrategy",
    "HeartbeatResurrectionStrategy",
    "HealthStatus",
    "HeartbeatStatus",
    "LicenseFileResource",
    "LicenseResource",
    "LicenseScheme",
    "LicenseScope",
    "MachineFileResource",
    "MachineResource",
    "OverageStrategy",
    "PolicyResource",
    "ProcessResource",
    "ReleaseResource",
    "SigningKey",
    "ValidationCode",
    "ValidationMeta",
    "ValidationResult",
]
