"""Data models for the Tamga SDK.

JSON:API resources, validation results, and policy-derived enums. See the Tamga
API protocol specification for the wire-level protocol these models mirror.
"""

from __future__ import annotations

from tamga.models.license import LicenseFileResource, LicenseResource, LicenseScope
from tamga.models.machine import (
    ComponentResource,
    HeartbeatStatus,
    MachineFileResource,
    MachineResource,
    ProcessResource,
)
from tamga.models.policy import (
    CheckInInterval,
    Entitlement,
    HeartbeatCullStrategy,
    HeartbeatResurrectionStrategy,
    LicenseScheme,
    OverageStrategy,
    PolicyResource,
)
from tamga.models.validation import ValidationCode, ValidationMeta, ValidationResult

__all__ = [
    "CheckInInterval",
    "ComponentResource",
    "Entitlement",
    "HeartbeatCullStrategy",
    "HeartbeatResurrectionStrategy",
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
    "ValidationCode",
    "ValidationMeta",
    "ValidationResult",
]
