"""License validation result models.

Covers the response shape shared by all three validation endpoints
(``validate-key``, ``validate`` by ID, quick-validate) as documented in the
Tamga API protocol specification section 2.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class ValidationCode(str, Enum):
    """The ``meta.code`` value returned by license validation endpoints.

    Modeled with all 24 server-declared values so deserialization never
    crashes on a value this SDK version doesn't yet recognize (see
    ``_missing_`` below for the lenient-unknown-value fallback). Only a
    subset is actually reachable against the current server — see the
    per-member docstrings.

    Reachable today (✅), in the exact priority order the server evaluates
    them for the validate-by-ID endpoint: VALID, SUSPENDED, EXPIRED,
    OVERDUE, PRODUCT_SCOPE_MISMATCH, POLICY_SCOPE_MISMATCH,
    USER_SCOPE_MISMATCH, ENVIRONMENT_SCOPE_MISMATCH, TOO_MANY_MACHINES,
    TOO_MANY_CORES, TOO_MUCH_MEMORY, TOO_MUCH_DISK, TOO_MANY_PROCESSES,
    TOO_MANY_USES.
    """

    VALID = "VALID"
    """All checks passed. Reachable: ✅"""

    SUSPENDED = "SUSPENDED"
    """``license.suspended == true``. Reachable: ✅"""

    EXPIRED = "EXPIRED"
    """``expiry < now``. Reachable: ✅"""

    OVERDUE = "OVERDUE"
    """Check-in required and window elapsed. Reachable: ✅"""

    PRODUCT_SCOPE_MISMATCH = "PRODUCT_SCOPE_MISMATCH"
    """``scope.product`` set and mismatched. Reachable: ✅"""

    POLICY_SCOPE_MISMATCH = "POLICY_SCOPE_MISMATCH"
    """``scope.policy`` set and mismatched. Reachable: ✅"""

    USER_SCOPE_MISMATCH = "USER_SCOPE_MISMATCH"
    """``scope.user`` set and mismatched. Reachable: ✅"""

    ENVIRONMENT_SCOPE_MISMATCH = "ENVIRONMENT_SCOPE_MISMATCH"
    """``scope.environment`` set and mismatched. Reachable: ✅"""

    TOO_MANY_MACHINES = "TOO_MANY_MACHINES"
    """Machine count over ``policy.max_machines`` (per overage strategy). Reachable: ✅"""

    TOO_MANY_CORES = "TOO_MANY_CORES"
    """Core count over ``policy.max_cores``. Reachable: ✅"""

    TOO_MUCH_MEMORY = "TOO_MUCH_MEMORY"
    """Memory over ``policy.max_memory``. Reachable: ✅"""

    TOO_MUCH_DISK = "TOO_MUCH_DISK"
    """Disk over ``policy.max_disk``. Reachable: ✅"""

    TOO_MANY_PROCESSES = "TOO_MANY_PROCESSES"
    """Process count over ``policy.max_processes``. Reachable: ✅"""

    TOO_MANY_USES = "TOO_MANY_USES"
    """``uses >= max_uses``. Reachable: ✅"""

    NOT_FOUND = "NOT_FOUND"
    """No license for key/id.

    Reachable: ⛔ — the handler returns raw HTTP 404 instead of embedding
    this code in a validation response body.
    """

    BANNED = "BANNED"
    """Reachable: ⛔ — declared in the enum, never emitted server-side."""

    ENTITLEMENTS_MISSING = "ENTITLEMENTS_MISSING"
    """Reachable: ⛔ — ``scope.entitlements`` is parsed but not checked."""

    TOO_MANY_USERS = "TOO_MANY_USERS"
    """Reachable: ⛔ — declared, never emitted."""

    HEARTBEAT_DEAD = "HEARTBEAT_DEAD"
    """Reachable: ⛔ — declared, never emitted."""

    HEARTBEAT_NOT_STARTED = "HEARTBEAT_NOT_STARTED"
    """Reachable: ⛔ — declared, never emitted."""

    FINGERPRINT_SCOPE_MISMATCH = "FINGERPRINT_SCOPE_MISMATCH"
    """Reachable: ⛔ — ``scope.fingerprint`` is parsed but not checked."""

    COMPONENTS_SCOPE_MISMATCH = "COMPONENTS_SCOPE_MISMATCH"
    """Reachable: ⛔ — declared, never emitted."""

    CHECKSUM_SCOPE_MISMATCH = "CHECKSUM_SCOPE_MISMATCH"
    """Reachable: ⛔ — ``scope.checksum`` is parsed but not checked."""

    VERSION_SCOPE_MISMATCH = "VERSION_SCOPE_MISMATCH"
    """Reachable: ⛔ — ``scope.version`` is parsed but not checked."""

    UNKNOWN = "UNKNOWN"
    """Sentinel fallback member for a ``code`` value this SDK version doesn't
    recognize (e.g. a future server-side addition). See ``_missing_``.
    """

    @classmethod
    def _missing_(cls, value: object) -> ValidationCode | None:
        """Lenient fallback: unknown codes from a newer server don't raise.

        Rather than raising ``ValueError`` (the default ``Enum`` behavior for
        an unrecognized value), returns ``UNKNOWN`` so deserialization never
        crashes on a value this SDK version doesn't yet model — see the
        module docstring and the Tamga API protocol specification gap #4.
        """
        return cls.UNKNOWN


@dataclass(frozen=True)
class ValidationMeta:
    """The ``meta`` object common to all three validation endpoints.

    Attributes:
        ts: Server timestamp the validation was evaluated at.
        valid: Whether the license passed validation.
        detail: Human-readable explanation of ``code``.
        code: The ``ValidationCode`` describing the validation result.
    """

    ts: datetime
    valid: bool
    detail: str
    code: ValidationCode


@dataclass(frozen=True)
class ValidationResult:
    """Composite return type for all ``licenses.validate_*`` calls.

    Attributes:
        license: Parsed license resource, where present (absent on the
            flat quick-validate response body).
        meta: The parsed ``ValidationMeta``.
    """

    license: Any | None
    meta: ValidationMeta
