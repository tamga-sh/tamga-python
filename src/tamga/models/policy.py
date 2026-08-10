"""Policy-derived enums, ``PolicyResource``, and ``Entitlement``.

A validating client needs to interpret the *policy* behind a license, not
just the validation code — see docs/sdk.md section 10.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID


class OverageStrategy(str, Enum):
    """Multiplies the relevant ``max_*`` limit before comparing usage against it.

    Applies to machines/cores/memory/disk/processes. Does **not** apply to
    ``uses`` — that field is always strict ``>=`` regardless of strategy.
    """

    NO_OVERAGE = "NO_OVERAGE"
    """x1 — no overage allowed."""

    ALLOW_1_25X_OVERAGE = "ALLOW_1_25X_OVERAGE"
    ALLOW_1_5X_OVERAGE = "ALLOW_1_5X_OVERAGE"
    ALLOW_2X_OVERAGE = "ALLOW_2X_OVERAGE"

    ALWAYS_ALLOW_OVERAGE = "ALWAYS_ALLOW_OVERAGE"
    """Limit is ignored entirely."""


class LicenseScheme(str, Enum):
    """Key/checkout signing algorithm.

    ``None``/unset on the wire means a legacy plain key string, unsigned.
    """

    ED25519_SIGN = "ED25519_SIGN"
    RSA_2048_PKCS1_SIGN = "RSA_2048_PKCS1_SIGN"
    RSA_2048_PKCS1_PSS_SIGN = "RSA_2048_PKCS1_PSS_SIGN"
    ECDSA_P256_SIGN = "ECDSA_P256_SIGN"

    RSA_2048_JWT_RS256 = "RSA_2048_JWT_RS256"
    """Explicitly rejected for machine checkout verification (422 SCHEME_NOT_SUPPORTED
    server-side) — the SDK's scheme dispatcher must raise ``SchemeNotSupportedError``
    rather than attempting to verify it."""


class HeartbeatCullStrategy(str, Enum):
    """What happens to a machine once it's ``DEAD``."""

    DEACTIVATE_DEAD = "DEACTIVATE_DEAD"
    """Row is deleted."""

    KEEP_DEAD = "KEEP_DEAD"
    """Row is kept."""


class HeartbeatResurrectionStrategy(str, Enum):
    """Grace window after a machine death during which a new ping revives it."""

    NO_REVIVE = "NO_REVIVE"
    ONE_MINUTE_REVIVE = "1_MINUTE_REVIVE"
    TWO_MINUTE_REVIVE = "2_MINUTE_REVIVE"
    FIVE_MINUTE_REVIVE = "5_MINUTE_REVIVE"
    TEN_MINUTE_REVIVE = "10_MINUTE_REVIVE"
    FIFTEEN_MINUTE_REVIVE = "15_MINUTE_REVIVE"
    ALWAYS_REVIVE = "ALWAYS_REVIVE"


class CheckInInterval(str, Enum):
    """Lowercase — inconsistent with the ``SCREAMING_SNAKE_CASE`` convention above."""

    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"


@dataclass(frozen=True)
class PolicyResource:
    """A license's policy, describing enforcement behavior.

    Important parsing gotchas (see docs/sdk.md section 10):

    - ``overage_strategy`` may be the string ``"DENY_ACCESS"`` on freshly
      created policies — this is **not a real ``OverageStrategy`` variant**;
      it silently behaves as ``NO_OVERAGE`` server-side. Parsing must not
      treat the field name's implication ("deny by default") as meaningful.
    - ``heartbeat_resurrection_strategy`` may similarly be
      ``"NO_RESURRECTION"`` — not a real variant, falls back to
      ``NO_REVIVE`` semantics.
    - The ``GET`` response for a policy **omits ``max_memory`` and
      ``max_disk``** even though both are enforced during validation. This
      SDK cannot introspect those two limits client-side; it can only
      observe ``TOO_MUCH_MEMORY``/``TOO_MUCH_DISK`` if validation fails.

    Free-text fields with no backing enum (branched by literal string match
    server-side; treat any value outside the documented list as
    "deny/default"):

    Attributes:
        id: Resource UUID.
        overage_strategy: See gotcha above.
        heartbeat_cull_strategy: See ``HeartbeatCullStrategy``.
        heartbeat_resurrection_strategy: See gotcha above.
        check_in_interval: See ``CheckInInterval``. ``None`` if check-in isn't required.
        require_check_in: Whether periodic check-in is required at all.
        scheme: See ``LicenseScheme``.
        expiration_strategy: ``"RESTRICT_ACCESS"`` (default) denies access
            past expiry; ``"MAINTAIN_ACCESS"``/``"ALLOW_ACCESS"`` permit it.
        renewal_basis: ``"FROM_EXPIRY"`` (default) vs ``"FROM_NOW"``.
        authentication_strategy: ``"TOKEN"`` (default);
            ``"LICENSE"``/``"MIXED"`` permit license-key bearer auth.
        max_machines: Machine limit, subject to ``overage_strategy``.
        max_cores: Core limit, subject to ``overage_strategy``.
        max_processes: Process limit, subject to ``overage_strategy``.
        max_uses: Use limit — always strict, ``overage_strategy`` does not apply.
    """

    id: UUID
    overage_strategy: OverageStrategy
    heartbeat_cull_strategy: HeartbeatCullStrategy
    heartbeat_resurrection_strategy: HeartbeatResurrectionStrategy
    check_in_interval: CheckInInterval | None
    require_check_in: bool
    scheme: LicenseScheme | None
    expiration_strategy: str
    renewal_basis: str
    authentication_strategy: str
    max_machines: int | None = None
    max_cores: int | None = None
    max_processes: int | None = None
    max_uses: int | None = None

    @classmethod
    def from_api(cls, attributes: dict[str, Any]) -> PolicyResource:
        """Parse a raw JSON:API ``policies`` attributes dict, applying the
        ``DENY_ACCESS``/``NO_RESURRECTION`` fallback rules documented above.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class Entitlement:
    """A full entitlement resource attached to a license.

    Despite the URL shape (``/licenses/{id}/entitlements``), these are full
    ``Entitlement`` resources, not lightweight junction/relationship
    records.

    Attributes:
        id: Resource UUID.
        name: Display label. Not stable — never match on this.
        code: Stable, developer-facing identifier. Always match on this.
        metadata: Arbitrary metadata.
        created: Creation timestamp.
        updated: Last-update timestamp.
    """

    id: UUID
    name: str
    code: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created: datetime | None = None
    updated: datetime | None = None
