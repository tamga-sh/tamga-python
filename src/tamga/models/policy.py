"""Policy-derived enums, ``PolicyResource``, and ``Entitlement``.

A validating client needs to interpret the *policy* behind a license, not
just the validation code — see the Tamga API protocol specification section 10.
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


#: Every legal ``policy.expiration_strategy`` value.
#:
#: The field stays typed as a plain ``str`` (the server treats it as free text
#: and branches on literal matches), so this set is for validation and
#: readability rather than parsing.
#:
#: Only ``REVOKE_ACCESS`` changes authentication: an expired license under it
#: stops authenticating entirely and the server answers ``401 LICENSE_EXPIRED``.
#: Under the other three an expired license still authenticates, and expiry
#: surfaces as ``ValidationCode.EXPIRED`` in the validation result instead.
EXPIRATION_STRATEGIES: frozenset[str] = frozenset(
    {"RESTRICT_ACCESS", "MAINTAIN_ACCESS", "ALLOW_ACCESS", "REVOKE_ACCESS"}
)

#: Every legal ``policy.authentication_strategy`` value.
#:
#: License-key auth (``Authorization: License <key>``, and the ``license:<key>``
#: Basic sub-form) is accepted **only** under ``LICENSE`` or ``MIXED``. The
#: column defaults to ``TOKEN``, and ``NONE`` behaves identically to ``TOKEN``
#: at this gate — under either the server answers ``401 LICENSE_NOT_ALLOWED``.
#: Treat that as a configuration precondition to fix on the policy, never as a
#: retryable authentication failure.
AUTHENTICATION_STRATEGIES: frozenset[str] = frozenset({"TOKEN", "LICENSE", "MIXED", "NONE"})


class CheckInInterval(str, Enum):
    """Lowercase — inconsistent with the ``SCREAMING_SNAKE_CASE`` convention above."""

    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"


@dataclass(frozen=True)
class PolicyResource:
    """A license's policy, describing enforcement behavior.

    Important parsing gotchas (see the Tamga API protocol specification
    section 10):

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
        expiration_strategy: One of ``EXPIRATION_STRATEGIES``.
            ``"RESTRICT_ACCESS"`` (default) denies access past expiry;
            ``"MAINTAIN_ACCESS"``/``"ALLOW_ACCESS"`` permit it;
            ``"REVOKE_ACCESS"`` additionally stops the expired license from
            authenticating at all (``401 LICENSE_EXPIRED``).
        renewal_basis: ``"FROM_EXPIRY"`` (default) vs ``"FROM_NOW"``.
        authentication_strategy: One of ``AUTHENTICATION_STRATEGIES``.
            ``"TOKEN"`` (default) and ``"NONE"`` both **reject** license-key
            auth with ``401 LICENSE_NOT_ALLOWED``; only ``"LICENSE"`` and
            ``"MIXED"`` accept it. Check this before shipping a client that
            authenticates with a raw license key.
        max_machines: Machine limit, subject to ``overage_strategy``.
        max_cores: Core limit, subject to ``overage_strategy``.
        max_processes: Process limit, subject to ``overage_strategy``.
        max_uses: Use limit — always strict, ``overage_strategy`` does not apply.
        max_memory: Memory limit, subject to ``overage_strategy``. **Always
            ``None`` in practice** — the server's ``GET`` response for a
            policy omits this field even though it's enforced during
            validation (see the Tamga API protocol specification section 10
            and "Known Server-Side Gaps" item 9's neighboring note). Modeled
            here anyway so parsing doesn't break if/when the server starts
            including it, and so callers have a typed field to check rather
            than reaching into raw attributes. Do not rely on this being
            populated — the only
            way to observe this limit today is a ``TOO_MUCH_MEMORY``
            validation code.
        max_disk: Disk limit, subject to ``overage_strategy``. Same
            "always ``None`` in practice" caveat as ``max_memory`` — only
            observable via a ``TOO_MUCH_DISK`` validation code.
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
    max_memory: int | None = None
    max_disk: int | None = None

    @classmethod
    def from_api(cls, attributes: dict[str, Any]) -> PolicyResource:
        """Parse a raw JSON:API ``policies`` attributes dict.

        Applies the ``DENY_ACCESS``/``NO_RESURRECTION`` fallback rules
        documented above.
        """
        raw_overage = attributes.get("overage_strategy")
        try:
            overage_strategy = (
                OverageStrategy(raw_overage)
                if raw_overage is not None
                else OverageStrategy.NO_OVERAGE
            )
        except ValueError:
            # "DENY_ACCESS" (and any other unrecognized string) is not a
            # real OverageStrategy variant — the server silently applies
            # NO_OVERAGE semantics for it, so parsing must match that
            # actual behavior rather than raising or trusting the name.
            overage_strategy = OverageStrategy.NO_OVERAGE

        raw_resurrection = attributes.get("heartbeat_resurrection_strategy")
        try:
            resurrection_strategy = (
                HeartbeatResurrectionStrategy(raw_resurrection)
                if raw_resurrection is not None
                else HeartbeatResurrectionStrategy.NO_REVIVE
            )
        except ValueError:
            # "NO_RESURRECTION" (and any other unrecognized string) is not a
            # real variant — silently behaves as NO_REVIVE server-side.
            resurrection_strategy = HeartbeatResurrectionStrategy.NO_REVIVE

        raw_cull = attributes.get("heartbeat_cull_strategy")
        cull_strategy = (
            HeartbeatCullStrategy(raw_cull)
            if raw_cull is not None
            else HeartbeatCullStrategy.DEACTIVATE_DEAD
        )

        raw_check_in_interval = attributes.get("check_in_interval")
        check_in_interval = (
            CheckInInterval(raw_check_in_interval) if raw_check_in_interval is not None else None
        )

        raw_scheme = attributes.get("scheme")
        scheme = LicenseScheme(raw_scheme) if raw_scheme is not None else None

        return cls(
            id=UUID(str(attributes["id"])) if "id" in attributes else UUID(int=0),
            overage_strategy=overage_strategy,
            heartbeat_cull_strategy=cull_strategy,
            heartbeat_resurrection_strategy=resurrection_strategy,
            check_in_interval=check_in_interval,
            require_check_in=bool(attributes.get("require_check_in", False)),
            scheme=scheme,
            expiration_strategy=attributes.get("expiration_strategy", "RESTRICT_ACCESS"),
            renewal_basis=attributes.get("renewal_basis", "FROM_EXPIRY"),
            authentication_strategy=attributes.get("authentication_strategy", "TOKEN"),
            max_machines=attributes.get("max_machines"),
            max_cores=attributes.get("max_cores"),
            max_processes=attributes.get("max_processes"),
            max_uses=attributes.get("max_uses"),
            max_memory=attributes.get("max_memory"),
            max_disk=attributes.get("max_disk"),
        )


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
        inherited: ``True`` when the license holds this entitlement through
            its policy rather than by a direct attachment. ``None`` when the
            server did not send the flag — it appears only on the
            license-scoped listing, not on account-, policy-, or
            release-scoped responses. An inherited entitlement cannot be
            detached from the license (``403 POLICY_ENTITLEMENT``), cannot be
            attached again (``422 ENTITLEMENT_ALREADY_INHERITED``), and is
            **not** resolvable through
            ``TamgaClient.entitlements.get`` — that route reads only direct
            attachments and answers ``404`` for it.
    """

    id: UUID
    name: str
    code: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created: datetime | None = None
    updated: datetime | None = None
    inherited: bool | None = None
