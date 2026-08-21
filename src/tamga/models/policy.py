"""Policy-derived enums, ``PolicyResource``, and ``Entitlement``.

A validating client needs to interpret the *policy* behind a license, not
just the validation code — see the Tamga API protocol specification section 10.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
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
    """What happens to a machine once it's ``DEAD`` server-side.

    Describes the culling worker's behavior, not the client's view. The
    ``DEAD`` status a client can read — from a checked-out machine file, see
    ``tamga.models.machine.HeartbeatStatus`` — says nothing about whether
    either strategy has run. The worker skips any policy with
    ``require_heartbeat: false``, which is the default, so under a default
    policy neither strategy applies at all and a machine reported ``DEAD``
    keeps its row and its seat.
    """

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

#: Every legal ``policy.machine_uniqueness_strategy`` value.
#:
#: Decides how wide a net ``409 FINGERPRINT_TAKEN`` is cast over on machine
#: creation. ``UNIQUE_PER_LICENSE`` (the effective default — the server falls
#: through to it for any unrecognized value) rejects a fingerprint already
#: registered against *this* license; ``UNIQUE_PER_POLICY`` widens that to every
#: license sharing the policy, and ``UNIQUE_PER_ACCOUNT`` to the whole account.
#:
#: All three scopes include the caller's own license in the duplicate check, so a
#: repeat activation of the same license and fingerprint conflicts under every
#: one of them and is always recoverable by a license-scoped lookup. What the two
#: wider scopes add is the *cross-license* conflict — one fingerprint registered
#: against a second license — and that is a rejection to respect, not to recover
#: from: it is the seat-sharing those scopes exist to prevent. See
#: ``MachinesClient.activate_machine_idempotent``.
MACHINE_UNIQUENESS_STRATEGIES: frozenset[str] = frozenset(
    {"UNIQUE_PER_LICENSE", "UNIQUE_PER_POLICY", "UNIQUE_PER_ACCOUNT"}
)

#: Heartbeat window applied when ``policy.heartbeat_duration`` is unset, in
#: seconds.
#:
#: This is a *fallback*, not the window. The server computes the effective window
#: as ``heartbeat_duration`` or this value, and the machine-culling job's claim
#: query uses the same ``COALESCE(p.heartbeat_duration, 600)``. Sizing a ping
#: interval against this constant is only correct for a policy that leaves the
#: column null — see ``PolicyResource.effective_heartbeat_window_seconds``.
DEFAULT_HEARTBEAT_DURATION_SECONDS: int = 600


#: Attribute names removed from :class:`PolicyResource` in 1.1.0, still served
#: at runtime by its ``__getattr__`` shim so a ``^1.0`` consumer that reads one
#: keeps working. Scheduled for deletion in 2.0.0.
_REMOVED_PHANTOM_LIMITS: frozenset[str] = frozenset({"max_memory", "max_disk"})

#: Version that deletes the ``__getattr__`` shim above.
_PHANTOM_LIMIT_REMOVAL_VERSION: str = "2.0.0"


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
        heartbeat_duration: The policy's machine-heartbeat window, in seconds,
            or ``None`` when the column is unset. **This is the field that
            decides how often a machine has to ping**; the SDK's 600s default is
            only what the server falls back to when this is ``None``. Read
            ``effective_heartbeat_window_seconds`` rather than this field
            directly, and size a ``HeartbeatScheduler`` from it (see
            ``tamga.client.heartbeat_interval_for_policy``).
        require_heartbeat: Whether the culling worker acts on this policy at
            all. ``False`` by default, and the worker early-returns on a policy
            where it is false, so under a default policy no machine is ever
            culled no matter how long its heartbeat has lapsed. A machine can
            still *report* ``DEAD`` under such a policy — the status is derived
            purely from ``last_heartbeat_at`` versus the window and never
            consults this flag.
        machine_uniqueness_strategy: One of
            ``MACHINE_UNIQUENESS_STRATEGIES``; see that constant for what each
            scope means for ``409 FINGERPRINT_TAKEN``. Defaults to
            ``"UNIQUE_PER_LICENSE"``, which is also what the server treats any
            unrecognized value as.

    Note:
        **``max_memory`` and ``max_disk`` are not modeled.** Both exist as
        columns and both are enforced during validation, but no policy
        serializer ever emits them: the single response shape for this
        resource (``policies/serializer.rs``'s ``PolicyAttributes``) carries
        ``max_machines`` and ``max_cores`` and stops there. They are writable
        through the create/update request bodies and readable nowhere, so a
        read-only client like this one could never populate them — which is
        why the fields this SDK used to carry were documented as "always
        ``None``" for as long as they existed.

        They were dropped from the dataclass in 1.1.0. Reading
        ``policy.max_memory`` or ``policy.max_disk`` still returns ``None`` at
        runtime, with a ``DeprecationWarning``, until they are deleted
        outright in 2.0.0; a type checker reports the attribute as gone today.
        Passing either name to ``PolicyResource(...)`` is a ``TypeError`` as
        of 1.1.0 — a dataclass field cannot be removed from the typed surface
        and kept in the constructor.

        Observing either limit still means watching for a
        ``ValidationCode.TOO_MUCH_MEMORY`` / ``TOO_MUCH_DISK`` result.
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
    heartbeat_duration: int | None = None
    require_heartbeat: bool = False
    machine_uniqueness_strategy: str = "UNIQUE_PER_LICENSE"

    # Deliberately invisible to type checkers. `__getattr__` on a class makes
    # mypy accept *any* attribute name on it, which would erase the very
    # typing this dataclass exists to provide — and would hand a caller still
    # reading `policy.max_memory` no signal at all until 2.0.0 deletes the
    # shim under them. Hiding it inverts that: static analysis reports the
    # attribute as gone now (the actionable, non-fatal warning Python
    # otherwise cannot give on a minor), while the runtime keeps serving the
    # same `None` the field always held.
    if not TYPE_CHECKING:

        def __getattr__(self, name: str) -> None:
            """Serve a removed phantom limit, with a deprecation warning.

            Only reached for names normal attribute lookup did not find, so it
            costs nothing on any real field. Whether a caller sees the warning
            more than once is the interpreter's default dedup-per-location
            filtering, not anything this does.

            Args:
                name: The attribute that was not found on the instance.

            Returns:
                ``None`` for ``max_memory``/``max_disk`` — the value those
                fields carried for their whole existence.

            Raises:
                AttributeError: For every other name, exactly as before.
            """
            if name in _REMOVED_PHANTOM_LIMITS:
                warnings.warn(
                    f"PolicyResource.{name} is deprecated and will be removed in "
                    f"tamga-sdk {_PHANTOM_LIMIT_REMOVAL_VERSION}. No policy "
                    "serializer emits this field, so it was always None and can "
                    "never be anything else; watch for a TOO_MUCH_MEMORY / "
                    "TOO_MUCH_DISK validation code instead.",
                    DeprecationWarning,
                    stacklevel=2,
                )
                return None
            raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    @property
    def effective_heartbeat_window_seconds(self) -> int:
        """The machine-heartbeat window this policy actually enforces, in seconds.

        ``heartbeat_duration`` when the policy sets it, otherwise
        ``DEFAULT_HEARTBEAT_DURATION_SECONDS`` (600). Mirrors the server's own
        ``Policy::effective_heartbeat_duration_secs``, and the same expression
        the culling job's claim query uses.

        Note:
            A non-positive ``heartbeat_duration`` is treated as unset and falls
            back to 600 rather than being propagated. The column is a signed
            integer with no positivity constraint, and a zero or negative window
            would otherwise turn a derived ping interval into a busy loop.

            That is no longer the only thing standing between such a policy and
            a spin — both schedulers hold ``tamga.client.MIN_HEARTBEAT_INTERVAL``
            themselves — but it does mean this SDK never derives an interval
            from a zero window at all. Worth knowing when comparing against the
            server, whose ``COALESCE(p.heartbeat_duration, 600)`` substitutes
            only for ``NULL``: a stored ``0`` really is a zero-second window
            server-side, and no ping rate at or above the floor can hold it.
            See the table in ``tests/test_policy_read.py``.
        """
        if self.heartbeat_duration is None or self.heartbeat_duration <= 0:
            return DEFAULT_HEARTBEAT_DURATION_SECONDS
        return self.heartbeat_duration

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
            heartbeat_duration=attributes.get("heartbeat_duration"),
            require_heartbeat=bool(attributes.get("require_heartbeat", False)),
            machine_uniqueness_strategy=attributes.get(
                "machine_uniqueness_strategy", "UNIQUE_PER_LICENSE"
            ),
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
