"""HTTP transport: base URL construction, auth transports, and header handling.

Base URL shape: ``https://<host>/v1/accounts/{account_id}/...`` —
``{account_id}`` is always required, in both singleplayer and multiplayer
server modes.

Auth transports, in the order the server tries them (SDK defaults to the
first — ``Bearer``):

1. ``Authorization: Bearer <token>``
2. ``Authorization: Basic <base64>`` — 3 sub-forms: ``email:password``,
   ``token:`` (token as username, empty password), ``license:<key>``
3. ``Authorization: License <key>`` — primary transport for
   embedded/client SDKs validating against a raw license key
4. ``Cookie: Tamga-Session=<uuid>`` — browser/portal only, requires a
   matching ``Origin`` header. **Not implemented** in this SDK — it targets
   non-browser embedded apps.
5. ``?token=``/``?auth=`` query parameter

Every issued token gets the ``tok-`` prefix regardless of documented type —
do not build prefix-based token type detection; treat all tokens as opaque
strings.

Not implemented server-side, do not build against: ``Tamga-Environment``
request header (planned EE feature); ``X-RateLimit-*`` response headers /
``429`` responses (declared in the CORS allowlist only, never set).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Union

import httpx  # noqa: F401

DEFAULT_TIMEOUT_SECONDS: float = 30.0
"""Default connect/read timeout for the underlying httpx.Client."""

MAX_TAMGA_VERSION_LENGTH: int = 32
"""Server-side max length for the sanitized ``Tamga-Version`` header value."""


def build_base_url(host: str, account_id: str) -> str:
    """Build the account-scoped base URL: ``https://<host>/v1/accounts/{account_id}``.

    Args:
        host: API host, without scheme (e.g. ``"api.tamga.sh"``).
        account_id: Account ID or code — always required, singleplayer and
            multiplayer alike.

    Returns:
        The fully-qualified base URL, with no trailing slash.
    """
    raise NotImplementedError


def sanitize_tamga_version(version: str) -> str:
    """Sanitize a ``Tamga-Version`` header value client-side.

    Server accepts alphanumeric + ``.``/``-``, max 32 chars.

    Args:
        version: The raw version string to sanitize.

    Returns:
        The sanitized version string.

    Raises:
        ValueError: If ``version`` cannot be sanitized into a valid value
            (e.g. empty after stripping disallowed characters).
    """
    raise NotImplementedError


@dataclass(frozen=True)
class BearerAuth:
    """``Authorization: Bearer <token>`` — the SDK default."""

    token: str


@dataclass(frozen=True)
class BasicAuth:
    """``Authorization: Basic <base64>``, one of three sub-forms.

    Attributes:
        email: Set together with ``password`` for the ``email:password`` sub-form.
        password: Set together with ``email``, or left empty for the ``token:`` sub-form.
        token: Set alone for the ``token:`` sub-form (token as username, empty password).
        license_key: Set alone for the ``license:<key>`` sub-form.
    """

    email: str | None = None
    password: str | None = None
    token: str | None = None
    license_key: str | None = None


@dataclass(frozen=True)
class LicenseAuth:
    """``Authorization: License <key>`` — primary transport for embedded/client SDKs."""

    key: str


@dataclass(frozen=True)
class QueryParamAuth:
    """``?token=``/``?auth=`` query parameter auth."""

    value: str
    param_name: str = "token"


AuthTransport = Union[BearerAuth, BasicAuth, LicenseAuth, QueryParamAuth]
"""Union of supported auth transports. Session-cookie auth (browser/portal-only)
is intentionally not modeled here.

Note: built with ``typing.Union`` rather than the ``X | Y`` PEP 604 syntax
because this is a runtime type-alias *assignment*, not an annotation — the
module's ``from __future__ import annotations`` only defers evaluation of
annotations, not this statement, and this SDK supports Python 3.9 (no
``|`` union operator on types until 3.10).
"""


def apply_auth(
    request_headers: dict[str, str],
    request_params: dict[str, Any],
    auth: AuthTransport,
) -> None:
    """Mutate ``request_headers``/``request_params`` in place to attach ``auth``.

    Args:
        request_headers: Header dict to add the auth header to, if applicable.
        request_params: Query-param dict to add the auth param to, if applicable.
        auth: The auth transport to apply.
    """
    raise NotImplementedError


@dataclass(frozen=True)
class TamgaResponse:
    """Wraps a parsed response body with the response headers callers may want to read.

    Attributes:
        data: The parsed JSON body (already unwrapped from the JSON:API
            envelope where applicable, or the flat quick-validate body).
        tamga_version: Echoed ``Tamga-Version`` response header.
        tamga_edition: ``"EE"`` or ``"CE"``, from the ``Tamga-Edition`` response header.
        tamga_mode: ``"singleplayer"`` or ``"multiplayer"``, from the ``Tamga-Mode`` header.
        request_id: ``X-Request-Id`` response header, useful to log for support.
    """

    data: Any
    tamga_version: str | None
    tamga_edition: str | None
    tamga_mode: str | None
    request_id: str | None


def parse_response(response: httpx.Response, *, is_quick_validate: bool = False) -> TamgaResponse:
    """Parse an httpx response into a ``TamgaResponse``.

    Special-cases the quick-validate endpoint
    (``GET .../licenses/{id}/actions/validate``), which returns plain
    ``application/json`` with a flat ``{ts, valid, detail, code}`` body — no
    ``data`` envelope — unlike every other endpoint's
    ``application/vnd.api+json`` JSON:API response.

    Args:
        response: The raw httpx response.
        is_quick_validate: Whether this response is from the quick-validate
            endpoint, to select the correct parsing path.

    Returns:
        The parsed ``TamgaResponse``.

    Raises:
        tamga.errors.TamgaError: If the response status indicates an error;
            see ``tamga.errors.parse_error_envelope``.
    """
    raise NotImplementedError
