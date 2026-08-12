"""Shared PEM-envelope parsing for ``.lic``/machine-file certificates.

Internal helper module — not part of the public API. Both
``tamga.checkout.license_file`` and ``tamga.checkout.machine_file`` wrap the
same outer ``-----BEGIN ...-----`` / ``{enc, sig, alg}`` JSON / ``-----END
...-----`` envelope and differ only in scheme dispatch and key derivation,
so the envelope-parsing pipeline itself lives here once.
"""

from __future__ import annotations

import base64
import binascii
import json

#: Sanity guard against an absurd/corrupted certificate body -- real
#: license/machine files are a few KB at most. Generous enough not to
#: reject any legitimate metadata/entitlements payload.
_MAX_CERTIFICATE_LENGTH = 1024 * 1024  # 1 MiB


def parse_certificate_envelope(
    certificate: str, header: str, footer: str
) -> tuple[str, bytes, str]:
    """Strip PEM markers, base64-decode, and parse the inner ``{enc, sig, alg}`` JSON.

    Args:
        certificate: The full certificate string, including PEM markers.
        header: Expected PEM header line (e.g. ``"-----BEGIN LICENSE FILE-----"``).
        footer: Expected PEM footer line.

    Returns:
        ``(enc, sig_bytes, alg)`` — ``enc`` and ``alg`` as strings, ``sig``
        already base64-decoded to raw bytes.

    Raises:
        ValueError: On malformed PEM markers, invalid base64, invalid JSON,
            or a body missing one of the required ``{enc, sig, alg}`` keys.
    """
    stripped = certificate.strip()
    if len(stripped) > _MAX_CERTIFICATE_LENGTH:
        raise ValueError(
            f"malformed certificate: too large ({len(stripped)} bytes, "
            f"max {_MAX_CERTIFICATE_LENGTH})"
        )
    if not (stripped.startswith(header) and stripped.endswith(footer)):
        raise ValueError(f"malformed certificate: expected {header!r}/{footer!r} PEM markers")
    # SECURITY: without this check, a crafted string where header/footer
    # text overlaps (shorter than len(header) + len(footer), but still
    # satisfying both startswith/endswith independently) produces a
    # negative-length slice below -- Python slicing doesn't raise on that,
    # it silently returns an empty body, which only fails several steps
    # later with a confusing "not valid JSON" message instead of pinpointing
    # the actual truncation. Found via audit; see
    # tests/test_checkout_hardening.py for the regression coverage. Same
    # underlying edge-case shape as tamga-dotnet's PemEnvelope fix (8fa11a5).
    if len(stripped) < len(header) + len(footer):
        raise ValueError("malformed certificate: too short to contain both PEM markers")
    body = stripped[len(header) : len(stripped) - len(footer)].strip()

    try:
        cert_json_bytes = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("malformed certificate: PEM body is not valid base64") from exc

    try:
        cert = json.loads(cert_json_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError("malformed certificate: PEM body is not valid JSON") from exc

    if not isinstance(cert, dict) or not all(k in cert for k in ("enc", "sig", "alg")):
        raise ValueError("malformed certificate: expected {enc, sig, alg} JSON object")

    enc = cert["enc"]
    alg = cert["alg"]
    if not isinstance(enc, str) or not isinstance(alg, str):
        raise ValueError("malformed certificate: 'enc' and 'alg' must be strings")

    try:
        sig_bytes = base64.b64decode(cert["sig"], validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise ValueError("malformed certificate: 'sig' is not valid base64") from exc

    return enc, sig_bytes, alg
