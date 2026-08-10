"""Shared pytest fixtures: a mock-transport HTTP client and throwaway keypairs.

These fixtures are test infrastructure, not SDK business logic — they exist
so that Sections B onward can write request/response tests against a
``TamgaClient`` without touching the network, and so that Sections E/F/H's
crypto tests have deterministic, disposable keypairs to sign/verify against.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


@pytest.fixture
def mock_transport_handler() -> Callable[[httpx.Request], httpx.Response]:
    """Default handler for the mock transport: 501, since no real routes are wired yet.

    Individual tests are expected to override this via
    ``httpx.MockTransport(their_own_handler)`` once endpoint implementations
    land; this default only guarantees the fixture machinery itself is
    exercised during scaffold-phase test collection.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(501, json={"errors": [{"code": "NOT_IMPLEMENTED"}]})

    return _handler


@pytest.fixture
def mock_http_client(
    mock_transport_handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.Client:
    """An ``httpx.Client`` backed by ``httpx.MockTransport`` — no real network I/O."""
    return httpx.Client(transport=httpx.MockTransport(mock_transport_handler))


@pytest.fixture
def ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """A throwaway Ed25519 keypair for license-checkout signature tests."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


@pytest.fixture
def rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """A throwaway RSA-2048 keypair for machine-checkout and offline-proof tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture
def ecdsa_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """A throwaway ECDSA P-256 keypair for machine-checkout signature tests."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


@pytest.fixture
def sample_license_key() -> str:
    """A fixed license key string used across naive-key-derivation known-answer tests."""
    return "TEST-LICENSE-KEY-0000-1111-2222-3333"


@pytest.fixture
def sample_fingerprint() -> str:
    """A fixed machine fingerprint used across HKDF known-answer tests."""
    return "test-machine-fingerprint-abc123"


@pytest.fixture
def sample_account_id() -> str:
    """A fixed account UUID string used across client-config and proof-payload tests."""
    return "018f2f3a-0000-7000-8000-000000000001"


@pytest.fixture
def json_api_error_body() -> dict[str, Any]:
    """A canned JSON:API error envelope for ``tamga.errors`` parsing tests."""
    return {
        "errors": [
            {
                "id": "018f2f3a-0000-7000-8000-000000000099",
                "status": "404",
                "code": "NOT_FOUND",
                "title": "Not Found",
                "detail": "The requested resource does not exist.",
                "source": {"pointer": None},
            }
        ]
    }
