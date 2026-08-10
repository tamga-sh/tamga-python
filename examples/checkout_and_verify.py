"""Check out a license both plain and encrypted, and run the full offline verify pipeline.

Run:
    TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_LICENSE_ID=... \
        TAMGA_ED25519_PUBLIC_KEY_B64=... python examples/checkout_and_verify.py
"""

from __future__ import annotations

import base64
import os
from uuid import UUID

from tamga import TamgaClient, TamgaConfig
from tamga.checkout.license_file import LicenseFile


def main() -> None:
    account_id = os.environ["TAMGA_ACCOUNT_ID"]
    host = os.environ.get("TAMGA_HOST", "api.tamga.sh")
    license_id = UUID(os.environ["TAMGA_LICENSE_ID"])

    # The account's Ed25519 public key — 32 raw bytes, base64-encoded here
    # for convenience of passing via an environment variable. Embed this in
    # your application; it's what makes offline verification possible.
    public_key = base64.b64decode(os.environ["TAMGA_ED25519_PUBLIC_KEY_B64"])

    with TamgaClient(TamgaConfig(account_id=account_id, host=host)) as client:
        # Plain (unencrypted) checkout — POST variant, structured resource.
        plain_result = client.licenses.check_out(license_id, encrypt=False)
        assert not isinstance(plain_result, bytes)
        plain_file = LicenseFile.parse(plain_result.certificate)
        plain_license = plain_file.verify(public_key)
        print("Plain checkout verified. License id:", plain_license.id)

        # Encrypted checkout — requires the license's own key string to
        # derive the AES-256-GCM decryption key (naive zero-pad/truncate
        # transform, NOT a KDF — see tamga.crypto.naive_key).
        license_key_string = os.environ["TAMGA_LICENSE_KEY_STRING"]
        encrypted_result = client.licenses.check_out(license_id, encrypt=True)
        assert not isinstance(encrypted_result, bytes)
        encrypted_file = LicenseFile.parse(encrypted_result.certificate)
        encrypted_license = encrypted_file.verify(public_key, license_key=license_key_string)
        print("Encrypted checkout verified. License id:", encrypted_license.id)

        # ttl/expiry are metadata only — never embedded in the signed
        # payload, never re-checked by the server. Expiry enforcement for
        # an offline file is entirely this application's responsibility.
        if encrypted_result.expiry:
            print("Checkout expiry metadata (advisory only):", encrypted_result.expiry)


if __name__ == "__main__":
    main()
