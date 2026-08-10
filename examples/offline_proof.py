"""Air-gapped machine offline proof: generate online once, verify fully offline later.

Lighter-weight alternative to full machine checkout for periodic "prove this
machine is still valid" pings in air-gapped environments. Always signed with
RSA-2048 PKCS#1 v1.5 / SHA-256 server-side, regardless of the license's own
signing scheme.

Run:
    TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_MACHINE_ID=... \
        TAMGA_RSA_PUBLIC_KEY_DER_B64=... python examples/offline_proof.py
"""

from __future__ import annotations

import base64
import os
from uuid import UUID

from tamga import TamgaClient, TamgaConfig


def main() -> None:
    account_id = os.environ["TAMGA_ACCOUNT_ID"]
    host = os.environ.get("TAMGA_HOST", "api.tamga.sh")
    machine_id = UUID(os.environ["TAMGA_MACHINE_ID"])

    # The account's RSA-2048 public key, SubjectPublicKeyInfo DER,
    # base64-encoded here for convenience. Embed the raw DER bytes in your
    # application for fully offline verification later.
    public_key_der = base64.b64decode(os.environ["TAMGA_RSA_PUBLIC_KEY_DER_B64"])

    with TamgaClient(TamgaConfig(account_id=account_id, host=host)) as client:
        # Online step: generate the proof (requires network access once).
        dataset = {"cores": os.cpu_count(), "checked_at": "startup"}
        proof = client.machines.generate_offline_proof(machine_id, dataset=dataset)
        print("Generated proof:", proof.raw[:20], "...")

        # Offline step: verify the proof against the embedded public key.
        # No network access needed here — this is the whole point.
        is_valid = proof.verify(public_key_der)
        print("Proof verifies:", is_valid)


if __name__ == "__main__":
    main()
