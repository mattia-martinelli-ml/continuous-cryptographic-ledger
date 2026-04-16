import tempfile
from pathlib import Path

from merkle_proof.signer import KeyManager, verify_signature
from merkle_proof.merkle import sha256_hash


def test_sign_and_verify_roundtrip(tmp_path):
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    signer = KeyManager(private_path, public_path)
    payload = sha256_hash("compliance-event")
    signature = signer.sign(payload)
    assert verify_signature(public_path, payload, signature)
    assert signer.public_key_fingerprint() is not None
