import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from config import settings

# The ledger's hash chain proves an entry wasn't altered after the fact
# (tamper-evidence). It doesn't prove who produced it — anyone with
# write access to the process could append. Signing each entry closes
# that gap: only the private-key holder can produce a signature the
# embedded public key will accept, so the signer can't later plausibly
# deny having produced a given entry. That's what makes non-repudiation
# a different, stronger property than tamper-evidence.


def _generate_and_persist_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    settings.signing_private_key_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    settings.signing_private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    # A private key readable by anyone on the machine isn't meaningfully
    # private — restrict to owner read/write.
    os.chmod(settings.signing_private_key_path, 0o600)

    settings.signing_public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    return private_key, public_key


def load_or_create_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Auto-generating on first run is convenient but means the identity
    behind a signature is whatever key existed on this machine at setup
    time — not one backed by an external identity system (a CA, a DID).
    The mechanism is real regardless ("only this key's holder could have
    produced this signature" holds either way) — be ready to explain
    that identity provisioning specifically is out of scope, not the
    non-repudiation property itself.
    """
    if settings.signing_private_key_path.exists():
        private_key = serialization.load_pem_private_key(
            settings.signing_private_key_path.read_bytes(), password=None
        )
        return private_key, private_key.public_key()

    return _generate_and_persist_keypair()


def get_public_key_hex(public_key: Ed25519PublicKey) -> str:
    # Embedding the raw public key in each ledger entry, rather than
    # just a reference to it, means a verifier never needs a separate
    # key-distribution step to check a signature.
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def sign_hash(private_key: Ed25519PrivateKey, digest_hex: str) -> str:
    # Signing the hash, not the whole entry, keeps signatures compact —
    # standard practice once you already have a collision-resistant
    # digest of the content.
    return private_key.sign(digest_hex.encode()).hex()


def verify_hash_signature(public_key: Ed25519PublicKey, digest_hex: str, signature_hex: str) -> bool:
    try:
        public_key.verify(bytes.fromhex(signature_hex), digest_hex.encode())
        return True
    except InvalidSignature:
        return False