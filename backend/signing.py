import hashlib
import json
import os
from typing import Any, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from config import settings

# The ledger's hash chain proves an entry wasn't altered after the fact
# (tamper-evidence). It doesn't prove who produced it — anyone with
# write access to the process could append. Signing each entry closes
# that gap: only the private-key holder can produce a signature the
# embedded public key will accept, so the signer can't later plausibly
# deny having produced a given entry. That's what makes non-repudiation
# a different, stronger property than tamper-evidence.


def _generate_and_persist_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
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
    # private — restrict to owner read/write. Best-effort on Windows,
    # where POSIX chmod bits don't map cleanly onto ACLs.
    try:
        os.chmod(settings.signing_private_key_path, 0o600)
    except OSError:
        pass

    settings.signing_public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    return private_key, public_key


def load_or_create_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
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


def get_public_key_hex(public_key: Optional[Ed25519PublicKey] = None) -> str:
    """public_key defaults to None (loads the current on-disk key) so
    this can be called either as get_public_key_hex(known_key) or
    get_public_key_hex() when the caller doesn't already have one."""
    if public_key is None:
        _, public_key = load_or_create_keypair()
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def sign_hash(digest_or_priv: Any, digest_hex: Optional[str] = None) -> str:
    """Supports both sign_hash(private_key, digest_hex) — ledger.py's
    style, which passes an already-loaded key to avoid a disk read per
    signature — and sign_hash(digest_hex) alone, which loads the key
    internally. Two call sites, two conventions, one function, rather
    than forcing every caller onto whichever style came first.
    """
    if digest_hex is not None:
        private_key = digest_or_priv
        target_digest = digest_hex
    elif isinstance(digest_or_priv, Ed25519PrivateKey):
        raise ValueError("digest_hex must be provided when passing a private key.")
    else:
        private_key, _ = load_or_create_keypair()
        target_digest = digest_or_priv

    return private_key.sign(target_digest.encode()).hex()


def verify_hash_signature(
    pub_or_digest: Any,
    digest_or_sig: str,
    signature_hex: Optional[str] = None,
) -> bool:
    """Supports both verify_hash_signature(public_key, digest_hex, sig) —
    ledger.py's style, which verifies against the SPECIFIC key embedded
    in a historical entry rather than whatever key is on disk today
    (what makes verification key-rotation-safe) — and
    verify_hash_signature(digest_hex, sig) alone, which always checks
    against the current on-disk key.
    """
    if signature_hex is not None:
        public_key = pub_or_digest
        digest_hex = digest_or_sig
        sig = signature_hex
    else:
        _, public_key = load_or_create_keypair()
        digest_hex = pub_or_digest
        sig = digest_or_sig

    try:
        public_key.verify(bytes.fromhex(sig), digest_hex.encode())
        return True
    except InvalidSignature:
        return False


def sign_mandate(mandate_dict: dict) -> str:
    """Signs a canonical JSON representation of a mandate.

    Reuses the SAME keypair as the ledger's own signing — this is one
    signing identity for the whole backend, not a separate per-role
    identity. In a fully rigorous AP2-style design, the party
    authorizing a mandate (the buyer/agent) and the party attesting to
    the audit trail (the merchant's ledger) are different roles that
    would hold different keys. Conflating them here is a real scope
    simplification, not an oversight — worth stating plainly if asked,
    same as load_or_create_keypair's own disclosed limitation.

    Also worth knowing: nothing in backend/schemas.py or
    backend/policy_gate.py currently VERIFIES a mandate signature —
    IntentMandate has no signature field, and evaluate() never checks
    one. Signing without a verification consumer doesn't add a security
    guarantee by itself; it's only meaningful once something downstream
    actually checks it before trusting the mandate.
    """
    private_key, _ = load_or_create_keypair()
    canonical = json.dumps(mandate_dict, sort_keys=True, default=str)
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return sign_hash(private_key, digest)