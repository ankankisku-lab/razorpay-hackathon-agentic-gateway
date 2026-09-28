"""Merchant signatures over catalog entries.

Replaces integrity_hash = sha256("sku:price"). That hash was unkeyed:
anyone able to edit a price in catalog.json could recompute it, so it
caught accidental edits but not deliberate ones. An Ed25519 signature
needs the merchant's private key, which never ships with the catalog.

Each signature covers the WHOLE entry (every field except the signature
itself), not just sku and price: descriptions are fed to the LLM in
LLMSelectionIntentLayer, so an unsigned description would be an easy
channel for indirect prompt injection.

Re-sign after editing the catalog:  python -m backend.catalog_signing
"""
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from config import settings

SIGNATURE_FIELD = "integrity_signature"


def entry_message(sku: str, entry: Dict[str, Any]) -> bytes:
    """Canonical bytes to sign. The dict key (sku) is included explicitly
    so a validly signed entry can't be moved under a different SKU."""
    body = {k: v for k, v in entry.items() if k not in (SIGNATURE_FIELD, "integrity_hash")}
    return json.dumps({"catalog_key": sku, "entry": body}, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_public_key(path: Optional[Path] = None) -> Ed25519PublicKey:
    path = path or settings.catalog_public_key_path
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(Path(path).read_text().strip()))


def verify_entry(sku: str, entry: Dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    signature = entry.get(SIGNATURE_FIELD)
    if not isinstance(signature, str):
        return False
    try:
        public_key.verify(bytes.fromhex(signature), entry_message(sku, entry))
        return True
    except (InvalidSignature, ValueError):
        return False


def _load_or_create_private_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def sign_catalog(catalog: Dict[str, Dict[str, Any]], private_key: Ed25519PrivateKey) -> Dict[str, Dict[str, Any]]:
    signed = {}
    for sku, entry in catalog.items():
        clean = {k: v for k, v in entry.items() if k not in (SIGNATURE_FIELD, "integrity_hash")}
        clean[SIGNATURE_FIELD] = private_key.sign(entry_message(sku, clean)).hex()
        signed[sku] = clean
    return signed


def sign_catalog_file(
    catalog_path: Optional[Path] = None,
    private_key_path: Optional[Path] = None,
    public_key_path: Optional[Path] = None,
) -> int:
    catalog_path = Path(catalog_path or settings.catalog_path)
    private_key = _load_or_create_private_key(Path(private_key_path or settings.catalog_signing_private_key_path))
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog_path.write_text(json.dumps(sign_catalog(catalog, private_key), indent=2) + "\n", encoding="utf-8")
    public_hex = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()
    Path(public_key_path or settings.catalog_public_key_path).write_text(public_hex + "\n")
    return len(catalog)


if __name__ == "__main__":
    count = sign_catalog_file()
    print(f"Signed {count} catalog entries; public key -> {settings.catalog_public_key_path}")
