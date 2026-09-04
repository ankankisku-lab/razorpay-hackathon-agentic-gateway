import hashlib
import json
from config import settings

# Run as: python -m retrieval.generate_catalog (from project root) — a
# direct `python retrieval/generate_catalog.py` invocation won't find
# `config`, since the project root needs to be on sys.path for that
# import to resolve.

CATALOG_ITEMS = [
    {
        "sku": "SKU_BOAT_100",
        "name": "boAt Bassheads 100 Wired Earphones",
        "category": "Audio",
        "description": "Super extra bass wired in-ear earphones with in-line microphone and tangle-free PVC cable.",
        "unit_price_paise": 39900,
    },
    {
        "sku": "SKU_BOAT_242",
        "name": "boAt Rockerz 242 Bluetooth Sports Earphones",
        "category": "Audio",
        "description": "Sweat and water resistant wireless neckband earphones with 10mm dynamic drivers for gym workouts and running.",
        "unit_price_paise": 99900,
    },
    {
        "sku": "SKU_NOISE_PULSE",
        "name": "Noise ColorFit Pulse Grand Smartwatch",
        "category": "Wearables",
        "description": "Fitness tracking smartwatch with 1.69 inch HD display, 24x7 heart rate monitor, sleep tracking, and IP68 water resistance.",
        "unit_price_paise": 149900,
    },
    {
        "sku": "SKU_SONY_WH1000",
        "name": "Sony WH-1000XM5 Wireless Noise Canceling Headphones",
        "category": "Audio",
        "description": "Flagship over-ear wireless headphones with industry-leading dual processor active noise cancellation and 30-hour battery life.",
        "unit_price_paise": 2999000,
    },
    {
        "sku": "SKU_MI_POWERBANK",
        "name": "Mi 3i 10000mAh Power Bank",
        "category": "Accessories",
        "description": "Fast charging portable power bank with dual USB output, 18W fast charging support, and 12-layer circuit protection.",
        "unit_price_paise": 129900,
    },
]


def compute_integrity_hash(sku: str, unit_price_paise: int) -> str:
    # Must exactly match the formula policy_gate.py's tamper check uses
    # to recompute this hash — any drift breaks every lookup.
    return hashlib.sha256(f"{sku}:{unit_price_paise}".encode()).hexdigest()


def generate_catalog() -> dict:
    # Keyed by SKU, not a flat list — the gate looks up catalog[sku]
    # directly per transaction, so SKUs have to be top-level keys, and
    # each item needs its own hash: tampering one price shouldn't
    # require re-signing (or invalidate the signature of) every other
    # item in the catalog.
    catalog = {}
    for item in CATALOG_ITEMS:
        sku = item["sku"]
        price = item["unit_price_paise"]
        catalog[sku] = {
            **{k: v for k, v in item.items() if k != "sku"},
            "integrity_hash": compute_integrity_hash(sku, price),
        }

    # Recompute every hash right before writing, so a bug in this script
    # can't silently ship a catalog that fails its own check.
    for sku, entry in catalog.items():
        assert entry["integrity_hash"] == compute_integrity_hash(sku, entry["unit_price_paise"])

    settings.catalog_path.parent.mkdir(parents=True, exist_ok=True)
    with open(settings.catalog_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)

    print(f"[+] Catalog written to: {settings.catalog_path}")
    print(f"[+] {len(catalog)} SKUs, each individually hashed")
    return catalog


if __name__ == "__main__":
    generate_catalog()