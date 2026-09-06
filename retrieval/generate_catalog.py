"""
retrieval/generate_catalog.py
Generates the grounded 20-item merchant catalog seed dataset, computes dense vector
embeddings using sentence-transformers (all-MiniLM-L6-v2), and builds the
FAISS index serialized for CatalogRetriever.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from config import settings

# ---------------------------------------------------------------------------
# 20 Ground-Truth Catalog Items
# Grounded inventory with realistic integer paise pricing (1 INR = 100 paise).
# ---------------------------------------------------------------------------
CATALOG_ITEMS: List[Dict[str, Any]] = [
    # --- Audio: Wired & Neckbands ---
    {
        "sku": "SKU_BOAT_100",
        "name": "boAt Bassheads 100 Wired Earphones",
        "category": "Audio",
        "unit_price_paise": 39900,  # ₹399.00
        "currency": "INR",
        "stock": 150,
        "description": "Wired in-ear headphones with 10mm dynamic drivers, super extra bass, in-line microphone, and 1.2m tangle-free cable.",
    },
    {
        "sku": "SKU_BOAT_242",
        "name": "boAt Rockerz 242 Bluetooth Neckband",
        "category": "Audio",
        "unit_price_paise": 99900,  # ₹999.00
        "currency": "INR",
        "stock": 80,
        "description": "Wireless bluetooth magnetic sports neckband earphones with IPX5 water and sweat resistance, 6-hour playback, and secure fit ear hooks for running.",
    },
    {
        "sku": "SKU_BOAT_ANC",
        "name": "boAt Nirvana 751 ANC Wireless Headphones",
        "category": "Audio",
        "unit_price_paise": 349900,  # ₹3,499.00
        "currency": "INR",
        "stock": 40,
        "description": "Active noise cancelling over-ear wireless headphones up to 33dB ANC, 65 hours playback, ASAP charge, and plush comfort earcups.",
    },
    {
        "sku": "SKU_SONY_C500",
        "name": "Sony WF-C500 Truly Wireless Earbuds",
        "category": "Audio",
        "unit_price_paise": 599000,  # ₹5,990.00
        "currency": "INR",
        "stock": 35,
        "description": "Compact true wireless Bluetooth earbuds with DSEE sound restoration, 20 hours battery life with charging case, and IPX4 splash resistance.",
    },
    {
        "sku": "SKU_ONEPLUS_BULLETS",
        "name": "OnePlus Bullets Wireless Z2 Neckband",
        "category": "Audio",
        "unit_price_paise": 199900,  # ₹1,999.00
        "currency": "INR",
        "stock": 60,
        "description": "Acoustic neckband earphones with 12.4mm bass drivers, fast warp charging for 20 hours in 10 minutes, and 30 hours total battery life.",
    },
    {
        "sku": "SKU_JBL_C100SI",
        "name": "JBL C100SI In-Ear Wired Headphones",
        "category": "Audio",
        "unit_price_paise": 59900,  # ₹599.00
        "currency": "INR",
        "stock": 120,
        "description": "Lightweight in-ear wired earphones with signature JBL pure bass sound, one-button universal remote with microphone, and angled acoustic tubes.",
    },
    {
        "sku": "SKU_REALME_BUDS_T300",
        "name": "Realme Buds T300 TWS Earbuds",
        "category": "Audio",
        "unit_price_paise": 229900,  # ₹2,299.00
        "currency": "INR",
        "stock": 70,
        "description": "True wireless earbuds featuring 30dB active noise cancellation, 360-degree spatial audio effect, and 40 hours total playback time.",
    },

    # --- Wearables & Smartwatches ---
    {
        "sku": "SKU_NOISE_2",
        "name": "Noise ColorFit Pulse 2 Smartwatch",
        "category": "Wearables",
        "unit_price_paise": 149900,  # ₹1,499.00
        "currency": "INR",
        "stock": 50,
        "description": "1.8 inch TFT LCD smart watch with Bluetooth calling, 550 nits peak brightness, 24/7 heart rate monitor, SpO2, and 60 sports modes.",
    },
    {
        "sku": "SKU_FIREBOLTT_NINJA",
        "name": "Fire-Boltt Ninja Call Pro Plus Smartwatch",
        "category": "Wearables",
        "unit_price_paise": 129900,  # ₹1,299.00
        "currency": "INR",
        "stock": 45,
        "description": "1.83 inch HD display smartwatch featuring Bluetooth calling, AI voice assistance, over 100 workout modes, and IP67 water rating.",
    },
    {
        "sku": "SKU_AMAZFIT_BIP3",
        "name": "Amazfit Bip 3 Pro Fitness Watch",
        "category": "Wearables",
        "unit_price_paise": 399900,  # ₹3,999.00
        "currency": "INR",
        "stock": 25,
        "description": "Fitness tracking smartwatch with 1.69 inch large color display, 4 satellite positioning systems (GPS), 5 ATM water resistance, and 14-day battery.",
    },

    # --- Power Banks & Charging Tech ---
    {
        "sku": "SKU_BOAT_POWER",
        "name": "boAt EnergyShroom PB300 10000mAh Power Bank",
        "category": "Accessories",
        "unit_price_paise": 119900,  # ₹1,199.00
        "currency": "INR",
        "stock": 65,
        "description": "10000mAh lithium-polymer compact portable power bank with dual USB output, 22.5W two-way fast charge, and multi-layer IC protection.",
    },
    {
        "sku": "SKU_MI_POWER_3I",
        "name": "Mi Power Bank 3i 20000mAh",
        "category": "Accessories",
        "unit_price_paise": 214900,  # ₹2,149.00
        "currency": "INR",
        "stock": 40,
        "description": "High capacity 20000mAh battery pack featuring 18W fast charging, triple USB port output, dual input via Type-C and Micro-USB, and smart power management.",
    },
    {
        "sku": "SKU_AMBRANE_MAGCLICK",
        "name": "Ambrane 10000mAh Magnetic Wireless Power Bank",
        "category": "Accessories",
        "unit_price_paise": 189900,  # ₹1,899.00
        "currency": "INR",
        "stock": 30,
        "description": "MagSafe compatible wireless charging power bank for iPhone with 15W wireless output, 20W PD wired fast charging, and built-in kickstand.",
    },

    # --- Cables & Fast Chargers ---
    {
        "sku": "SKU_BOAT_CABLE",
        "name": "boAt Rugged v3 Type-C Fast Charging Cable",
        "category": "Accessories",
        "unit_price_paise": 29900,  # ₹299.00
        "currency": "INR",
        "stock": 200,
        "description": "1 meter heavy-duty nylon braided USB to Type-C fast charging cable supporting 3A rapid data sync and unbreakable connector heads.",
    },
    {
        "sku": "SKU_ANKER_65W_GAN",
        "name": "Anker Nano II 65W GaN Fast Charger",
        "category": "Accessories",
        "unit_price_paise": 349900,  # ₹3,499.00
        "currency": "INR",
        "stock": 35,
        "description": "Ultra-compact Gallium Nitride (GaN) USB-C fast wall charger capable of powering high-end laptops, MacBooks, tablets, and smartphones at full 65W speed.",
    },
    {
        "sku": "SKU_PORT_LIGHTNING_CABLE",
        "name": "Portronics Konnect CL Type-C to Lightning Cable",
        "category": "Accessories",
        "unit_price_paise": 44900,  # ₹449.00
        "currency": "INR",
        "stock": 110,
        "description": "MFi certified 1.2 meter Type-C to Lightning fast charging cable supporting Power Delivery 20W for iPhone and iPad with 480Mbps data transfer.",
    },
    {
        "sku": "SKU_BOAT_65W_CHARGER",
        "name": "boAt Dual Port 65W GaN Wall Adapter",
        "category": "Accessories",
        "unit_price_paise": 199900,  # ₹1,999.00
        "currency": "INR",
        "stock": 55,
        "description": "Dual-port wall adapter with 1 USB-C and 1 USB-A port, GaN technology, power distribution, and multi-layered surge protection for laptops and phones.",
    },

    # --- Computing & Desk Peripherals ---
    {
        "sku": "SKU_LOGI_PEBBLE_MOUSE",
        "name": "Logitech Pebble M350 Silent Bluetooth Mouse",
        "category": "Peripherals",
        "unit_price_paise": 159500,  # ₹1,595.00
        "currency": "INR",
        "stock": 45,
        "description": "Slim, silent wireless mouse with dual Bluetooth and 2.4GHz USB receiver connectivity, long 18-month battery life, and ultra-quiet clicking.",
    },
    {
        "sku": "SKU_LOGI_K380_KEYBOARD",
        "name": "Logitech K380 Multi-Device Bluetooth Keyboard",
        "category": "Peripherals",
        "unit_price_paise": 289500,  # ₹2,895.00
        "currency": "INR",
        "stock": 30,
        "description": "Compact wireless keyboard with multi-device easy-switch pairing for up to 3 devices across Windows, Mac, iPad, and Android with rounded scissor keys.",
    },
    {
        "sku": "SKU_PORT_LAPTOP_STAND",
        "name": "Portronics My Buddy K Portable Aluminum Laptop Stand",
        "category": "Peripherals",
        "unit_price_paise": 69900,  # ₹699.00
        "currency": "INR",
        "stock": 90,
        "description": "Foldable aluminum alloy ergonomic laptop riser with adjustable height levels, anti-slip silicone pads, and heat dissipation hollow design for 11-17 inch laptops.",
    },
]


def build_embedding_text(item: Dict[str, Any]) -> str:
    """Builds a rich semantic document representation for vector indexing."""
    return f"{item['name']}. Category: {item['category']}. {item['description']}"


def _compute_integrity_hash(sku: str, unit_price_paise: int) -> str:
    """Must match backend/policy_gate.py's verification formula exactly —
    sha256(f"{sku}:{unit_price_paise}") — or every transaction fails
    with CATALOG_TAMPER_REJECT before any other check even runs. This
    is computed here, once, at catalog-generation time, rather than
    duplicated logic living in two places that could drift apart.
    """
    return hashlib.sha256(f"{sku}:{unit_price_paise}".encode()).hexdigest()


def build_catalog_and_index(
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
):
    # catalog.json and catalog.index deliberately do NOT share one
    # output_dir — settings.catalog_path lives under backend/,
    # settings.index_path lives under retrieval/. load_catalog() reads
    # from settings.catalog_path specifically; writing both files to
    # the same folder means the catalog ends up somewhere PolicyGate
    # never looks, failing with FileNotFoundError at first use.
    catalog_file = settings.catalog_path
    index_file = settings.index_path
    catalog_file.parent.mkdir(parents=True, exist_ok=True)
    index_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Initializing encoder: {model_name}...")
    model = SentenceTransformer(model_name)

    print(f"[*] Preparing {len(CATALOG_ITEMS)} catalog documents...")
    corpus = [build_embedding_text(item) for item in CATALOG_ITEMS]

    embeddings = model.encode(corpus, convert_to_numpy=True, show_progress_bar=True)

    faiss.normalize_L2(embeddings)
    dim = embeddings.shape[1]

    print(f"[*] Constructing FAISS IndexFlatIP (dim={dim})...")
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings.astype(np.float32))

    faiss.write_index(index, str(index_file))
    print(f"[+] Serialized FAISS index -> {index_file} ({index.ntotal} vectors)")

    # SKU-keyed dict, NOT a list — backend/policy_gate.py's load_catalog()
    # does a plain json.load() and every caller does catalog[sku] lookups
    # directly. A list here breaks with "list indices must be integers,
    # not str" the moment anything looks up an item — this is the exact
    # bug this project hit and fixed at the very start of the build.
    # Each entry also gets integrity_hash added, computed with the same
    # formula PolicyGate verifies against — without it, every single
    # transaction is rejected with CATALOG_CONFIG_REJECT before price or
    # budget is ever checked.
    catalog_dict: Dict[str, Dict[str, Any]] = {}
    for item in CATALOG_ITEMS:
        entry = dict(item)
        entry["integrity_hash"] = _compute_integrity_hash(item["sku"], item["unit_price_paise"])
        catalog_dict[item["sku"]] = entry

    with open(catalog_file, "w", encoding="utf-8") as f:
        json.dump(catalog_dict, f, indent=2)
    print(f"[+] Serialized Catalog JSON (SKU-keyed dict, with integrity_hash) -> {catalog_file}")

    print("\n[SUCCESS] 20-item grounded catalog and vector index generated successfully.")


if __name__ == "__main__":
    build_catalog_and_index()