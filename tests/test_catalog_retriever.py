import numpy as np
import pytest

from retrieval.catalog_retriever import CatalogRetriever


class DummyModel:
    """Mock encoder returning deterministic 2D unit vectors."""
    def encode(self, texts, convert_to_numpy=True, normalize_embeddings=True):
        vecs = []
        for text in texts:
            if "earphone" in text.lower() or "bass" in text.lower():
                vecs.append([1.0, 0.0])
            else:
                vecs.append([0.0, 1.0])
        return np.array(vecs, dtype=np.float32)


MOCK_CATALOG = {
    "SKU_BOAT_100": {
        "name": "boAt Bassheads 100",
        "brand": "boAt",
        "category": "Audio",
        "description": "Wired earphones with heavy bass",
        "tags": ["earphone", "audio", "bass"],
        "unit_price_paise": 39900,
    },
    "SKU_ANKER_CHG": {
        "name": "Anker 20W Charger",
        "brand": "Anker",
        "category": "Accessories",
        "description": "USB-C wall plug",
        "tags": ["charger", "power"],
        "unit_price_paise": 129900,
    },
}


def test_search_retrieves_correct_sku():
    retriever = CatalogRetriever(model=DummyModel(), catalog=MOCK_CATALOG)
    results = retriever.search("I want heavy bass earphones", top_k=1)

    assert len(results) == 1
    item, score = results[0]
    assert item["sku"] == "SKU_BOAT_100"
    assert score > 0.99


def test_empty_catalog_returns_empty_results():
    retriever = CatalogRetriever(model=DummyModel(), catalog={})
    results = retriever.search("any query", top_k=3)
    assert results == []