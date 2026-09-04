from typing import Any, Dict, List, Optional, Tuple

import faiss
import numpy as np

from backend.policy_gate import load_catalog

MODEL_NAME = "all-MiniLM-L6-v2"


class CatalogRetriever:
    """Encodes catalog items and performs dense semantic vector search
    using a normalized Inner Product (cosine similarity) FAISS index.
    """

    def __init__(
        self,
        model_name: str = MODEL_NAME,
        model: Optional[Any] = None,
        catalog: Optional[Dict[str, dict]] = None,
    ):
        # Injectable, same reasoning as PolicyGate's catalog parameter:
        # a test can hand in a lightweight fake implementing .encode(),
        # instead of paying for a real SentenceTransformer + torch load
        # on every test run.
        if model is not None:
            self.model = model
        else:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(model_name)

        self.catalog = catalog if catalog is not None else load_catalog()
        self.sku_lookup: List[str] = []
        self.index: Optional[faiss.IndexFlatIP] = None
        self._build_index()

    def _build_index(self) -> None:
        # Without this, an empty catalog reaches model.encode([]) — many
        # encoders return a bare 1-D array for empty input rather than
        # shape (0, dim), and embeddings.shape[1] then raises IndexError.
        if not self.catalog:
            self.index = None
            self.sku_lookup = []
            return

        texts: List[str] = []
        self.sku_lookup = []
        for sku, item in self.catalog.items():
            name = item.get("name", "")
            brand = item.get("brand", "")
            category = item.get("category", "")
            description = item.get("description", "")
            tags = " ".join(item.get("tags", []))
            rich_text = (
                f"Product: {name} | Brand: {brand} | Category: {category} | "
                f"Description: {description} | Tags: {tags}"
            )
            texts.append(rich_text)
            self.sku_lookup.append(sku)

        embeddings = self.model.encode(
            texts, convert_to_numpy=True, normalize_embeddings=True
        )
        dimension = embeddings.shape[1]
        # Inner product on unit-normalized vectors equals cosine similarity.
        self.index = faiss.IndexFlatIP(dimension)
        self.index.add(embeddings.astype(np.float32))

    def search(self, query: str, top_k: int = 3) -> List[Tuple[Dict[str, Any], float]]:
        """Searches the catalog for the top-k matches against a natural language query."""
        if not self.index or self.index.ntotal == 0:
            return []
        query_vec = self.model.encode(
            [query], convert_to_numpy=True, normalize_embeddings=True
        )
        scores, indices = self.index.search(query_vec.astype(np.float32), top_k)
        results: List[Tuple[Dict[str, Any], float]] = []
        for idx, score in zip(indices[0], scores[0]):
            if idx == -1:
                continue
            sku = self.sku_lookup[idx]
            item_data = dict(self.catalog[sku])
            item_data["sku"] = sku
            results.append((item_data, float(score)))
        return results