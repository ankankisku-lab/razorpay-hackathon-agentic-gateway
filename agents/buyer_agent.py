import time
import uuid
from typing import Any, Dict, Optional

from backend.schemas import CartItem, CartMandate, IntentMandate
from backend.signing import sign_mandate
from config import settings
from retrieval.catalog_retriever import CatalogRetriever


class BuyerAgent:
    """Translates natural-language user intent into signed payment
    mandates backed by deterministic FAISS retrieval and budget math.

    NOTE: returns raw mandate/cart objects and a signature — it does
    NOT construct an ExecutionRequest. That wrapping is IntentLayer's
    job, not this class's.
    """

    def __init__(self, retriever: Optional[CatalogRetriever] = None):
        self.retriever = retriever if retriever is not None else CatalogRetriever()

    def select_product(
        self, query: str, max_budget_paise: int, quantity: int = 1, top_k: int = 3
    ) -> Dict[str, Any]:
        """Picks the highest-scoring match whose TOTAL cost (unit price
        x quantity) fits the budget — not just unit price. See prior
        discussion: checking unit price alone would approve a candidate
        that only fits at quantity=1, skipping a genuinely-fitting
        lower-scored alternative in the same top_k results.
        """
        matches = self.retriever.search(query, top_k=top_k)
        if not matches:
            raise ValueError(f"No catalog matches found for query: '{query}'")

        for item, score in matches:
            # No silent 0 default: a catalog entry missing its price is
            # a data problem worth surfacing immediately, not a "free"
            # item that would pass every budget check by construction
            # and get selected ahead of correctly-priced alternatives.
            if "unit_price_paise" not in item:
                raise ValueError(f"Catalog entry '{item.get('sku')}' is missing unit_price_paise.")
            unit_price = item["unit_price_paise"]
            if unit_price * quantity <= max_budget_paise:
                return {"item": item, "score": score}

        best_item, _ = matches[0]
        raise ValueError(
            f"Best match '{best_item.get('name')}' costs {best_item.get('unit_price_paise')}p x "
            f"{quantity}, exceeding the budget of {max_budget_paise}p."
        )

    def create_mandate(
        self,
        user_prompt: str,
        user_id: str,
        max_budget_paise: int,
        quantity: int = 1,
        query: Optional[str] = None,
        validity_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Builds and signs an IntentMandate and CartMandate.

        query lets a caller (IntentLayer) pass Planner's cleaned-up
        search_query for retrieval while user_prompt stays the raw
        original text used for user_intent_summary — a conversational
        prompt like "can you please find me 2 boAt bassheads and make
        sure it's under 1000 bucks" can drag FAISS similarity down
        versus a clean query, and there's no reason retrieval and
        audit/explainability need to share the same string.

        user_id has no default — see IntentMandate's own docstring for
        why a shared placeholder here would be a real problem, not a
        convenience.
        """
        if validity_seconds is None:
            validity_seconds = settings.mandate_validity_seconds

        search_term = query or user_prompt
        selection = self.select_product(
            search_term, max_budget_paise=max_budget_paise, quantity=quantity
        )
        item = selection["item"]
        sku = item["sku"]
        unit_price = item["unit_price_paise"]
        total_amount = unit_price * quantity

        mandate_id = f"mnd_{uuid.uuid4().hex[:8]}"
        idempotency_key = f"idem_{uuid.uuid4().hex[:12]}"
        cart_id = f"crt_{uuid.uuid4().hex[:6]}"

        cart_item = CartItem(
            sku=sku,
            name=item.get("name", "Unknown Product"),
            quantity=quantity,
            unit_price_paise=unit_price,
            line_total_paise=total_amount,
        )
        cart_mandate = CartMandate(
            cart_id=cart_id,
            mandate_id=mandate_id,
            items=[cart_item],
            total_amount_paise=total_amount,
        )
        intent_mandate = IntentMandate(
            mandate_id=mandate_id,
            user_id=user_id,
            idempotency_key=idempotency_key,
            max_authorized_budget_paise=max_budget_paise,
            expires_at=int(time.time()) + validity_seconds,
            user_intent_summary=user_prompt,
        )

        # Signs mandate + cart together, not the mandate alone — a
        # signature covering only the budget/expiry authorization would
        # still "verify" after the cart contents were swapped for
        # something else entirely, since nothing about which item was
        # actually being purchased was ever part of what got signed.
        signed_payload = {
            "mandate": intent_mandate.model_dump(),
            "cart": cart_mandate.model_dump(),
        }
        signature = sign_mandate(signed_payload)

        return {
            "mandate_id": mandate_id,
            "cart": cart_mandate,
            "mandate": intent_mandate,
            "signature": signature,
            "match_confidence": selection["score"],
        }