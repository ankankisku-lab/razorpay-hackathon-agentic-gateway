import hashlib
import json
import time
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from pydantic import ValidationError

from backend.schemas import CartMandate, IntentMandate
from backend.signing import verify_mandate_signature
from config import settings


def load_catalog(path: Path = settings.catalog_path) -> Dict[str, dict]:
    if not path.exists():
        raise FileNotFoundError(f"Catalog file missing at {path}. Run generator first.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class PolicyGate:
    def __init__(
        self,
        session_spend_cap_paise: int = settings.session_spend_cap_paise,
        catalog: Optional[Dict[str, dict]] = None,
    ):
        self.session_spend_cap_paise = session_spend_cap_paise
        self.session_spent_paise = 0
        # Injectable rather than a module-level global — lets a test hand
        # in a synthetic catalog with zero disk I/O, and keeps two gate
        # instances from silently sharing state through a shared global.
        self.catalog = catalog if catalog is not None else load_catalog()
        self.processed_idempotency_keys: Set[str] = set()
        self.reserved_amounts_paise: Dict[str, int] = {}

    def _verify_item_against_catalog(self, sku: str, claimed_unit_price_paise: int) -> Tuple[bool, str, int]:
        if sku not in self.catalog:
            return False, f"CATALOG_REJECT: Unknown SKU '{sku}'.", 0

        entry = self.catalog[sku]
        actual_price = entry["unit_price_paise"]

        computed_hash = hashlib.sha256(f"{sku}:{actual_price}".encode()).hexdigest()
        expected_hash = entry.get("integrity_hash")
        if not expected_hash:
            return False, f"CATALOG_CONFIG_REJECT: Missing integrity hash for '{sku}'.", 0
        if computed_hash != expected_hash:
            return False, f"CATALOG_TAMPER_REJECT: Signature mismatch for '{sku}'.", 0

        if claimed_unit_price_paise != actual_price:
            return False, (
                f"INTEGRITY_REJECT: Price mismatch on '{sku}'. "
                f"Claimed: {claimed_unit_price_paise}p, Actual: {actual_price}p."
            ), 0

        return True, "", actual_price

    def evaluate(self, cart_payload: dict, intent_mandate: dict, signature: Optional[str] = None) -> Tuple[bool, str, dict]:
        # Re-validates regardless of whether the caller already did — a
        # route, an MCP tool call, and a test all reach this differently,
        # so trusting prior validation would make this boundary only as
        # strong as its weakest caller.
        try:
            cart = CartMandate(**cart_payload)
            mandate = IntentMandate(**intent_mandate)
        except ValidationError as e:
            err = e.errors()[0]
            field = ".".join(str(loc) for loc in err.get("loc", []))
            return False, f"SCHEMA_REJECT: Field '{field}' - {err.get('msg')}", {}

        # Verified unconditionally, not `if signature:` — a caller that
        # simply omits the signature must be rejected, not silently let
        # through. verify_mandate_signature already returns False (not
        # a crash) for None or any malformed input, so no special case
        # is needed to make "missing" behave the same as "invalid".
        # Placed before idempotency/expiry/catalog checks deliberately:
        # nothing about an unverified mandate's own fields — including
        # its idempotency_key — should be trusted enough to act on
        # until authenticity is confirmed first.
        signed_payload = {"mandate": mandate.model_dump(), "cart": cart.model_dump()}
        if not verify_mandate_signature(signed_payload, signature):
            return False, "MANDATE_SIGNATURE_TAMPER_REJECT: Mandate signature verification failed — payload altered, forged, or missing.", {}

        idem_key = mandate.idempotency_key

        if idem_key in self.processed_idempotency_keys:
            return False, "IDEMPOTENCY_REJECT: Duplicate or replayed transaction token.", {}

        if mandate.expires_at < int(time.time()):
            return False, f"MANDATE_EXPIRED_REJECT: IntentMandate '{mandate.mandate_id}' has expired.", {}

        # One bad item fails the whole cart — nothing partially executes.
        verified_total_paise = 0
        for item in cart.items:
            ok, reason, actual_price = self._verify_item_against_catalog(item.sku, item.unit_price_paise)
            if not ok:
                return False, reason, {}
            verified_total_paise += actual_price * item.quantity

        # Not an independent check: once every item passes the loop
        # above, this is mathematically forced to hold. Kept as a canary
        # against a future bug in that loop, not a separate defense.
        if verified_total_paise != cart.total_amount_paise:
            return False, (
                f"INTEGRITY_REJECT: Cart total {cart.total_amount_paise}p does not match "
                f"catalog-verified total {verified_total_paise}p."
            ), {}

        if verified_total_paise > mandate.max_authorized_budget_paise:
            return False, (
                f"AP2_BUDGET_REJECT: Order total {verified_total_paise}p exceeds "
                f"mandate ceiling of {mandate.max_authorized_budget_paise}p."
            ), {}

        # Cumulative across the whole session, not just this one order —
        # three separate ₹900 orders under a ₹2,000 mandate each pass
        # individually but must still be caught in aggregate.
        projected_session_total = self.session_spent_paise + verified_total_paise
        if projected_session_total > self.session_spend_cap_paise:
            return False, (
                f"SESSION_CAP_REJECT: Cumulative session spend {projected_session_total}p "
                f"would exceed cap of {self.session_spend_cap_paise}p "
                f"(already spent {self.session_spent_paise}p)."
            ), {}

        # Phase 1 of 2PC: reserve, don't finalize. commit()/rollback()
        # resolve this once the downstream Razorpay outcome is known.
        self.processed_idempotency_keys.add(idem_key)
        self.reserved_amounts_paise[idem_key] = verified_total_paise
        self.session_spent_paise = projected_session_total

        return True, "GATE_APPROVED", {
            "cart_id": cart.cart_id,
            "mandate_id": mandate.mandate_id,
            "verified_total_paise": verified_total_paise,
            "currency": "INR",
        }

    def commit(self, idempotency_key: str) -> bool:
        """Phase 2, success path — finalizes a reservation so it can
        never be rolled back."""
        return self.reserved_amounts_paise.pop(idempotency_key, None) is not None

    def rollback(self, idempotency_key: str) -> bool:
        """Phase 2, confirmed-failure path only — never call this for an
        ambiguous outcome (timeout, unclear response), only when
        Razorpay explicitly declined and nothing was charged.

        Frees the idempotency key, not just the budget: an idempotency
        key exists to make retries of the SAME operation safe, not to
        be a single-use ticket. Since rollback only ever fires when
        we're certain nothing was charged under this key, reusing it for
        an immediate retry is provably safe — burning it here would just
        force a new key on every retry without adding real protection.
        """
        amount_paise = self.reserved_amounts_paise.pop(idempotency_key, None)
        if amount_paise is None:
            return False
        self.processed_idempotency_keys.discard(idempotency_key)
        self.session_spent_paise = max(0, self.session_spent_paise - amount_paise)
        return True