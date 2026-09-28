import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

from pydantic import ValidationError

from backend.catalog_signing import load_public_key, verify_entry
from backend.schemas import CartMandate, IntentMandate
from backend.signing import verify_mandate_signature
from backend.state_store import (
    AWAITING_CONFIRMATION,
    COMMITTED,
    HELD,
    OPEN_STATUSES,
    RESERVED,
    SQLiteStateStore,
)
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
        store: Optional[SQLiteStateStore] = None,
        session_id: str = "default",
    ):
        self.session_spend_cap_paise = session_spend_cap_paise
        # Injectable rather than a module-level global — lets a test hand
        # in a synthetic catalog with zero disk I/O, and keeps two gate
        # instances from silently sharing state through a shared global.
        self.catalog = catalog if catalog is not None else load_catalog()
        self.catalog_public_key = load_public_key()
        # Reservation state lives in the store, not on this object: two
        # gates on the same database file — the API, the MCP server, a
        # second worker, or this process after a restart — see one
        # budget and one set of idempotency keys. The in-memory version
        # lost held reservations on restart and forked the budget between
        # every process that built its own gate.
        self.store = store if store is not None else SQLiteStateStore()
        # A scope, not a single budget: spend is tracked per user within
        # it ("<session_id>:<user_id>"), and the cap applies to each user
        # separately. One shared budget let any one user exhaust the cap
        # for everyone else.
        self.session_id = session_id

    def _user_session(self, user_id: str) -> str:
        return f"{self.session_id}:{user_id}"

    def spent_by(self, user_id: str) -> int:
        return self.store.spent(self._user_session(user_id))

    # Read-only views kept under their old names so callers that inspect
    # gate state (webhook, demo, dashboard, tests) keep working.
    @property
    def session_spent_paise(self) -> int:
        """Total across every user in this scope; see spent_by() for one user."""
        return self.store.spent_in_scope(self.session_id)

    @property
    def reserved_amounts_paise(self) -> Dict[str, int]:
        return self.store.open_amounts(self.session_id)

    @property
    def processed_idempotency_keys(self) -> Set[str]:
        return self.store.all_keys()

    def _verify_item_against_catalog(self, sku: str, claimed_unit_price_paise: int) -> Tuple[bool, str, int]:
        if sku not in self.catalog:
            return False, f"CATALOG_REJECT: Unknown SKU '{sku}'.", 0

        entry = self.catalog[sku]
        actual_price = entry["unit_price_paise"]

        # Merchant Ed25519 signature over the whole entry. The unkeyed
        # sha256("sku:price") it replaces could be recomputed by whoever
        # edited the price — it caught accidents, not attacks.
        if not entry.get("integrity_signature"):
            return False, f"CATALOG_CONFIG_REJECT: Missing catalog signature for '{sku}'.", 0
        if not verify_entry(sku, entry, self.catalog_public_key):
            return False, f"CATALOG_TAMPER_REJECT: Signature mismatch for '{sku}'.", 0

        if claimed_unit_price_paise != actual_price:
            return False, (
                f"INTEGRITY_REJECT: Price mismatch on '{sku}'. "
                f"Claimed: {claimed_unit_price_paise}p, Actual: {actual_price}p."
            ), 0

        return True, "", actual_price

    def evaluate(
        self,
        cart_payload: dict,
        intent_mandate: dict,
        signature: Optional[str] = None,
        *,
        requester_user_id: str,
    ) -> Tuple[bool, str, dict]:
        """requester_user_id is keyword-only and required, deliberately
        not Optional: an optional binding check is one a caller can skip
        by omission — the same failure mode the old `if signature:`
        guard had.
        """
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
        # Placed before every other check deliberately: nothing about an
        # unverified mandate's own fields — including its user_id and
        # idempotency_key — should be trusted enough to act on until
        # authenticity is confirmed first.
        signed_payload = {"mandate": mandate.model_dump(), "cart": cart.model_dump()}
        if not verify_mandate_signature(signed_payload, signature):
            return False, "MANDATE_SIGNATURE_TAMPER_REJECT: Mandate signature verification failed — payload altered, forged, or missing.", {}

        # The mandate's user_id is inside the signed payload, but the
        # request's user_id is not — without this comparison a validly
        # signed mandate issued for User A could be submitted under User
        # B's name and nothing would notice the mismatch.
        # KNOWN LIMITATION: requester_user_id is still caller-asserted —
        # this closes misattribution, not impersonation. That needs real
        # authentication in front of the gate.
        if requester_user_id != mandate.user_id:
            return False, (
                f"USER_BINDING_REJECT: Mandate '{mandate.mandate_id}' was issued for a "
                f"different user than the one submitting it."
            ), {}

        # `<=`, not `<`: expires_at is documented as "invalid at/after
        # this unix timestamp" — the strict comparison accepted a mandate
        # for its entire final second.
        if mandate.expires_at <= int(time.time()):
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

        # Everything above is a pure function of the request and the
        # catalog. Everything below touches shared state, so it's one
        # atomic store call: the idempotency check, the cumulative
        # session-cap check and the reservation happen inside a single
        # BEGIN IMMEDIATE transaction. That serializes concurrent
        # requests across threads AND processes — the threading.Lock it
        # replaces only ever covered threads in one process.
        #
        # Session cap: cumulative across all of this user's orders, not just
        # this one — three separate ₹900 orders under a ₹2,000 mandate
        # each pass individually but must still be caught in aggregate.
        #
        # Phase 1 of 2PC: reserve, don't finalize. commit()/rollback()
        # resolve this once the downstream Razorpay outcome is known.
        outcome, spent_before = self.store.try_reserve(self._user_session(mandate.user_id), self.session_spend_cap_paise, {
            "idempotency_key": mandate.idempotency_key,
            "mandate_id": mandate.mandate_id,
            "cart_id": cart.cart_id,
            "user_id": mandate.user_id,
            "amount_paise": verified_total_paise,
            "currency": "INR",
            "expires_at": mandate.expires_at,
        })
        if outcome == "DUPLICATE":
            return False, "IDEMPOTENCY_REJECT: Duplicate or replayed transaction token.", {}
        if outcome == "CAP_EXCEEDED":
            return False, (
                f"SESSION_CAP_REJECT: Cumulative spend for user '{mandate.user_id}' of "
                f"{spent_before + verified_total_paise}p would exceed the per-user cap of "
                f"{self.session_spend_cap_paise}p (already spent {spent_before}p)."
            ), {}

        return True, "GATE_APPROVED", {
            "cart_id": cart.cart_id,
            "mandate_id": mandate.mandate_id,
            "verified_total_paise": verified_total_paise,
            "currency": "INR",
        }

    def get_reservation(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        return self.store.get(idempotency_key)

    def mark_awaiting_confirmation(self, idempotency_key: str) -> bool:
        """auto_execute=False: park a fresh reservation until a human
        confirms or cancels it (or it expires and the reconciler frees it)."""
        return self.store.transition(idempotency_key, (RESERVED,), AWAITING_CONFIRMATION)

    def claim_for_confirmation(self, idempotency_key: str) -> bool:
        """Atomic AWAITING_CONFIRMATION -> RESERVED. Two concurrent
        confirms of one reservation can't both proceed to Phase 2 — only
        the call that actually moved the row gets True."""
        return self.store.transition(idempotency_key, (AWAITING_CONFIRMATION,), RESERVED)

    def mark_held(self, idempotency_key: str) -> bool:
        """Ambiguous gateway outcome: keep the budget reserved, and make
        the reservation visible to the reconciler."""
        return self.store.transition(idempotency_key, (RESERVED,), HELD)

    def commit(self, idempotency_key: str, order_id: Optional[str] = None) -> bool:
        """Phase 2, success path — finalizes a reservation so it can
        never be rolled back. True only if this call did the committing,
        so a redelivered webhook or a second reconciler can tell it lost
        the race and must not log the outcome twice."""
        return self.store.transition(idempotency_key, (RESERVED, HELD), COMMITTED, order_id=order_id)

    def rollback(self, idempotency_key: str, from_statuses: Tuple[str, ...] = OPEN_STATUSES) -> bool:
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
        return self.store.release(idempotency_key, from_statuses) is not None
