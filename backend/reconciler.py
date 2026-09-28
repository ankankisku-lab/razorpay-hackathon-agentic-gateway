import time
from typing import Dict, Optional

from backend.exceptions import RazorpayAmbiguousError
from backend.ledger import build_entry, write_ledger_entry
from backend.razorpay_gateway import build_receipt, find_orders_by_receipt
from backend.state_store import AWAITING_CONFIRMATION, HELD
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from config import settings


def reconcile_once(
    coordinator: TwoPhaseCommitCoordinator,
    now: Optional[float] = None,
    held_grace_seconds: Optional[int] = None,
) -> Dict[str, int]:
    """One pass over every reservation that can't resolve itself.

    HELD (ambiguous timeout / 5xx): webhooks were the only way these
    ever got resolved, and a webhook that never arrives left the budget
    reserved forever. Here the gateway asks Razorpay directly, by the
    same deterministic receipt the order was created with:
      - order found           -> commit. The synchronous path treats
        order creation as success, so a late-visible order must resolve
        exactly the way a timely one would have.
      - no order, past grace  -> release. The create call never landed.
      - no order, within grace-> leave held; it may not be visible yet.
      - lookup failed         -> leave held. "Couldn't ask" is never
        treated as "no order".

    AWAITING_CONFIRMATION past its mandate's expiry: nobody confirmed in
    time and nobody ever can (confirm re-checks expiry), so the reserved
    budget is released.

    Safe to run from several workers at once: every resolution goes
    through a conditional state transition, and only the worker whose
    transition actually happened writes the ledger entry.
    """
    now = time.time() if now is None else now
    grace = settings.held_order_grace_seconds if held_grace_seconds is None else held_grace_seconds
    gate = coordinator.policy_gate
    counts = {"committed": 0, "released": 0, "still_held": 0, "lookup_failed": 0, "expired_confirmations": 0}

    for res in gate.store.list_by_status(HELD):
        key, mandate_id = res["idempotency_key"], res["mandate_id"]
        try:
            orders = find_orders_by_receipt(build_receipt(mandate_id, key))
        except RazorpayAmbiguousError:
            counts["lookup_failed"] += 1
            continue

        if orders:
            order_id = orders[0]["id"]
            if gate.commit(key, order_id=order_id):
                write_ledger_entry(build_entry(
                    mandate_id, "RECONCILED_ORDER_FOUND_COMMITTED",
                    order_id=order_id, amount_paise=res["amount_paise"],
                ))
                counts["committed"] += 1
        elif now - res["updated_at"] >= grace:
            if gate.rollback(key, (HELD,)):
                write_ledger_entry(build_entry(
                    mandate_id, "RECONCILED_NO_ORDER_RELEASED",
                    amount_paise=res["amount_paise"],
                    reason=f"No order with this receipt after {int(now - res['updated_at'])}s held.",
                ))
                counts["released"] += 1
        else:
            counts["still_held"] += 1

    for res in gate.store.list_by_status(AWAITING_CONFIRMATION):
        if res["expires_at"] <= now and gate.rollback(res["idempotency_key"], (AWAITING_CONFIRMATION,)):
            write_ledger_entry(build_entry(
                res["mandate_id"], "CONFIRMATION_EXPIRED_RELEASED",
                amount_paise=res["amount_paise"],
            ))
            counts["expired_confirmations"] += 1

    return counts
