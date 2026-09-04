import hashlib
import hmac
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request

from backend.ledger import build_entry, write_ledger_entry
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from config import settings

# Razorpay signs the raw request body with your webhook secret using
# HMAC-SHA256, sent in the X-Razorpay-Signature header. Two rules
# enforced via the stdlib hmac module, not hand-rolled:
#   1. hmac.new(...) computes the HMAC — never reimplement HMAC's
#      inner/outer padding construction by hand.
#   2. hmac.compare_digest(...) compares — never `==`. A plain
#      comparison short-circuits on the first mismatched byte, leaking
#      timing information an attacker could use to forge a signature
#      one byte at a time.


def verify_webhook_signature(raw_body: bytes, received_signature: str) -> bool:
    """raw_body MUST be the exact, unparsed request bytes — even a
    whitespace or key-ordering difference from a re-serialized version
    produces a different HMAC and a false rejection."""
    expected = hmac.new(
        key=settings.razorpay_webhook_secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, received_signature)


def create_webhook_router(coordinator: TwoPhaseCommitCoordinator) -> APIRouter:
    """Takes the coordinator as a parameter rather than constructing its
    own, so this router closes over the exact same PolicyGate instance
    the rest of the app uses — two separately-instantiated gates would
    silently fork reservation state between the synchronous purchase
    path and this reconciliation path.
    """
    router = APIRouter()

    @router.post("/api/v1/webhooks/razorpay")
    async def razorpay_webhook(request: Request) -> Dict[str, Any]:
        raw_body = await request.body()
        signature = request.headers.get("X-Razorpay-Signature", "")

        if not signature or not verify_webhook_signature(raw_body, signature):
            raise HTTPException(status_code=400, detail="Invalid webhook signature")

        payload = await request.json()
        event_type = payload.get("event", "")

        payload_data = payload.get("payload", {})
        order_entity = payload_data.get("order", {}).get("entity", {})
        payment_entity = payload_data.get("payment", {}).get("entity", {})

        # `or {}`, not `.get(key, {})` — Razorpay can send an explicit
        # "notes": null rather than omitting the key, and dict.get's
        # default only applies when the key is MISSING, not when it's
        # present with a None value. Order notes take precedence (we
        # set them at order-creation time); payment notes are a
        # fallback for payload shapes where they're populated instead.
        notes = {
            **(payment_entity.get("notes") or {}),
            **(order_entity.get("notes") or {}),
        }

        idem_key = notes.get("idempotency_key")
        mandate_id = notes.get("mandate_id", "UNKNOWN")
        order_id = payment_entity.get("order_id") or order_entity.get("id")
        webhook_amount_paise = payment_entity.get("amount")

        if not idem_key:
            # Not every webhook carries the notes we set, or Razorpay's
            # payload shape can vary by event type — acknowledge rather
            # than error, since there's genuinely nothing to reconcile.
            return {"status": "ok", "reconciled": False, "reason": "no idempotency_key in payload"}

        reserved_amount = coordinator.policy_gate.reserved_amounts_paise.get(idem_key)
        if reserved_amount is None:
            # The normal case for most webhooks: the synchronous path
            # already resolved this transaction before the webhook
            # arrived. Nothing to do.
            return {"status": "ok", "reconciled": False, "reason": "no held reservation for this key"}

        if event_type == "payment.captured":
            if webhook_amount_paise != reserved_amount:
                # Signature valid, but the reported amount disagrees
                # with what was reserved — exactly what signature
                # verification alone doesn't catch. Refuse to auto-
                # commit; log as an anomaly for manual review. Still
                # 200: this is a permanent discrepancy, not a transient
                # failure, and a non-2xx would just make Razorpay retry
                # a webhook that retrying can't fix.
                write_ledger_entry(build_entry(
                    mandate_id, "WEBHOOK_AMOUNT_MISMATCH",
                    order_id=order_id, amount_paise=webhook_amount_paise,
                    reason=f"Webhook reported {webhook_amount_paise}p, reservation held {reserved_amount}p.",
                ))
                return {"status": "ok", "reconciled": False, "reason": "amount mismatch — held for manual review"}

            coordinator.policy_gate.commit(idem_key)
            write_ledger_entry(build_entry(
                mandate_id, "WEBHOOK_RECONCILED_CAPTURED",
                order_id=order_id, amount_paise=reserved_amount,
            ))
            return {"status": "ok", "reconciled": True, "resolution": "committed"}

        elif event_type == "payment.failed":
            coordinator.policy_gate.rollback(idem_key)
            write_ledger_entry(build_entry(
                mandate_id, "WEBHOOK_RECONCILED_FAILED",
                order_id=order_id, amount_paise=reserved_amount,
            ))
            return {"status": "ok", "reconciled": True, "resolution": "rolled_back"}

        return {"status": "ok", "reconciled": False, "reason": f"unhandled event type: {event_type}"}

    return router