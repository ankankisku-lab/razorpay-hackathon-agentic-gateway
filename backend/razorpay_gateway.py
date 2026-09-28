from typing import Any, Dict, List

import razorpay
import requests

from backend.exceptions import RazorpayDeclinedError, RazorpayAmbiguousError
from config import settings

# No credential check here — config.py's Settings() already raised at
# import time if RAZORPAY_KEY_ID/SECRET were unset. Duplicating that
# check here would just be a second place for the same guarantee to
# drift out of sync with the first.
razorpay_client = razorpay.Client(auth=(settings.razorpay_key_id, settings.razorpay_key_secret))

def build_receipt(mandate_id: str, idempotency_key: str) -> str:
    """Razorpay requires receipt to be unique (max 40 chars, per their
    Orders entity docs — NOT alphanumeric-only; their own examples
    include '#' and '_'). Deriving it from mandate_id alone isn't
    enough: one IntentMandate can back several separate CartMandate
    purchases, so multiple real orders could share a mandate_id and
    collide. idempotency_key is what's actually guaranteed unique per
    order attempt — safer than a timestamp, which can repeat within the
    same second for two fast back-to-back orders.

    Deterministic on purpose: after an ambiguous timeout the reconciler
    recomputes this exact receipt to ask Razorpay whether the order was
    created, without ever having received an order_id.
    """
    clean_mandate = "".join(ch for ch in mandate_id if ch.isalnum())[:10]
    clean_idem = "".join(ch for ch in idempotency_key if ch.isalnum())[:20]
    return f"ap2_{clean_mandate}_{clean_idem}"[:40]


def create_razorpay_order(
    validated_payload: dict,
    mandate_id: str,
    idempotency_key: str,
    *,
    order_cache,
    simulate_timeout: bool = False,
    simulate_decline: bool = False,
) -> Dict[str, Any]:
    """order_cache (a SQLiteStateStore) is required: Razorpay's Orders
    API has no server-side idempotency (only Payouts and Refunds do), so
    this cache is what actually prevents a retried request from creating
    a duplicate order. It used to be a module-level dict — lost on every
    restart, which the old comment called the highest-priority thing to
    move to a database. Required rather than defaulted so a caller can't
    quietly opt out of it.

    simulate_timeout/simulate_decline exist to trigger the two demo
    failure paths on command. They must only ever be reachable from a
    debug/demo code path gated by settings.allow_mock_gateway — never
    from a field a real caller (or a real AI buyer agent) can set on an
    ordinary request. The check below is defense-in-depth: even if a
    route-level gate were ever misconfigured or bypassed, this function
    still refuses to honor a simulate flag unless mock mode is
    explicitly on.
    """
    if (simulate_timeout or simulate_decline) and not settings.allow_mock_gateway:
        raise RuntimeError(
            "simulate_timeout/simulate_decline requested but "
            "ALLOW_MOCK_GATEWAY is not enabled — refusing to fake a "
            "gateway outcome outside an explicit debug context."
        )

    # Idempotency cache check first — before simulation or any network
    # call — so a cached real result is never shadowed by a simulated one.
    cached = order_cache.get_cached_order(idempotency_key)
    if cached is not None:
        return {"success": True, "order": cached, "cached": True}

    if simulate_timeout:
        raise RazorpayAmbiguousError("Simulated 504 Gateway Timeout / Connection Drop")
    if simulate_decline:
        raise RazorpayDeclinedError("Simulated 400 Bad Request: Merchant account inactive or invalid currency")

    try:
        receipt = build_receipt(mandate_id, idempotency_key)
        order_data = {
            "amount": validated_payload["verified_total_paise"],
            "currency": validated_payload.get("currency", "INR"),
            "receipt": receipt,
            "notes": {
                "protocol": "AP2-Inspired",
                "mandate_id": mandate_id,
                "idempotency_key": idempotency_key,
                "cart_id": validated_payload.get("cart_id", "UNKNOWN"),
            },
        }
        order = razorpay_client.order.create(data=order_data)
        order_cache.cache_order(idempotency_key, order)
        return {"success": True, "order": order, "cached": False}

    # Confirmed failures — Razorpay definitively rejected the request.
    except razorpay.errors.BadRequestError as e:
        raise RazorpayDeclinedError(f"Razorpay 4xx Client Error: {e}")
    except razorpay.errors.SignatureVerificationError as e:
        raise RazorpayDeclinedError(f"Signature Verification Error: {e}")

    # Ambiguous outcomes — the order may or may not exist on Razorpay's
    # side. Never roll back a reservation on any of these.
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
        raise RazorpayAmbiguousError(f"Network error / timeout: {e}")
    except razorpay.errors.ServerError as e:
        raise RazorpayAmbiguousError(f"Razorpay 5xx Internal Server Error: {e}")
    except razorpay.errors.GatewayError as e:
        raise RazorpayAmbiguousError(f"Razorpay Gateway Error: {e}")

    # Unclassified defaults to ambiguous too — never to a silent
    # confirmed-failure rollback.
    except Exception as e:
        raise RazorpayAmbiguousError(f"Unclassified Gateway Error: {e}")


def find_orders_by_receipt(receipt: str) -> List[Dict[str, Any]]:
    """Asks Razorpay whether an order with this receipt exists — how the
    reconciler resolves a HELD reservation that never got an order_id
    back. Any failure raises RazorpayAmbiguousError: "couldn't ask" must
    never be mistaken for "no such order", since that answer is what
    licenses releasing the reservation."""
    try:
        response = razorpay_client.order.all({"receipt": receipt})
    except Exception as e:
        raise RazorpayAmbiguousError(f"Order lookup by receipt failed: {e}")
    return [o for o in response.get("items", []) if o.get("receipt") == receipt]
