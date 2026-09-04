from typing import Any, Dict

import razorpay
import requests

from backend.exceptions import RazorpayDeclinedError, RazorpayAmbiguousError
from config import settings

# No credential check here — config.py's Settings() already raised at
# import time if RAZORPAY_KEY_ID/SECRET were unset. Duplicating that
# check here would just be a second place for the same guarantee to
# drift out of sync with the first.
razorpay_client = razorpay.Client(auth=(settings.razorpay_key_id, settings.razorpay_key_secret))

# Razorpay's Orders API has no server-side idempotency (only Payouts and
# Refunds do) — this cache is what actually prevents a retried request
# from creating a duplicate order. KNOWN LIMITATION: in-memory only, so
# it doesn't survive a restart. If the process dies between an ambiguous
# timeout and its retry, this cache is empty and a retry WILL create a
# real duplicate order. Highest-priority thing to move to Postgres
# before this runs anywhere beyond a demo.
IDEMPOTENCY_ORDER_STORE: Dict[str, Dict[str, Any]] = {}


def create_razorpay_order(
    validated_payload: dict,
    mandate_id: str,
    idempotency_key: str,
    simulate_timeout: bool = False,
    simulate_decline: bool = False,
) -> Dict[str, Any]:
    """simulate_timeout/simulate_decline exist to trigger the two demo
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
    if idempotency_key in IDEMPOTENCY_ORDER_STORE:
        return {"success": True, "order": IDEMPOTENCY_ORDER_STORE[idempotency_key], "cached": True}

    if simulate_timeout:
        raise RazorpayAmbiguousError("Simulated 504 Gateway Timeout / Connection Drop")
    if simulate_decline:
        raise RazorpayDeclinedError("Simulated 400 Bad Request: Merchant account inactive or invalid currency")

    try:
        # Razorpay requires receipt to be unique (max 40 chars, per their
        # Orders entity docs — NOT alphanumeric-only; their own examples
        # include '#' and '_'). Deriving it from mandate_id alone isn't
        # enough: one IntentMandate can back several separate CartMandate
        # purchases, so multiple real orders could share a mandate_id and
        # collide. idempotency_key is what's actually guaranteed unique
        # per order attempt — safer than a timestamp, which can repeat
        # within the same second for two fast back-to-back orders.
        clean_mandate = "".join(ch for ch in mandate_id if ch.isalnum())[:10]
        clean_idem = "".join(ch for ch in idempotency_key if ch.isalnum())[:20]
        receipt = f"ap2_{clean_mandate}_{clean_idem}"[:40]

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
        IDEMPOTENCY_ORDER_STORE[idempotency_key] = order
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

    