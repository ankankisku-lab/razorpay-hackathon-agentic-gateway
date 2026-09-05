import hashlib
import hmac
import json
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.exceptions import RazorpayAmbiguousError
from backend.policy_gate import PolicyGate, load_catalog
from backend.schemas import CartItem, CartMandate, IntentMandate, SimulatedExecutionRequest
from backend.signing import sign_mandate
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from backend.webhook import create_webhook_router
from config import settings

CATALOG = load_catalog()
TEST_SKU = "SKU_BOAT_100"
TEST_PRICE_PAISE = CATALOG[TEST_SKU]["unit_price_paise"]


def sign(body: bytes) -> str:
    return hmac.new(settings.razorpay_webhook_secret.encode(), body, hashlib.sha256).hexdigest()


def make_captured_payload(mandate_id, idem_key, order_id, amount_paise):
    return {
        "event": "payment.captured",
        "payload": {
            "order": {"entity": {"id": order_id, "notes": {"idempotency_key": idem_key, "mandate_id": mandate_id}}},
            "payment": {"entity": {"order_id": order_id, "amount": amount_paise}},
        },
    }


def make_failed_payload(mandate_id, idem_key, order_id, amount_paise):
    payload = make_captured_payload(mandate_id, idem_key, order_id, amount_paise)
    payload["event"] = "payment.failed"
    return payload


@pytest.fixture
def held_reservation(monkeypatch):
    """Puts a real reservation into the ambiguous-held state via the
    actual coordinator, not a hand-constructed dict — so the webhook
    tests below reconcile against genuine PolicyGate state."""
    settings.allow_mock_gateway = True
    gate = PolicyGate(session_spend_cap_paise=10_000_00)
    coordinator = TwoPhaseCommitCoordinator(policy_gate=gate)

    idem_key = "idem_" + uuid.uuid4().hex[:12]
    mandate_id = "mnd_" + uuid.uuid4().hex[:8]
    cart = CartMandate(
        cart_id="crt_" + uuid.uuid4().hex[:6], mandate_id=mandate_id,
        items=[CartItem(sku=TEST_SKU, name="x", quantity=1, unit_price_paise=TEST_PRICE_PAISE, line_total_paise=TEST_PRICE_PAISE)],
        total_amount_paise=TEST_PRICE_PAISE,
    )
    mandate = IntentMandate(mandate_id=mandate_id, user_id="usr_test_01", idempotency_key=idem_key, max_authorized_budget_paise=10_000_00, expires_at=int(2e9), user_intent_summary="x")
    signature = sign_mandate({"mandate": mandate.model_dump(), "cart": cart.model_dump()})
    req = SimulatedExecutionRequest(user_prompt="x", user_id="u1", cart=cart, mandate=mandate, signature=signature, simulate_network_timeout=True)

    with pytest.raises(RazorpayAmbiguousError):
        coordinator.execute_transaction(req)

    assert gate.reserved_amounts_paise.get(idem_key) == TEST_PRICE_PAISE  # sanity check before testing reconciliation

    app = FastAPI()
    app.include_router(create_webhook_router(coordinator))
    client = TestClient(app)
    return {"client": client, "coordinator": coordinator, "idem_key": idem_key, "mandate_id": mandate_id}


def test_webhook_reconciles_captured_payment(held_reservation):
    body = json.dumps(make_captured_payload(
        held_reservation["mandate_id"], held_reservation["idem_key"], "order_abc", TEST_PRICE_PAISE,
    )).encode()
    resp = held_reservation["client"].post(
        "/api/v1/webhooks/razorpay", content=body,
        headers={"X-Razorpay-Signature": sign(body), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json()["reconciled"] is True
    assert resp.json()["resolution"] == "committed"
    assert held_reservation["idem_key"] not in held_reservation["coordinator"].policy_gate.reserved_amounts_paise


def test_webhook_reconciles_failed_payment(held_reservation):
    body = json.dumps(make_failed_payload(
        held_reservation["mandate_id"], held_reservation["idem_key"], "order_abc", TEST_PRICE_PAISE,
    )).encode()
    resp = held_reservation["client"].post(
        "/api/v1/webhooks/razorpay", content=body,
        headers={"X-Razorpay-Signature": sign(body), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json()["resolution"] == "rolled_back"
    assert held_reservation["idem_key"] not in held_reservation["coordinator"].policy_gate.reserved_amounts_paise
    assert held_reservation["idem_key"] not in held_reservation["coordinator"].policy_gate.processed_idempotency_keys


def test_webhook_rejects_invalid_signature(held_reservation):
    body = json.dumps(make_captured_payload(
        held_reservation["mandate_id"], held_reservation["idem_key"], "order_abc", TEST_PRICE_PAISE,
    )).encode()
    resp = held_reservation["client"].post(
        "/api/v1/webhooks/razorpay", content=body,
        headers={"X-Razorpay-Signature": "0" * 64, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    # Reservation must be untouched — rejected before any reconciliation logic ran.
    assert held_reservation["idem_key"] in held_reservation["coordinator"].policy_gate.reserved_amounts_paise


def test_webhook_rejects_tampered_body(held_reservation):
    real_body = json.dumps(make_captured_payload(
        held_reservation["mandate_id"], held_reservation["idem_key"], "order_abc", TEST_PRICE_PAISE,
    )).encode()
    real_signature = sign(real_body)
    tampered_body = json.dumps(make_captured_payload(
        held_reservation["mandate_id"], held_reservation["idem_key"], "order_abc", 1,  # amount tampered to 1 paise
    )).encode()
    resp = held_reservation["client"].post(
        "/api/v1/webhooks/razorpay", content=tampered_body,
        headers={"X-Razorpay-Signature": real_signature, "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert held_reservation["idem_key"] in held_reservation["coordinator"].policy_gate.reserved_amounts_paise


def test_webhook_refuses_to_commit_on_amount_mismatch(held_reservation):
    # Validly signed, but the webhook's own reported amount disagrees
    # with what was actually reserved.
    body = json.dumps(make_captured_payload(
        held_reservation["mandate_id"], held_reservation["idem_key"], "order_abc", TEST_PRICE_PAISE + 1,
    )).encode()
    resp = held_reservation["client"].post(
        "/api/v1/webhooks/razorpay", content=body,
        headers={"X-Razorpay-Signature": sign(body), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200  # acknowledged, not retried
    assert resp.json()["reconciled"] is False
    # Must NOT have committed — still held, exactly as before.
    assert held_reservation["coordinator"].policy_gate.reserved_amounts_paise.get(held_reservation["idem_key"]) == TEST_PRICE_PAISE


def test_webhook_acknowledges_unknown_idempotency_key(held_reservation):
    # A key with no held reservation at all — the normal case when the
    # synchronous path already resolved things before the webhook arrived.
    body = json.dumps(make_captured_payload(
        held_reservation["mandate_id"], "idem_never_reserved", "order_xyz", TEST_PRICE_PAISE,
    )).encode()
    resp = held_reservation["client"].post(
        "/api/v1/webhooks/razorpay", content=body,
        headers={"X-Razorpay-Signature": sign(body), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json()["reconciled"] is False


def test_webhook_handles_explicit_null_notes_without_crashing(held_reservation):
    # Regression test: Razorpay can send "notes": null explicitly rather
    # than omitting the key. dict.get(key, {}) only applies its default
    # for a MISSING key, not an explicit None value — an earlier version
    # of this handler crashed with AttributeError on exactly this shape.
    payload = {
        "event": "payment.captured",
        "payload": {
            "order": {"entity": {"id": "order_null_notes", "notes": None}},
            "payment": {"entity": {"order_id": "order_null_notes", "amount": TEST_PRICE_PAISE, "notes": None}},
        },
    }
    body = json.dumps(payload).encode()
    resp = held_reservation["client"].post(
        "/api/v1/webhooks/razorpay", content=body,
        headers={"X-Razorpay-Signature": sign(body), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200, resp.text  # must not 500
    assert resp.json()["reconciled"] is False
    assert resp.json()["reason"] == "no idempotency_key in payload"