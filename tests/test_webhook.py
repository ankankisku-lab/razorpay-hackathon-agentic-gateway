import hashlib
import hmac
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.policy_gate import PolicyGate
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from backend.webhook import create_webhook_router
from config import settings


@pytest.fixture
def setup_webhook_app():
    gate = PolicyGate(session_spend_cap_paise=100000)
    coordinator = TwoPhaseCommitCoordinator(policy_gate=gate)
    app = FastAPI()
    app.include_router(create_webhook_router(coordinator))
    client = TestClient(app)
    return client, coordinator


def seed_held_reservation(coordinator: TwoPhaseCommitCoordinator, idem_key: str, amount_paise: int):
    """Simulates what a real evaluate() approval leaves behind, without
    going through a full CartMandate/IntentMandate/catalog round-trip.
    Both pieces of state matter: reserved_amounts_paise is what
    commit()/rollback() look up, and processed_idempotency_keys is what
    a real approval also sets — poking only the first one leaves the
    gate's state inconsistent with what evaluate() actually produces,
    and any assertion checking processed_idempotency_keys will fail
    against a fixture that never touched it."""
    coordinator.policy_gate.processed_idempotency_keys.add(idem_key)
    coordinator.policy_gate.reserved_amounts_paise[idem_key] = amount_paise


def make_signed_request(client: TestClient, payload: dict, custom_secret: str = None):
    body_bytes = json.dumps(payload).encode("utf-8")
    secret = custom_secret or settings.razorpay_webhook_secret
    signature = hmac.new(
        key=secret.encode("utf-8"),
        msg=body_bytes,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return client.post(
        "/api/v1/webhooks/razorpay",
        content=body_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Razorpay-Signature": signature,
        },
    )


def test_webhook_rejects_invalid_signature(setup_webhook_app):
    client, _ = setup_webhook_app
    payload = {"event": "payment.captured"}
    response = make_signed_request(client, payload, custom_secret="wrong_secret")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid webhook signature"


def test_webhook_reconciles_captured_payment(setup_webhook_app):
    client, coordinator = setup_webhook_app
    idem_key = "idem_webhook_test_01"
    amount_paise = 39900
    seed_held_reservation(coordinator, idem_key, amount_paise)

    payload = {
        "event": "payment.captured",
        "payload": {
            "order": {
                "entity": {
                    "id": "order_test_123",
                    "notes": {"idempotency_key": idem_key, "mandate_id": "mnd_test_123"},
                }
            },
            "payment": {
                "entity": {
                    "id": "pay_test_123",
                    "order_id": "order_test_123",
                    "amount": amount_paise,
                    "notes": None,  # null-notes resilience
                }
            },
        },
    }
    response = make_signed_request(client, payload)
    assert response.status_code == 200
    assert response.json()["reconciled"] is True
    assert response.json()["resolution"] == "committed"

    # commit() only ever pops reserved_amounts_paise — it never touches
    # processed_idempotency_keys, so that key staying present here is
    # correct and expected, not a leftover bug.
    assert idem_key not in coordinator.policy_gate.reserved_amounts_paise
    assert idem_key in coordinator.policy_gate.processed_idempotency_keys


def test_webhook_reconciles_failed_payment(setup_webhook_app):
    client, coordinator = setup_webhook_app
    idem_key = "idem_webhook_fail_01"
    amount_paise = 39900
    seed_held_reservation(coordinator, idem_key, amount_paise)

    payload = {
        "event": "payment.failed",
        "payload": {
            "order": {
                "entity": {
                    "id": "order_test_fail_123",
                    "notes": {"idempotency_key": idem_key, "mandate_id": "mnd_test_fail_123"},
                }
            },
            "payment": {
                "entity": {
                    "id": "pay_test_fail_123",
                    "order_id": "order_test_fail_123",
                    "amount": amount_paise,
                    "notes": None,
                }
            },
        },
    }
    response = make_signed_request(client, payload)
    assert response.status_code == 200
    assert response.json()["reconciled"] is True
    assert response.json()["resolution"] == "rolled_back"

    # rollback() discards from BOTH sets — unlike commit(), which only
    # ever pops reserved_amounts_paise. Freeing processed_idempotency_keys
    # too is what makes the same idempotency_key safely reusable for an
    # immediate retry after a confirmed failure.
    assert idem_key not in coordinator.policy_gate.reserved_amounts_paise
    assert idem_key not in coordinator.policy_gate.processed_idempotency_keys


def test_webhook_flags_amount_mismatch(setup_webhook_app):
    client, coordinator = setup_webhook_app
    idem_key = "idem_mismatch_01"
    seed_held_reservation(coordinator, idem_key, 39900)

    payload = {
        "event": "payment.captured",
        "payload": {
            "order": {
                "entity": {
                    "id": "order_test_999",
                    "notes": {"idempotency_key": idem_key, "mandate_id": "mnd_test_999"},
                }
            },
            "payment": {
                "entity": {
                    "order_id": "order_test_999",
                    "amount": 10000,  # reported 10000p vs reserved 39900p
                }
            },
        },
    }
    response = make_signed_request(client, payload)
    assert response.status_code == 200
    assert response.json()["reconciled"] is False
    assert "amount mismatch" in response.json()["reason"]
    assert coordinator.policy_gate.reserved_amounts_paise.get(idem_key) == 39900