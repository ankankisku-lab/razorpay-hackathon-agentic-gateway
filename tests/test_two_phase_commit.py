import uuid

import pytest

from backend.exceptions import RazorpayAmbiguousError, RazorpayDeclinedError, PolicyViolationError
from backend.ledger import verify_chain, verify_signatures
from backend.policy_gate import PolicyGate, load_catalog
from backend.schemas import CartItem, CartMandate, IntentMandate, SimulatedExecutionRequest
from backend.signing import sign_mandate
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from config import settings

CATALOG = load_catalog()
TEST_SKU = "SKU_BOAT_100"
TEST_PRICE_PAISE = CATALOG[TEST_SKU]["unit_price_paise"]


@pytest.fixture
def coordinator():
    return TwoPhaseCommitCoordinator(policy_gate=PolicyGate(session_spend_cap_paise=10_000_00))


def make_request(simulate_timeout: bool = False, simulate_decline: bool = False, auto_execute: bool = True):
    idem_key = "idem_" + uuid.uuid4().hex[:12]
    mandate_id = "mnd_" + uuid.uuid4().hex[:8]

    cart = CartMandate(
        cart_id="crt_" + uuid.uuid4().hex[:6],
        mandate_id=mandate_id,
        items=[
            CartItem(
                sku=TEST_SKU,
                name="boAt Bassheads 100",
                quantity=1,
                unit_price_paise=TEST_PRICE_PAISE,
                line_total_paise=TEST_PRICE_PAISE,
            )
        ],
        total_amount_paise=TEST_PRICE_PAISE,
    )
    mandate = IntentMandate(
        mandate_id=mandate_id,
        user_id="usr_test_01",
        idempotency_key=idem_key,
        max_authorized_budget_paise=10_000_00,
        expires_at=int(2e9),
        user_intent_summary="buy boAt earphones",
    )
    # evaluate() now verifies this against exactly {"mandate": ..., "cart": ...} —
    # must match that shape precisely or a legitimate request fails the
    # same check a forged one would.
    signature = sign_mandate({"mandate": mandate.model_dump(), "cart": cart.model_dump()})
    return SimulatedExecutionRequest(
        user_prompt="get me the boAt earphones",
        user_id="usr_ankan_01",
        cart=cart,
        mandate=mandate,
        signature=signature,
        auto_execute=auto_execute,
        simulate_network_timeout=simulate_timeout,
        simulate_gateway_decline=simulate_decline,
    )


def test_2pc_mutated_mandate_after_signing_is_tamper_detected(coordinator):
    # Exactly the scenario the OLD version of the previous test relied
    # on (mutate a field post-signing) — now correctly caught as
    # tampering rather than treated as an ordinary budget rejection.
    from backend.exceptions import SecurityTamperError

    req = make_request()
    req.mandate.max_authorized_budget_paise = TEST_PRICE_PAISE - 1

    with pytest.raises(SecurityTamperError):
        coordinator.execute_transaction(req)


def test_2pc_missing_signature_is_rejected_not_bypassed(coordinator):
    # The exact bypass a naive `if signature:` check would have allowed —
    # simply omitting the signature must reject, not silently pass.
    from backend.exceptions import SecurityTamperError

    req = make_request()
    req.signature = None

    with pytest.raises(SecurityTamperError):
        coordinator.execute_transaction(req)


def test_2pc_happy_path(coordinator, monkeypatch):
    monkeypatch.setattr(
        "backend.razorpay_gateway.razorpay_client.order.create",
        lambda data: {"id": "order_" + uuid.uuid4().hex[:10]},
    )
    req = make_request()
    result = coordinator.execute_transaction(req)

    assert result["status"] == "SUCCESS"
    assert result["order_id"].startswith("order_")
    assert result["amount_paise"] == TEST_PRICE_PAISE

    chain_ok, chain_msg = verify_chain()
    sig_ok, sig_msg = verify_signatures()
    assert chain_ok, chain_msg
    assert sig_ok, sig_msg


def test_2pc_declined_rollback(coordinator):
    settings.allow_mock_gateway = True
    req = make_request(simulate_decline=True)

    with pytest.raises(RazorpayDeclinedError):
        coordinator.execute_transaction(req)

    # Both must be freed, not just the budget — rollback only ever fires
    # on a confirmed outcome, so reusing the same idempotency_key for an
    # immediate retry is provably safe, not just convenient.
    assert req.mandate.idempotency_key not in coordinator.policy_gate.reserved_amounts_paise
    assert req.mandate.idempotency_key not in coordinator.policy_gate.processed_idempotency_keys


def test_2pc_ambiguous_timeout_holds_reservation(coordinator):
    settings.allow_mock_gateway = True
    req = make_request(simulate_timeout=True)

    with pytest.raises(RazorpayAmbiguousError):
        coordinator.execute_transaction(req)

    # Must stay held, not released — an ambiguous outcome means the
    # order may exist on Razorpay's side even without a clean response.
    assert coordinator.policy_gate.reserved_amounts_paise.get(req.mandate.idempotency_key) == TEST_PRICE_PAISE


def test_2pc_policy_rejection_never_reaches_gateway(coordinator, monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(
        "backend.razorpay_gateway.razorpay_client.order.create",
        lambda data: called.__setitem__("n", called["n"] + 1) or {"id": "order_should_not_happen"},
    )
    # Budget set below the item price so Phase 1 must reject before
    # Phase 2 ever gets a chance to call the gateway. Built correctly
    # from the start (signed with the low budget already in place) —
    # mutating a mandate's field AFTER signing would itself look like
    # tampering to the signature check now, which would raise
    # SecurityTamperError instead of the AP2_BUDGET_REJECT this test
    # is actually trying to exercise.
    idem_key = "idem_" + uuid.uuid4().hex[:12]
    mandate_id = "mnd_" + uuid.uuid4().hex[:8]
    cart = CartMandate(
        cart_id="crt_" + uuid.uuid4().hex[:6],
        mandate_id=mandate_id,
        items=[CartItem(sku=TEST_SKU, name="x", quantity=1, unit_price_paise=TEST_PRICE_PAISE, line_total_paise=TEST_PRICE_PAISE)],
        total_amount_paise=TEST_PRICE_PAISE,
    )
    mandate = IntentMandate(
        mandate_id=mandate_id, user_id="usr_test_01", idempotency_key=idem_key,
        max_authorized_budget_paise=TEST_PRICE_PAISE - 1, expires_at=int(2e9),
        user_intent_summary="under-budget test",
    )
    signature = sign_mandate({"mandate": mandate.model_dump(), "cart": cart.model_dump()})
    req = SimulatedExecutionRequest(
        user_prompt="x", user_id="usr_test_01", cart=cart, mandate=mandate, signature=signature,
    )

    with pytest.raises(PolicyViolationError):
        coordinator.execute_transaction(req)
    assert called["n"] == 0, "Gateway must never be called when the policy gate rejects."


def test_2pc_auto_execute_false_reserves_without_calling_gateway(coordinator, monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(
        "backend.razorpay_gateway.razorpay_client.order.create",
        lambda data: called.__setitem__("n", called["n"] + 1) or {"id": "order_should_not_happen"},
    )
    req = make_request(auto_execute=False)
    result = coordinator.execute_transaction(req)

    assert result["status"] == "RESERVED"
    assert result["order_id"] is None
    assert called["n"] == 0, "auto_execute=False must not touch the gateway."
    # Held, not resolved either way — neither committed nor rolled back.
    assert req.mandate.idempotency_key in coordinator.policy_gate.reserved_amounts_paise