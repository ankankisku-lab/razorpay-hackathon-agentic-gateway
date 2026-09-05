import hashlib
import json
import re
import time
import warnings

warnings.filterwarnings("ignore")

import streamlit as st

from agents.buyer_agent import BuyerAgent
from agents.guardrail import PromptGuard
from agents.intent_layer import IntentLayer
from agents.planner import Planner
from backend.exceptions import (
    PolicyViolationError,
    PromptInjectionDetectedError,
    RazorpayAmbiguousError,
    RazorpayDeclinedError,
    SecurityTamperError,
)
from backend.ledger import (
    LEDGER_STREAM,
    build_entry,
    verify_chain,
    verify_signatures,
    write_ledger_entry,
)
from backend.policy_gate import PolicyGate, load_catalog
from backend.schemas import SimulatedExecutionRequest
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from config import settings

st.set_page_config(page_title="Agentic Commerce Gateway", layout="wide")


# --- MOCK LLM CLIENTS FOR REHEARSAL ---
def fake_completion(content: str):
    class Msg:
        content: str = ""

    class Choice:
        message = Msg()

    class Completion:
        choices = []

    m = Msg()
    m.content = content
    c = Choice()
    c.message = m
    comp = Completion()
    comp.choices = [c]
    return comp


class FakeGuardClient:
    def __init__(self, score: str):
        class _Completions:
            def create(self, model, messages):
                return fake_completion(score)

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


class FakePlannerClient:
    def __init__(self, response: dict):
        class _Completions:
            def create(self, model, messages, response_format, temperature=0.0):
                return fake_completion(json.dumps(response))

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


class FakeRetriever:
    def __init__(self, catalog: dict):
        self.catalog = catalog

    def search(self, query: str, top_k: int = 3):
        query_words = set(query.lower().split())
        scored = []
        for sku, item in self.catalog.items():
            text = f"{item.get('name', '')} {item.get('description', '')} {' '.join(item.get('tags', []))}".lower()
            overlap = sum(1 for w in query_words if w in text)
            scored.append(({**item, "sku": sku}, float(overlap)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]


# --- PERSISTENT STATE ---
if "policy_gate" not in st.session_state:
    st.session_state.policy_gate = PolicyGate(session_spend_cap_paise=10_000_00)
    st.session_state.coordinator = TwoPhaseCommitCoordinator(policy_gate=st.session_state.policy_gate)
    st.session_state.catalog = load_catalog()
    st.session_state.history = []

policy_gate = st.session_state.policy_gate
coordinator = st.session_state.coordinator
CATALOG = st.session_state.catalog

st.title("🛡️ Agentic Commerce Gateway — Live Demo")

with st.sidebar:
    st.header("Gateway Controls")
    use_real_groq = st.checkbox(
        "Use real Groq API calls",
        value=False,
        help="Off = deterministic mock clients for rehearsal. On = live Groq LLM inference.",
    )
    use_real_razorpay = st.checkbox(
        "Use real Razorpay Sandbox",
        value=False,
        help="Off = mock gateway responses. On = calls live Razorpay order APIs.",
    )
    settings.allow_mock_gateway = not use_real_razorpay

    st.divider()
    st.subheader("Chaos & Adversarial Scenarios")
    force_decline = st.checkbox("Simulate Gateway Decline (402)", disabled=use_real_razorpay)
    force_timeout = st.checkbox("Simulate Gateway Timeout (504)", disabled=use_real_razorpay)
    force_tamper = st.checkbox("Simulate MitM Price Tamper (₹1 price forgery)")

    st.divider()
    st.caption(f"Session Spend Cap: ₹{policy_gate.session_spend_cap_paise / 100:,.2f}")
    st.caption(f"Spent so far: ₹{policy_gate.session_spent_paise / 100:,.2f}")
    active_holds = sum(policy_gate.reserved_amounts_paise.values())
    st.caption(f"Active Holds (Ambiguous): ₹{active_holds / 100:,.2f}")

    if st.session_state.history:
        st.divider()
        st.subheader("Recent Executions")
        for h in st.session_state.history[:5]:
            status = h.get("final_status", "")
            icon = "✅" if status == "SUCCESS" else ("🟡" if status == "HELD" else "🔴")
            st.caption(f"{icon} {h['prompt'][:35]} [{status}]")

user_prompt = st.text_input("Customer Request", placeholder="Buy boAt bassheads earphones under 1000 rupees")
user_id = st.text_input("User ID", value="usr_demo_judge")
submit = st.button("Submit to Agentic Gateway", type="primary")

if submit and user_prompt:
    record = {"prompt": user_prompt, "user_id": user_id, "final_status": None}

    # Stage 1: Guardrail Screen
    st.subheader("1️⃣ Layer 1: Prompt Injection Guardrail Screen")
    if use_real_groq:
        guard = PromptGuard()
    else:
        injection_markers = ["ignore previous", "ignore all", "system override", "disregard instructions"]
        is_injection = any(m in user_prompt.lower() for m in injection_markers)
        guard = PromptGuard(client=FakeGuardClient("0.985" if is_injection else "0.001"))

    is_safe, detail = guard.screen(user_prompt)
    col_a, col_b = st.columns(2)
    col_a.metric("Verdict", "🟢 BENIGN" if is_safe else "🔴 BLOCKED")
    col_b.metric("Confidence / Classifier Detail", detail)

    if not is_safe:
        st.error("Tripwire Activated: Request blocked before reaching the Planner model.")
        record["final_status"] = "BLOCKED"
        st.session_state.history.insert(0, record)
        st.stop()

    # Stage 2: Intent Extraction & Mandate Signing
    st.subheader("2️⃣ Layer 2: Intent Extraction & Cryptographic Mandate")
    if use_real_groq:
        planner = Planner()
        buyer_agent = BuyerAgent()
    else:
        budget_match = re.search(
            r"(?:under|below|max|budget|within|upto|up to)\s*(?:rs\.?|inr|₹)?\s*(\d+)",
            user_prompt,
            re.IGNORECASE,
        )
        if budget_match:
            budget_guess_paise = int(budget_match.group(1)) * 100
        else:
            all_numbers = [int(n) for n in re.findall(r"\b\d+\b", user_prompt)]
            budget_guess_paise = max(all_numbers) * 100 if all_numbers else 50000

        planner = Planner(
            client=FakePlannerClient({
                "search_query": user_prompt,
                "max_budget_paise": budget_guess_paise,
                "quantity": 1,
            })
        )
        buyer_agent = BuyerAgent(retriever=FakeRetriever(CATALOG))

    layer = IntentLayer(guardrail=guard, planner=planner, buyer_agent=buyer_agent)

    try:
        req = layer.process(user_prompt, user_id=user_id, auto_execute=True)
    except PromptInjectionDetectedError as e:
        st.error(f"Security Alert: {e}")
        record["final_status"] = "BLOCKED"
        st.session_state.history.insert(0, record)
        st.stop()
    except Exception as e:
        st.error(f"Resolution Failure: {e}")
        record["final_status"] = "NO_MATCH"
        st.session_state.history.insert(0, record)
        st.stop()

    record["mandate_id"] = req.mandate.mandate_id
    record["item"] = req.cart.items[0].name
    record["amount_paise"] = req.cart.total_amount_paise

    cart_to_execute = req.cart

    if force_tamper:
        st.warning("⚠️ MitM Simulation: Tampering with cart payload in transit (forging to 100 paise / ₹1.00)...")
        tampered_items = [
            item.model_copy(update={"unit_price_paise": 100, "line_total_paise": 100})
            for item in req.cart.items
        ]
        cart_to_execute = req.cart.model_copy(
            update={
                "items": tampered_items,
                "total_amount_paise": 100 * len(tampered_items),
            }
        )

    col_cart, col_sig = st.columns([2, 1])
    with col_cart:
        st.json({"mandate": req.mandate.model_dump(), "cart": cart_to_execute.model_dump()})
    with col_sig:
        st.info("Cryptographic Proof")
        st.markdown(f"**Ed25519 Asymmetric Signature:**\n`{req.signature[:32]}...{req.signature[-16:]}`")
        st.markdown(f"**Idempotency Token:**\n`{req.mandate.idempotency_key}`")
        st.markdown(f"**Authorized Budget:**\n₹{req.mandate.max_authorized_budget_paise / 100:,.2f}")

    exec_req = SimulatedExecutionRequest(
        user_prompt=req.user_prompt,
        user_id=req.user_id,
        mandate=req.mandate,
        cart=cart_to_execute,
        signature=req.signature,
        auto_execute=True,
        simulate_gateway_decline=force_decline and not use_real_razorpay,
        simulate_network_timeout=force_timeout and not use_real_razorpay,
    )

    # Stage 3: Two-Phase Commit Execution
    st.subheader("3️⃣ Layer 3: Two-Phase Commit (2PC) Execution")

    try:
        result = coordinator.execute_transaction(exec_req)
        st.success(f"Phase 2: 🟢 COMMITTED — Razorpay Order ID `{result['order_id']}`, Amount: ₹{result['amount_paise'] / 100:,.2f}")
        record["final_status"] = "SUCCESS"

    except SecurityTamperError as e:
        st.error(f"Phase 1 Gate Block: 🛡️ SECURITY TAMPER DETECTED — {e}")
        st.caption("Payload was altered in transit. Asymmetric signature verification failed before gateway invocation.")
        record["final_status"] = "TAMPER_REJECTED"

    except PolicyViolationError as e:
        st.error(f"Phase 1 Gate Block: 🔴 POLICY REJECTION — {e}")
        record["final_status"] = "POLICY_REJECTED"

    except RazorpayDeclinedError as e:
        st.error(f"Phase 2 Gateway Outcome: 🔴 ROLLED BACK — {e}")
        st.caption("Gateway declined authorization. Reserved budget and idempotency lock cleanly released.")
        record["final_status"] = "ROLLED_BACK"

    except RazorpayAmbiguousError as e:
        st.warning(f"Phase 2 Gateway Outcome: 🟡 AMBIGUOUS HOLD — {e}")
        st.caption("Network timeout. Reservation held to prevent double spending pending webhook arrival.")
        record["final_status"] = "HELD"
        st.session_state.held_transaction = {
            "idempotency_key": req.mandate.idempotency_key,
            "mandate_id": req.mandate.mandate_id,
            "amount_paise": cart_to_execute.total_amount_paise,
        }

    st.session_state.history.insert(0, record)

# --- WEBHOOK RECONCILIATION ---
if st.session_state.get("held_transaction"):
    held = st.session_state.held_transaction
    st.divider()
    st.info(f"⏳ **Pending Ambiguous State:** Reservation for Mandate `{held['mandate_id']}` is locked.")

    col_hook1, col_hook2 = st.columns(2)
    with col_hook1:
        if st.button("Simulate Inbound Webhook (payment.captured)", key="reconcile_cap"):
            order_id = "order_reconciled_" + held["mandate_id"][:6]
            policy_gate.commit(held["idempotency_key"])
            write_ledger_entry(
                build_entry(
                    held["mandate_id"],
                    "PAYMENT_CAPTURED",
                    order_id=order_id,
                    amount_paise=held["amount_paise"],
                )
            )
            st.success("Transaction committed and ledger updated via verified webhook.")
            del st.session_state.held_transaction
            st.rerun()

    with col_hook2:
        if st.button("Simulate Inbound Webhook (payment.failed)", key="reconcile_fail"):
            policy_gate.rollback(held["idempotency_key"])
            write_ledger_entry(
                build_entry(
                    held["mandate_id"],
                    "PAYMENT_DECLINED_ROLLED_BACK",
                    amount_paise=held["amount_paise"],
                    reason="Webhook reported payment.failed",
                )
            )
            st.warning("Hold released cleanly on failed payment notification.")
            del st.session_state.held_transaction
            st.rerun()

# --- CRYPTOGRAPHIC LEDGER ---
st.divider()
st.subheader("📜 Cryptographic Ledger Feed")

chain_ok, chain_msg = verify_chain()
sig_ok, sig_msg = verify_signatures()

col1, col2 = st.columns(2)
col1.metric("SHA-256 Hash Chain Integrity", "✅ Intact" if chain_ok else "❌ BROKEN", help=chain_msg)
col2.metric("Ed25519 Block Signatures", "✅ Valid" if sig_ok else "❌ INVALID", help=sig_msg)

if LEDGER_STREAM:
    st.caption(f"Displaying last {min(8, len(LEDGER_STREAM))} ledger blocks:")
    for block in reversed(LEDGER_STREAM[-8:]):
        ts = time.strftime("%H:%M:%S", time.localtime(block["timestamp"]))
        st.text(
            f"[{ts}] Block #{block['index']:<3} | {block['event_type']:<22} | "
            f"Mandate: {block['mandate_id']:<14} | ₹{block['amount_paise'] / 100:,.2f} | "
            f"Hash: {block.get('block_hash', '')[:16]}..."
        )
else:
    st.caption("No ledger events written yet in this process runtime.")