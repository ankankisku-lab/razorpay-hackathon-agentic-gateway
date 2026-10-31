"""Interactive demo: the gateway API plus the browser UI in frontend/.

    python demo_server.py                         # live AI (Groq) + Razorpay sandbox
    python demo_server.py --offline-ai            # rule-based stand-ins for the two AI models
    python demo_server.py --simulated-razorpay    # fake order creation instead of the sandbox
    then open http://127.0.0.1:8000

Demo state (reservations, spend, ledger) lives in demo_data/, separate
from the real state database and ledger. See frontend/DESIGN.md.
"""
import argparse
import itertools
import json
import re
import uuid
from pathlib import Path

from config import settings

DEMO_CAP_PAISE = 5_000_00  # ₹5,000 per user, small enough to demo the cap


def configure(data_dir: Path) -> None:
    """Must run before anything imports backend.ledger, which reads its
    paths and loads its chain at import time."""
    data_dir.mkdir(parents=True, exist_ok=True)
    settings.state_db_path = data_dir / "state.db"
    settings.ledger_path = data_dir / "ledger.jsonl"
    settings.ledger_checkpoint_path = data_dir / "ledger.checkpoint.json"
    settings.ledger_archive_dir = data_dir / "ledger_archive"
    settings.allow_mock_gateway = True        # enables the timeout/decline simulation route
    settings.reconcile_interval_seconds = 0   # the UI runs the reconciler on demand


# --- Offline stand-ins (only with --offline-ai) ----------------------------------

class _Completion:
    def __init__(self, content: str):
        self.choices = [type("Choice", (), {"message": type("Msg", (), {"content": content})()})()]


class OfflinePlannerClient:
    """Rule-based replacement for the Groq planner: pulls budget and
    quantity out with regexes. Clearly labelled in the UI; nothing here
    pretends to be the real model."""

    def __init__(self):
        self.chat = type("Chat", (), {"completions": self})()

    BUDGET = re.compile(r"(?:under|below|within|max|budget(?: is)?|upto|up to)\s*(?:rs\.?|inr|₹)?\s*([\d,]+)", re.I)
    # A standalone 1–3 digit number: "3 Sony" counts, "65W" and "C500" don't.
    QUANTITY = re.compile(r"\b(\d{1,3})\b")
    FILLER = re.compile(r"\b(buy|get|me|please|order|i want|rupees?|rs)\b", re.I)

    def create(self, model, messages, response_format=None, temperature=0.0):
        prompt = messages[-1]["content"]
        budget = self.BUDGET.search(prompt)
        without_budget = self.BUDGET.sub("", prompt)
        quantity = self.QUANTITY.search(without_budget)
        query = self.FILLER.sub("", self.QUANTITY.sub("", without_budget)).strip(" ,.")
        return _Completion(json.dumps({
            "search_query": query or prompt,
            "max_budget_paise": int(budget.group(1).replace(",", "")) * 100 if budget else 100_000,
            "quantity": int(quantity.group(1)) if quantity else 1,
        }))


class OfflineMLGuard:
    def screen(self, prompt):
        return True, "offline: ML classifier not run (rule-based demo mode)"


def simulate_razorpay() -> None:
    """Fake order creation and lookup in place of the sandbox, so the demo
    runs without Razorpay keys. Orders are labelled order_sim_*."""
    import backend.razorpay_gateway as gateway

    created = []
    counter = itertools.count(1)

    def create(data):
        order = {"id": f"order_sim_{uuid.uuid4().hex[:10]}", "entity": "order", "amount": data["amount"],
                 "currency": data["currency"], "receipt": data["receipt"], "status": "created",
                 "notes": data.get("notes", {}), "attempts": 0, "seq": next(counter)}
        created.append(order)
        return order

    gateway.razorpay_client.order.create = create
    gateway.razorpay_client.order.all = lambda params: {
        "items": [o for o in created if o["receipt"] == params.get("receipt")]
    }


def build_app(offline_ai: bool, simulated_razorpay: bool):
    from agents.buyer_agent import BuyerAgent
    from agents.intent_layer import IntentLayer
    from app import create_app
    from backend.policy_gate import PolicyGate
    from backend.two_phase_commit import TwoPhaseCommitCoordinator

    if simulated_razorpay:
        simulate_razorpay()

    print("[demo] Loading the embedding model and catalog index…")
    if offline_ai:
        from agents.pattern_guard import CombinedGuard
        from agents.planner import Planner
        layer = IntentLayer(
            guardrail=CombinedGuard(OfflineMLGuard()),
            planner=Planner(client=OfflinePlannerClient()),
            buyer_agent=BuyerAgent(),
        )
    else:
        layer = IntentLayer()

    gate = PolicyGate(session_spend_cap_paise=DEMO_CAP_PAISE, session_id="demo")
    return create_app(
        coordinator=TwoPhaseCommitCoordinator(policy_gate=gate),
        intent_layer_factory=lambda: layer,
        demo=True,
        demo_modes={
            "ai_mode": "offline" if offline_ai else "live",
            "razorpay_mode": "simulated" if simulated_razorpay else "sandbox",
            "planner_model": "rule-based stand-in" if offline_ai else settings.planner_model,
            "guard_model": "regex only" if offline_ai else settings.guard_model,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--offline-ai", action="store_true", help="replace the Groq models with labelled rule-based stand-ins")
    parser.add_argument("--simulated-razorpay", action="store_true", help="fake order creation instead of the Razorpay sandbox")
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parent / "demo_data")
    args = parser.parse_args()

    configure(args.data_dir)
    app = build_app(args.offline_ai, args.simulated_razorpay)

    import uvicorn
    print(f"[demo] Open http://{args.host}:{args.port}  (state in {args.data_dir})")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
