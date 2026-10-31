"""Endpoints that exist only for the interactive demo (frontend/).

Registered by create_app(demo=True), which only demo_server.py passes.
The production app never includes them: they issue API keys without
credentials, expose per-layer guard scores (an attack-tuning oracle),
sign webhooks on the client's behalf and wipe runtime state.
See frontend/DESIGN.md §10 for why each one has to exist.
"""
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from backend.auth import issue_api_key
from backend.exceptions import PromptInjectionDetectedError
from backend.ledger import LEDGER_STREAM, verify_chain, verify_signatures
from backend.reconciler import reconcile_once
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from backend.webhook import process_razorpay_webhook
from config import settings

DEMO_USERS = [
    {"id": "usr_alice", "name": "Alice"},
    {"id": "usr_bob", "name": "Bob"},
]


class DemoIntentRequest(BaseModel):
    prompt: str
    auto_execute: bool = True


class DemoWebhookRequest(BaseModel):
    idempotency_key: str
    event: str = "payment.captured"          # or "payment.failed"
    amount_paise: Optional[int] = None       # default: the reserved amount
    event_id: Optional[str] = None           # reuse one to demonstrate replay protection


def _ledger_view(limit: int = 14):
    return [{
        "index": b.get("index"),
        "event_type": b.get("event_type"),
        "mandate_id": b.get("mandate_id"),
        "order_id": b.get("order_id"),
        "amount_paise": b.get("amount_paise"),
        "timestamp": b.get("timestamp"),
        "block_hash": (b.get("block_hash") or "")[:12],
        "previous_hash": (b.get("previous_hash") or "")[:12],
        "reason": (b.get("payload") or {}).get("reason"),
    } for b in reversed(LEDGER_STREAM[-limit:])]


def create_demo_router(
    coordinator: TwoPhaseCommitCoordinator,
    intent_layer: Callable[[], Any],
    authenticated_user: Callable[..., str],
    rate_limited_user: Callable[..., str],
    modes: Dict[str, str],
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/demo", tags=["Demo only"])
    gate = coordinator.policy_gate
    store = gate.store

    @router.post("/session")
    def demo_session() -> Dict[str, Any]:
        """Fresh API keys for the demo users. Keys are returned once and
        held only in the page's memory."""
        users = [{**u, "api_key": issue_api_key(store, u["id"])} for u in DEMO_USERS]
        return {
            "users": users,
            "config": {
                "cap_paise": gate.session_spend_cap_paise,
                "mandate_ttl_seconds": settings.mandate_validity_seconds,
                "guard_threshold": settings.prompt_guard_threshold,
                "rate_limit": f"{settings.rate_limit_requests} per {settings.rate_limit_window_seconds}s",
                **modes,
            },
        }

    @router.post("/intent")
    def demo_intent(body: DemoIntentRequest, user_id: str = Depends(rate_limited_user)) -> Dict[str, Any]:
        """/intent/process plus the stage-by-stage trace."""
        trace: Dict[str, Any] = {}
        start = time.perf_counter()
        try:
            request = intent_layer().process(
                user_prompt=body.prompt, user_id=user_id, auto_execute=body.auto_execute, trace=trace,
            )
            outcome = {"status": "DRAFTED", "request": request.model_dump()}
        except PromptInjectionDetectedError as err:
            outcome = {"status": "BLOCKED", "reason": str(err)}
        except ValueError as err:
            outcome = {"status": "NO_MATCH", "reason": str(err)}
        trace["total_ms"] = (time.perf_counter() - start) * 1000
        return {**outcome, "trace": trace}

    @router.get("/state")
    def demo_state(user_id: str = Depends(authenticated_user)) -> Dict[str, Any]:
        """Authenticated but not rate-limited: the page refreshes this
        after every action, and that must not eat the user's allowance."""
        chain_ok, chain_msg = verify_chain()
        sig_ok, sig_msg = verify_signatures()
        return {
            "user_id": user_id,
            "cap_paise": gate.session_spend_cap_paise,
            "spent_paise": gate.spent_by(user_id),
            "by_status": store.amounts_by_status(f"{gate.session_id}:{user_id}"),
            "reservations": store.list_for_user(user_id),
            "ledger": {
                "blocks": _ledger_view(),
                "total_in_segment": len(LEDGER_STREAM),
                "chain_ok": chain_ok, "chain_msg": chain_msg,
                "signatures_ok": sig_ok, "signatures_msg": sig_msg,
            },
        }

    @router.post("/webhook")
    def demo_webhook(body: DemoWebhookRequest, user_id: str = Depends(rate_limited_user)) -> Dict[str, Any]:
        """A SIMULATED Razorpay event, signed here (the browser must never
        hold the webhook secret) and passed through the production
        webhook pipeline unchanged: signature check, dedupe, reconcile."""
        reservation = store.get(body.idempotency_key)
        if reservation is None or reservation["user_id"] != user_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such reservation for this user.")
        if body.event not in ("payment.captured", "payment.failed"):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unsupported event.")

        order_id = reservation.get("order_id") or f"order_sim_{uuid.uuid4().hex[:10]}"
        notes = {"idempotency_key": body.idempotency_key, "mandate_id": reservation["mandate_id"]}
        raw_body = json.dumps({
            "event": body.event,
            "payload": {
                "order": {"entity": {"id": order_id, "notes": notes}},
                "payment": {"entity": {
                    "order_id": order_id,
                    "amount": body.amount_paise if body.amount_paise is not None else reservation["amount_paise"],
                }},
            },
        }).encode("utf-8")
        signature = hmac.new(settings.razorpay_webhook_secret.encode(), raw_body, hashlib.sha256).hexdigest()
        event_id = body.event_id or f"evt_sim_{uuid.uuid4().hex[:12]}"
        result = process_razorpay_webhook(coordinator, raw_body, signature, event_id)
        return {"simulated": True, "event_id": event_id, "result": result}

    @router.post("/reconcile")
    def demo_reconcile(user_id: str = Depends(rate_limited_user)) -> Dict[str, Any]:
        """The real reconciler, run now with no grace period."""
        return {"counts": reconcile_once(coordinator, held_grace_seconds=0)}

    @router.post("/reset")
    def demo_reset(user_id: str = Depends(authenticated_user)) -> Dict[str, Any]:
        store.reset_runtime_state()
        return {"reset": True, "ledger_kept": True}

    return router
