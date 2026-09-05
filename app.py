from typing import Any, Dict

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from agents.intent_layer import IntentLayer
from backend.exceptions import (
    PolicyViolationError,
    SecurityTamperError,
    RazorpayDeclinedError,
    RazorpayAmbiguousError,
    PromptInjectionDetectedError,
)
from backend.ledger import verify_chain, verify_signatures, LEDGER_STREAM
from backend.policy_gate import PolicyGate
from backend.schemas import ExecutionRequest, SimulatedExecutionRequest
from backend.two_phase_commit import TwoPhaseCommitCoordinator
from backend.webhook import create_webhook_router
from config import settings

app = FastAPI(
    title="Agentic Payment Gateway",
    version="1.0.0",
    description="Deterministic, policy-gated agentic checkout with signed mandate authorization and tamper-evident ledger.",
)

# One PolicyGate, one coordinator, shared by every route that can touch a
# reservation. The webhook's reconciliation logic (create_webhook_router)
# takes this SAME coordinator — if execute_payment and the webhook route
# each held their own PolicyGate, a reservation made through one would be
# invisible to the other, and an ambiguous-timeout hold could never be
# resolved by an incoming payment.captured event.
policy_gate = PolicyGate()
coordinator = TwoPhaseCommitCoordinator(policy_gate=policy_gate)
intent_layer = IntentLayer()

app.include_router(create_webhook_router(coordinator))


@app.get("/healthz", tags=["Ops"])
def health_check() -> Dict[str, str]:
    return {"status": "healthy", "service": "agentic-payment-gateway"}


class IntentRequest(BaseModel):
    """A JSON body, not query params — the original draft declared
    prompt/user_id/auto_execute as plain function arguments on a POST
    route, which FastAPI treats as query-string parameters for simple
    types, not a request body. Fine mechanically, surprising for a POST
    endpoint that conceptually takes a payload."""
    prompt: str
    user_id: str
    auto_execute: bool = True


@app.post("/api/v1/intent/process", tags=["Agent"])
def process_intent(body: IntentRequest) -> Dict[str, Any]:
    """Screens prompt, plans intent, deterministically retrieves an
    item, and returns a signed mandate inside an ExecutionRequest —
    drafted, not yet executed."""
    try:
        execution_req: ExecutionRequest = intent_layer.process(
            user_prompt=body.prompt,
            user_id=body.user_id,
            auto_execute=body.auto_execute,
        )
        return {"status": "DRAFTED", "request": execution_req.model_dump()}
    except PromptInjectionDetectedError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Security alert: {err}")
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err))


@app.post("/api/v1/execute", tags=["2PC Execution"])
def execute_payment(request: ExecutionRequest) -> Dict[str, Any]:
    """Phase 1 policy check & reservation -> Phase 2 gateway execution."""
    try:
        result = coordinator.execute_transaction(request)
        return {"status": result["status"], "result": result}
    except SecurityTamperError as err:
        # Signed/catalog data was altered — a security event, not a
        # routine rejection. Distinct status from PolicyViolationError
        # on purpose: this is the case worth alerting on differently.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Security tamper detected: {err}")
    except PolicyViolationError as err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Policy rejection: {err}")
    except RazorpayDeclinedError as err:
        raise HTTPException(status_code=status.HTTP_402_PAYMENT_REQUIRED, detail=f"Payment declined: {err}")
    except RazorpayAmbiguousError as err:
        # Held, not failed — the order may exist on Razorpay's side even
        # without a clean response. 504 signals "unresolved," not "no."
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Ambiguous gateway outcome, held for reconciliation: {err}",
        )


# Registered only when explicitly enabled — this is what keeps
# simulate_network_timeout/simulate_gateway_decline from being reachable
# by accident in a real deployment.
if settings.allow_mock_gateway:
    @app.post("/api/v1/simulate/execute", tags=["Debug / Simulation"])
    def simulate_execution(request: SimulatedExecutionRequest) -> Dict[str, Any]:
        """Debug-only route for triggering the demo failure paths on
        command. Exists at all only because settings.allow_mock_gateway
        is explicitly true."""
        try:
            result = coordinator.execute_transaction(request)
            return {"status": "SIMULATED", "result": result}
        except (SecurityTamperError, PolicyViolationError, RazorpayDeclinedError, RazorpayAmbiguousError) as err:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))


@app.get("/api/v1/ledger/verify", tags=["Audit"])
def verify_audit_ledger() -> Dict[str, Any]:
    """Runs both cryptographic checks: tamper-evidence (hash chain) and
    non-repudiation (signatures) — deliberately kept as two separate
    results, since they prove different properties.

    active_segment_block_count reflects only the CURRENT, not-yet-
    rotated segment — LEDGER_STREAM is bounded by design (see ledger.py's
    rotation), so this is not a full historical count once any rotation
    has occurred. Older segments live in the archive directory and are
    verified independently via verify_archive(), not counted here.
    """
    chain_valid, chain_err = verify_chain()
    sig_valid, sig_err = verify_signatures()

    return {
        "tamper_evident_chain_intact": chain_valid,
        "chain_error": chain_err,
        "non_repudiation_signatures_intact": sig_valid,
        "signature_error": sig_err,
        "active_segment_block_count": len(LEDGER_STREAM),
    }