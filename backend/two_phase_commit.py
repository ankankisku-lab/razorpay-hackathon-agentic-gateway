from typing import Any, Dict

from backend.exceptions import (
    PolicyViolationError,
    SecurityTamperError,
    RazorpayDeclinedError,
    RazorpayAmbiguousError,
)
from backend.ledger import build_entry, write_ledger_entry
from backend.policy_gate import PolicyGate
from backend.razorpay_gateway import create_razorpay_order
from backend.schemas import ExecutionRequest


class TwoPhaseCommitCoordinator:
    """Phase 1 (policy_gate.evaluate) reserves budget against the
    catalog. Phase 2 (the Razorpay call) resolves synchronously: success
    commits, a confirmed decline rolls back, an ambiguous outcome is
    held for reconciliation rather than rolled back — the order may
    exist on Razorpay's side even without a clean response.
    """

    def __init__(self, policy_gate: PolicyGate):
        self.policy_gate = policy_gate

    def execute_transaction(self, request: ExecutionRequest) -> Dict[str, Any]:
        cart_payload = request.cart.model_dump()
        intent_payload = request.mandate.model_dump()
        mandate_id = request.mandate.mandate_id
        idem_key = request.mandate.idempotency_key

        passed, reason, data = self.policy_gate.evaluate(cart_payload, intent_payload, request.signature)
        if not passed:
            write_ledger_entry(build_entry(mandate_id, "POLICY_REJECTED", reason=reason))
            # Tamper means signed data was altered — a security event,
            # not the gate doing its ordinary job like every other
            # rejection reason is.
            if "TAMPER" in reason:
                raise SecurityTamperError(reason)
            raise PolicyViolationError(reason)

        write_ledger_entry(build_entry(
            mandate_id, "POLICY_APPROVED",
            amount_paise=data["verified_total_paise"],
        ))

        # The pause point auto_execute exists for: return after Phase 1
        # with the reservation held but neither committed nor rolled
        # back, so a human-in-the-loop step can confirm before any
        # money moves.
        if not request.auto_execute:
            return {
                "status": "RESERVED",
                "order_id": None,
                "amount_paise": data["verified_total_paise"],
            }

        try:
            order_res = create_razorpay_order(
                validated_payload=data,
                mandate_id=mandate_id,
                idempotency_key=idem_key,
                simulate_timeout=getattr(request, "simulate_network_timeout", False),
                simulate_decline=getattr(request, "simulate_gateway_decline", False),
            )
            self.policy_gate.commit(idem_key)
            order_id = order_res["order"]["id"]
            write_ledger_entry(build_entry(
                mandate_id, "PAYMENT_CAPTURED",
                order_id=order_id, amount_paise=data["verified_total_paise"],
            ))
            return {
                "status": "SUCCESS",
                "order_id": order_id,
                "amount_paise": data["verified_total_paise"],
            }

        except RazorpayDeclinedError as e:
            self.policy_gate.rollback(idem_key)
            write_ledger_entry(build_entry(
                mandate_id, "PAYMENT_DECLINED_ROLLED_BACK",
                amount_paise=data["verified_total_paise"], reason=str(e),
            ))
            raise

        except RazorpayAmbiguousError as e:
            # No rollback here — freeing the budget on an unresolved
            # outcome could let a second purchase get approved while a
            # first charge may already be pending on Razorpay's side.
            write_ledger_entry(build_entry(
                mandate_id, "PAYMENT_AMBIGUOUS_HELD",
                amount_paise=data["verified_total_paise"], reason=str(e),
            ))
            raise