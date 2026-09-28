import time
from typing import Any, Dict, Optional

from backend.exceptions import (
    PolicyViolationError,
    RazorpayAmbiguousError,
    RazorpayDeclinedError,
    ReservationNotFoundError,
    SecurityTamperError,
)
from backend.ledger import build_entry, write_ledger_entry
from backend.policy_gate import PolicyGate
from backend.razorpay_gateway import create_razorpay_order
from backend.schemas import ExecutionRequest
from backend.state_store import AWAITING_CONFIRMATION


class TwoPhaseCommitCoordinator:
    """Phase 1 (policy_gate.evaluate) reserves budget against the
    catalog. Phase 2 (the Razorpay call) resolves synchronously: success
    commits, a confirmed decline rolls back, an ambiguous outcome is
    held for reconciliation rather than rolled back — the order may
    exist on Razorpay's side even without a clean response.
    """

    def __init__(self, policy_gate: PolicyGate):
        self.policy_gate = policy_gate

    def execute_transaction(self, request: ExecutionRequest, requester_user_id: Optional[str] = None) -> Dict[str, Any]:
        """requester_user_id is who is actually asking, and the mandate
        must have been issued to them. The HTTP layer always passes the
        API-key-authenticated user, so a caller can no longer name
        themselves. The fallback to request.user_id exists only for
        in-process callers that are already inside the trust boundary —
        the demo, the dashboard, tests — which have no key to present."""
        requester = requester_user_id if requester_user_id is not None else request.user_id
        cart_payload = request.cart.model_dump()
        intent_payload = request.mandate.model_dump()
        mandate_id = request.mandate.mandate_id
        idem_key = request.mandate.idempotency_key

        passed, reason, data = self.policy_gate.evaluate(
            cart_payload, intent_payload, request.signature,
            requester_user_id=requester,
        )
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
        # back, so a human-in-the-loop step can confirm before any money
        # moves. Parked as AWAITING_CONFIRMATION in the store, so it
        # survives a restart and can be finished with confirm/cancel —
        # previously nothing could ever resolve it, and its budget stayed
        # reserved forever.
        if not request.auto_execute:
            self.policy_gate.mark_awaiting_confirmation(idem_key)
            return {
                "status": "RESERVED",
                "order_id": None,
                "amount_paise": data["verified_total_paise"],
                "idempotency_key": idem_key,
            }

        return self._settle(
            mandate_id, idem_key, data,
            simulate_timeout=getattr(request, "simulate_network_timeout", False),
            simulate_decline=getattr(request, "simulate_gateway_decline", False),
        )

    def confirm_reservation(self, idempotency_key: str, requester_user_id: str) -> Dict[str, Any]:
        """Human-in-the-loop approval: runs Phase 2 for a reservation
        parked by auto_execute=False. Same user binding, same expiry
        rule and the same settle path as an auto-executed purchase —
        a confirmation is a deferred execution, not a different one."""
        reservation = self._owned_reservation(idempotency_key, requester_user_id)
        mandate_id = reservation["mandate_id"]

        # Expiry is re-checked at confirmation time, not just at
        # reservation time — a human approving an hour-old draft must
        # not settle a mandate that has since expired.
        if reservation["expires_at"] <= int(time.time()):
            if self.policy_gate.rollback(idempotency_key, (AWAITING_CONFIRMATION,)):
                write_ledger_entry(build_entry(
                    mandate_id, "CONFIRMATION_EXPIRED_RELEASED",
                    amount_paise=reservation["amount_paise"],
                ))
            raise PolicyViolationError(f"MANDATE_EXPIRED_REJECT: IntentMandate '{mandate_id}' expired before confirmation.")

        if not self.policy_gate.claim_for_confirmation(idempotency_key):
            raise PolicyViolationError(
                f"RESERVATION_STATE_REJECT: Reservation is '{reservation['status']}', not awaiting confirmation."
            )

        write_ledger_entry(build_entry(mandate_id, "CONFIRMATION_ACCEPTED", amount_paise=reservation["amount_paise"]))
        return self._settle(mandate_id, idempotency_key, {
            "cart_id": reservation["cart_id"],
            "mandate_id": mandate_id,
            "verified_total_paise": reservation["amount_paise"],
            "currency": reservation["currency"],
        })

    def cancel_reservation(self, idempotency_key: str, requester_user_id: str) -> Dict[str, Any]:
        """Releases a reservation still awaiting confirmation. Only that
        state: once Phase 2 has started, the outcome belongs to Razorpay
        and the settle/reconcile paths, not to a cancel button."""
        reservation = self._owned_reservation(idempotency_key, requester_user_id)
        if not self.policy_gate.rollback(idempotency_key, (AWAITING_CONFIRMATION,)):
            raise PolicyViolationError(
                f"RESERVATION_STATE_REJECT: Reservation is '{reservation['status']}', not awaiting confirmation."
            )
        write_ledger_entry(build_entry(
            reservation["mandate_id"], "CONFIRMATION_CANCELLED",
            amount_paise=reservation["amount_paise"],
        ))
        return {"status": "CANCELLED", "order_id": None, "amount_paise": reservation["amount_paise"]}

    def _owned_reservation(self, idempotency_key: str, requester_user_id: str) -> Dict[str, Any]:
        reservation = self.policy_gate.get_reservation(idempotency_key)
        if reservation is None:
            raise ReservationNotFoundError(f"No reservation for idempotency key '{idempotency_key}'.")
        if reservation["user_id"] != requester_user_id:
            raise PolicyViolationError("USER_BINDING_REJECT: Reservation belongs to a different user.")
        return reservation

    def _settle(
        self,
        mandate_id: str,
        idem_key: str,
        data: Dict[str, Any],
        simulate_timeout: bool = False,
        simulate_decline: bool = False,
    ) -> Dict[str, Any]:
        """Phase 2, shared by auto-executed and human-confirmed purchases."""
        try:
            order_res = create_razorpay_order(
                validated_payload=data,
                mandate_id=mandate_id,
                idempotency_key=idem_key,
                order_cache=self.policy_gate.store,
                simulate_timeout=simulate_timeout,
                simulate_decline=simulate_decline,
            )
            order_id = order_res["order"]["id"]
            self.policy_gate.commit(idem_key, order_id=order_id)
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
            # Marked HELD so the webhook and the reconciler can find it.
            self.policy_gate.mark_held(idem_key)
            write_ledger_entry(build_entry(
                mandate_id, "PAYMENT_AMBIGUOUS_HELD",
                amount_paise=data["verified_total_paise"], reason=str(e),
            ))
            raise
