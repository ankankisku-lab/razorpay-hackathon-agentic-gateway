from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class MandateStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    ABORTED = "ABORTED"


class IntentMandate(BaseModel):
    """Pure authorization — what's permitted, independent of any single
    purchase attempt. Deliberately carries no sku/quantity: keeping cart
    contents out of the mandate is what lets one mandate be checked
    against several purchase attempts within its budget and time window
    (the session-spend-cap logic depends on this separation existing).
    """
    mandate_id: str
    idempotency_key: str
    max_authorized_budget_paise: int = Field(..., gt=0)
    expires_at: int  # mandate is invalid at/after this unix timestamp
    user_intent_summary: str


class CartItem(BaseModel):
    sku: str
    name: str
    quantity: int = Field(default=1, ge=1)
    unit_price_paise: int = Field(..., ge=0)
    line_total_paise: int = Field(..., ge=0)

    @model_validator(mode="after")
    def _line_total_matches_unit_price(self):
        # Storing both fields without enforcing agreement is exactly the
        # class of bug that let a claimed price silently diverge from
        # the real one elsewhere in this project — same fix here.
        expected = self.unit_price_paise * self.quantity
        if self.line_total_paise != expected:
            raise ValueError(
                f"line_total_paise ({self.line_total_paise}) does not match "
                f"unit_price_paise * quantity ({expected})"
            )
        return self


class CartMandate(BaseModel):
    """The specific items/prices being claimed for one purchase attempt
    — checked against the signed catalog and against an IntentMandate's
    budget ceiling, but never merged into it (see IntentMandate)."""
    cart_id: str
    mandate_id: str
    items: List[CartItem]
    total_amount_paise: int = Field(..., ge=0)

    @model_validator(mode="after")
    def _total_matches_line_items(self):
        expected = sum(item.line_total_paise for item in self.items)
        if self.total_amount_paise != expected:
            raise ValueError(
                f"total_amount_paise ({self.total_amount_paise}) does not "
                f"match sum of item line totals ({expected})"
            )
        return self


class ExecutionRequest(BaseModel):
    """Real production request shape. user_prompt/user_id are kept (not
    just mandate+cart) because the intent layer's explainability story
    depends on being able to trace a gate decision back to what the
    user actually asked for, not just what the agent derived from it.

    No simulate_* fields here — see SimulatedExecutionRequest.
    """
    user_prompt: str
    user_id: str
    mandate: IntentMandate
    cart: CartMandate
    auto_execute: bool = True


class SimulatedExecutionRequest(ExecutionRequest):
    """Debug-only. Only ever construct this from a route gated behind
    settings.allow_mock_gateway — never accept these fields on the real
    transaction path."""
    simulate_network_timeout: bool = False
    simulate_gateway_decline: bool = False


class LedgerBlock(BaseModel):
    """Typed ledger entry. previous_hash/block_hash prove the chain
    wasn't altered after the fact (tamper-evidence). signature/
    signer_public_key prove who produced the entry (non-repudiation) —
    a different property, verified independently of chain integrity.
    Both are Optional here only because genesis handling may construct
    a block before signing is wired in; ledger.py should never write a
    block with these unset once signing is live.
    """
    index: int = Field(..., ge=0)
    timestamp: float
    event_type: str
    mandate_id: str  # 'ROOT' for the genesis block
    order_id: Optional[str] = None
    amount_paise: int = Field(default=0, ge=0)
    payload: Dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    block_hash: str
    signature: Optional[str] = None
    signer_public_key: Optional[str] = None