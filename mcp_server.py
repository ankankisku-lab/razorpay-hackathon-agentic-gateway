import json
from mcp.server.fastmcp import FastMCP

from agents.buyer_agent import BuyerAgent
from agents.guardrail import PromptGuard
from agents.intent_layer import IntentLayer
from agents.planner import Planner
from backend.ledger import LEDGER_STREAM, verify_chain, verify_signatures
from backend.policy_gate import PolicyGate, load_catalog
from backend.schemas import CartMandate, IntentMandate, SimulatedExecutionRequest
from backend.two_phase_commit import TwoPhaseCommitCoordinator

# Initialize MCP application
mcp = FastMCP("AgenticCommerceGateway")

# Isolated instances for the MCP runtime
catalog = load_catalog()
policy_gate = PolicyGate(catalog=catalog)
coordinator = TwoPhaseCommitCoordinator(policy_gate=policy_gate)

guard = PromptGuard()
planner = Planner()
buyer_agent = BuyerAgent()
intent_layer = IntentLayer(guardrail=guard, planner=planner, buyer_agent=buyer_agent)


@mcp.tool()
def search_catalog(query: str, top_k: int = 3) -> str:
    """
    Search the verified merchant catalog for products, SKUs, and official unit prices.

    Args:
        query: Item description or keywords (e.g. 'boAt earphones', 'wireless mouse').
        top_k: Maximum number of matches to retrieve (default: 3).
    """
    try:
        # Check retriever attribute on BuyerAgent
        if hasattr(buyer_agent, "retriever") and hasattr(buyer_agent.retriever, "search"):
            matches = buyer_agent.retriever.search(query, top_k=top_k)
        elif hasattr(buyer_agent, "retriever") and hasattr(buyer_agent.retriever, "retrieve"):
            matches = buyer_agent.retriever.retrieve(query, top_k=top_k)
        elif hasattr(buyer_agent, "search"):
            matches = buyer_agent.search(query, top_k=top_k)
        else:
            # Direct semantic/catalog fallback
            query_words = set(query.lower().split())
            scored = []
            for sku, item in catalog.items():
                text = f"{item.get('name', '')} {item.get('description', '')} {' '.join(item.get('tags', []))}".lower()
                overlap = sum(1 for w in query_words if w in text)
                scored.append(({**item, "sku": sku}, float(overlap)))
            scored.sort(key=lambda pair: pair[1], reverse=True)
            matches = scored[:top_k]

        # Format cleaned JSON
        formatted = []
        for match in matches:
            item = match[0] if isinstance(match, (tuple, list)) else match
            formatted.append({
                "sku": item.get("sku"),
                "name": item.get("name"),
                "unit_price_paise": item.get("unit_price_paise"),
                "currency": item.get("currency", "INR"),
                "category": item.get("category", ""),
            })

        return json.dumps({"status": "SUCCESS", "results": formatted}, indent=2)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})


@mcp.tool()
def issue_signed_mandate(user_prompt: str, user_id: str = "agent_mcp_user") -> str:
    """
    Screen prompt for injection, resolve cart SKUs, check budget ceilings,
    and produce an Ed25519-signed authorization mandate envelope.

    Args:
        user_prompt: The raw user intent (e.g. 'Buy boAt earphones under 1000').
        user_id: The ID of the ordering user.
    """
    try:
        req = intent_layer.process(user_prompt=user_prompt, user_id=user_id, auto_execute=True)
        return json.dumps({
            "status": "APPROVED",
            "mandate": req.mandate.model_dump(),
            "cart": req.cart.model_dump(),
            "signature": req.signature,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "REJECTED", "reason": str(e)})


@mcp.tool()
def execute_two_phase_commit(
    user_prompt: str,
    user_id: str,
    mandate: dict,
    cart: dict,
    signature: str,
    auto_execute: bool = True,
) -> str:
    """
    Execute transaction under Two-Phase Commit: verifies Ed25519 signature, enforces
    session budget caps, and creates the upstream Razorpay order.

    Args:
        user_prompt: Original intent string.
        user_id: User identifier.
        mandate: The IntentMandate dictionary object.
        cart: The CartMandate dictionary object with items and price.
        signature: The Ed25519 cryptographic signature string.
        auto_execute: Whether to proceed to Phase 2 (payment order creation) or hold reservation.
    """
    try:
        parsed_mandate = IntentMandate(**mandate)
        parsed_cart = CartMandate(**cart)

        exec_req = SimulatedExecutionRequest(
            user_prompt=user_prompt,
            user_id=user_id,
            mandate=parsed_mandate,
            cart=parsed_cart,
            signature=signature,
            auto_execute=auto_execute,
        )

        result = coordinator.execute_transaction(exec_req)
        return json.dumps({"status": "COMMITTED", "result": result}, indent=2)

    except Exception as e:
        return json.dumps({"status": "REJECTED_OR_HELD", "error": str(e)})


@mcp.tool()
def inspect_audit_ledger() -> str:
    """
    Inspect recent transactions and cryptographic hash-chain integrity of the tamper-evident ledger.
    """
    chain_ok, chain_msg = verify_chain()
    sig_ok, sig_msg = verify_signatures()

    recent_blocks = LEDGER_STREAM[-5:] if LEDGER_STREAM else []
    return json.dumps({
        "chain_integrity": "INTACT" if chain_ok else "BROKEN",
        "signature_integrity": "VALID" if sig_ok else "INVALID",
        "recent_blocks": recent_blocks,
    }, indent=2)


if __name__ == "__main__":
    mcp.run()