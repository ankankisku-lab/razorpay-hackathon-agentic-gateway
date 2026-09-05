import json
from typing import Any, Dict, Optional, Type

from pydantic import BaseModel, Field

from agents.buyer_agent import BuyerAgent
from agents.guardrail import PromptGuard
from agents.planner import Planner
from agents.schema_utils import to_strict_schema
from backend.exceptions import PromptInjectionDetectedError
from backend.schemas import ExecutionRequest
from config import settings
from retrieval.catalog_retriever import CatalogRetriever


class IntentLayer:
    """The missing piece between a raw user prompt and something
    TwoPhaseCommitCoordinator can execute: guardrail screens first,
    planner extracts structured intent, buyer_agent resolves that
    intent against the catalog and signs a mandate — this class's own
    job is just wiring those three together and producing a real
    ExecutionRequest, not doing any of their work itself.
    """

    def __init__(
        self,
        guardrail: Optional[PromptGuard] = None,
        planner: Optional[Planner] = None,
        buyer_agent: Optional[BuyerAgent] = None,
    ):
        self.guardrail = guardrail if guardrail is not None else PromptGuard()
        self.planner = planner if planner is not None else Planner()
        self.buyer_agent = buyer_agent if buyer_agent is not None else BuyerAgent()

    def process(self, user_prompt: str, user_id: str, auto_execute: bool = True) -> ExecutionRequest:
        # Guardrail runs before the planner ever sees the prompt — the
        # whole point of screening first is that a flagged prompt never
        # reaches the model that would otherwise act on it.
        is_safe, classification = self.guardrail.screen(user_prompt)
        if not is_safe:
            raise PromptInjectionDetectedError(
                f"Guardrail flagged prompt as unsafe: {classification}"
            )

        intent = self.planner.draft_intent(user_prompt)

        mandate_result = self.buyer_agent.create_mandate(
            user_prompt=user_prompt,
            user_id=user_id,
            max_budget_paise=intent["max_budget_paise"],
            quantity=intent.get("quantity", 1),
            query=intent.get("search_query"),
        )

        return ExecutionRequest(
            user_prompt=user_prompt,
            user_id=user_id,
            mandate=mandate_result["mandate"],
            cart=mandate_result["cart"],
            signature=mandate_result["signature"],
            auto_execute=auto_execute,
        )


class IntentExtractionResult(BaseModel):
    selected_sku: str = Field(description="The exact SKU chosen from the candidate catalog list")
    quantity: int = Field(default=1, ge=1, description="Quantity extracted from user prompt")
    reasoning: str = Field(description="Brief explanation of why this item was selected")


class LLMSelectionIntentLayer:
    """A different tool from IntentLayer, not a replacement: this lets
    an LLM choose among FAISS-retrieved candidates and extract quantity
    in one call, with a hard check that the chosen SKU actually exists
    in the candidate pool. IntentLayer.process() instead never lets an
    LLM choose a SKU at all — Planner only extracts a search query,
    and BuyerAgent.select_product() picks deterministically by budget
    math. Which one to use is a real design choice, not a version
    upgrade of the other.

    NOTE: budget compliance here is a prompt instruction to the LLM,
    not a Python-level check — nothing in resolve() re-verifies that
    the chosen item's price x quantity actually fits max_budget_paise.
    That's fine ONLY if whatever consumes this result's output still
    passes through PolicyGate before any money moves, since the gate
    is what actually enforces the budget deterministically.
    """

    def __init__(
        self,
        retriever: Optional[CatalogRetriever] = None,
        guard: Optional[PromptGuard] = None,
        client: Optional[Any] = None,
        model_name: Optional[str] = None,
    ):
        self.retriever = retriever if retriever is not None else CatalogRetriever()
        self.guard = guard if guard is not None else PromptGuard()
        self.model_name = model_name or settings.planner_model

        if client is not None:
            self.client = client
        else:
            from groq import Groq
            self.client = Groq(api_key=settings.groq_api_key)

    def resolve(
        self,
        user_prompt: str,
        max_budget_paise: int,
        top_k: int = 3,
    ) -> Dict[str, Any]:
        is_safe, label = self.guard.screen(user_prompt)
        if not is_safe:
            raise PromptInjectionDetectedError(f"Prompt failed security screening: flagged as '{label}'")

        matches = self.retriever.search(user_prompt, top_k=top_k)
        if not matches:
            raise ValueError(f"No catalog items matched query: '{user_prompt}'")

        candidates = [item for item, _ in matches]
        candidates_summary = [
            {
                "sku": c["sku"],
                "name": c.get("name"),
                "unit_price_paise": c.get("unit_price_paise", 0),
                "description": c.get("description"),
            }
            for c in candidates
        ]

        system_instruction = (
            "You are an e-commerce purchasing agent. Analyze the user prompt and select "
            "the single best matching SKU from the candidate list that fits within the spend cap. "
            "Extract the target quantity (default to 1 if unspecified)."
        )
        user_content = (
            f"User Prompt: {user_prompt}\n"
            f"Max Spend Cap: {max_budget_paise} paise\n"
            f"Candidate Items: {json.dumps(candidates_summary)}"
        )

        completion = self.client.chat.completions.create(
            model=self.model_name,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "intent_extraction",
                    "strict": True,
                    "schema": to_strict_schema(IntentExtractionResult),
                },
            },
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_content},
            ],
            temperature=0.0,
        )

        raw_json = completion.choices[0].message.content or "{}"
        try:
            parsed = IntentExtractionResult.model_validate_json(raw_json)
        except Exception as err:
            raise ValueError(f"Failed to parse LLM intent response: {err} | Raw: {raw_json}")

        candidate_map = {c["sku"]: c for c in candidates}
        selected_item = candidate_map.get(parsed.selected_sku)
        if not selected_item:
            raise ValueError(
                f"LLM returned SKU '{parsed.selected_sku}' which is not in the candidate pool."
            )

        return {
            "item": selected_item,
            "quantity": parsed.quantity,
            "reasoning": parsed.reasoning,
        }