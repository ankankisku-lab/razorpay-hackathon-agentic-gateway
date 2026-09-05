from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from agents.schema_utils import to_strict_schema
from config import settings


class DraftIntentOutput(BaseModel):
    search_query: str = Field(
        description="Clean, normalized product search keywords extracted from user prompt"
    )
    max_budget_paise: int = Field(
        description="User-authorized budget cap in paise. If not mentioned, infer from context or use default"
    )
    quantity: int = Field(
        default=1,
        ge=1,
        description="Total quantity requested by user",
    )


SYSTEM_PROMPT = (
    "You are an intent extraction parser for an e-commerce assistant. "
    "Extract the search keywords, the maximum authorized budget in paise "
    "(default to 100000 paise / \u20b91000 if not specified), and target quantity "
    "(default to 1). Return strictly valid JSON."
)


class Planner:
    """Extracts structured search queries, budget constraints, and
    quantity from user prompts — never a SKU, never a signed mandate.
    Keeping selection out of this class is what lets BuyerAgent's
    deterministic budget filtering (or LLMSelectionIntentLayer's
    LLM-driven candidate choice) be swapped independently of how intent
    gets extracted in the first place.
    """

    def __init__(self, client: Optional[Any] = None, model_name: Optional[str] = None):
        self.model_name = model_name or settings.planner_model
        if client is not None:
            self.client = client
        else:
            from groq import Groq
            self.client = Groq(api_key=settings.groq_api_key)

    def draft_intent(self, user_prompt: str) -> Dict[str, Any]:
        """Returns {"search_query": str, "max_budget_paise": int,
        "quantity": int}. Uses the same to_strict_schema helper
        LLMSelectionIntentLayer uses — one shared way of turning a
        Pydantic model into a Groq-strict-mode-compliant schema,
        instead of each caller hand-writing (and risking drifting) its
        own equivalent dict.
        """
        completion = self.client.chat.completions.create(
            model=self.model_name,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "draft_intent",
                    "strict": True,
                    "schema": to_strict_schema(DraftIntentOutput),
                },
            },
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.0,
        )
        raw_content = completion.choices[0].message.content or "{}"
        try:
            parsed = DraftIntentOutput.model_validate_json(raw_content)
        except Exception as err:
            raise ValueError(f"Failed to parse Planner output: {err} | Raw: {raw_content}")
        return parsed.model_dump()