from typing import Any, Optional, Tuple

from config import settings


class PromptGuard:
    """Screens a prompt via llama-prompt-guard-2-86m before the planner
    ever sees it. Fails closed: anything other than an exact 'benign'
    classification is treated as unsafe — including an API error,
    an unexpected response shape, or an empty string. An ambiguous
    guardrail result should block, not admit, matching the same
    default-to-caution principle used for ambiguous Razorpay outcomes
    elsewhere in this project.
    """

    def __init__(self, client: Optional[Any] = None):
        if client is not None:
            self.client = client
        else:
            from groq import Groq
            self.client = Groq(api_key=settings.groq_api_key)

    def screen(self, user_prompt: str) -> Tuple[bool, str]:
        try:
            completion = self.client.chat.completions.create(
                model=settings.guard_model,
                messages=[{"role": "user", "content": user_prompt}],
            )
            raw = (completion.choices[0].message.content or "").strip().lower()
            # Trailing punctuation only — not a prefix/startswith match.
            # startswith() would also accept "benign_injection_attempt"
            # or any other string merely beginning with "benign", which
            # only ever widens what counts as safe. Stripping a fixed
            # set of punctuation characters handles "benign." without
            # opening that door.
            classification = raw.rstrip(".:;!")
        except Exception as e:
            return False, f"guardrail_call_failed: {e}"

        is_safe = classification == "benign"
        return is_safe, classification