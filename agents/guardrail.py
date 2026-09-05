from typing import Any, Optional, Tuple

from config import settings


class PromptGuard:
    """Screens a prompt via llama-prompt-guard-2-86m before the planner
    ever sees it.

    Confirmed via live testing against the real Groq API: this model
    returns a raw probability-of-malicious score as a string (e.g.
    "0.0015442771837115288"), NOT a text label like "benign"/
    "malicious" as the model card's description of the underlying
    classifier initially suggested. Meta's own reference usage computes
    this same score via softmax(logits)[0, 1] — index 1 being the
    malicious class — and compares it to a threshold; a LOW score means
    safe. Getting this backwards or comparing it as a string (as an
    earlier version of this file did) means every prompt gets rejected,
    since a numeric string never equals "benign" — a demo-breaking bug
    that only surfaced by actually calling the real API, not by
    reasoning from the model card alone.

    Fails closed on anything that's neither a parseable score nor a
    recognized text label — an ambiguous guardrail result should block,
    not admit, matching the same default-to-caution principle used for
    ambiguous Razorpay outcomes elsewhere in this project.
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
            raw = (completion.choices[0].message.content or "").strip()
        except Exception as e:
            return False, f"guardrail_call_failed: {e}"

        # Primary path: a probability score, confirmed as the real
        # response shape. Low score = safe.
        try:
            malicious_score = float(raw)
            is_safe = malicious_score < settings.prompt_guard_threshold
            return is_safe, f"malicious_score={malicious_score}"
        except ValueError:
            pass

        # Fallback path: some deployment or future model version might
        # return a text label instead — handle both rather than
        # assuming only one is ever possible. Trailing punctuation only,
        # not a prefix match (see the earlier startswith() vs rstrip()
        # discussion) — startswith would also accept
        # "benign_injection_attempt" as safe, which only ever widens
        # what counts as safe.
        normalized = raw.lower().rstrip(".:;!")
        if normalized == "benign":
            return True, normalized
        if normalized in ("malicious", "injection", "jailbreak"):
            return False, normalized

        # Neither a parseable score nor a recognized label.
        return False, f"unrecognized_guardrail_response: {raw!r}"