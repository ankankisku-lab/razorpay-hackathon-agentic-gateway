import re
from typing import List, Pattern, Tuple


class PatternGuard:
    """Deterministic keyword/regex pre-filter for prompt-injection
    patterns confirmed to evade llama-prompt-guard-2-86m by direct
    testing against the real Groq API: fake system/admin tags,
    roleplay-based persona hijacks, and privilege-escalation phrasing
    all scored under 0.2 (most under 1%) from the real model despite
    being genuine attacks — nowhere near any threshold that could
    plausibly be tuned to catch them without flooding false positives
    on benign traffic scored in that same range.

    NOT a replacement for the ML guard, and not a general jailbreak
    solution — a complementary layer for exactly the gap the real eval
    run exposed. This is a known arms race: a finite pattern list can
    always be evaded by rephrasing. It raises the bar for the specific,
    confirmed gap; it does not close prompt injection as a problem.
    """

    PATTERNS: List[Pattern] = [
        # Fake system/admin tags and delimiter smuggling — a genuine
        # shopping request never legitimately contains markup like this.
        # Broadened from literal "system|admin|override" tag names to
        # any tag containing a privilege/control-flavored word, after
        # testing showed <prompt_injection>/<auth_bypass>-style tags
        # slip past a literal name match.
        re.compile(r"<\s*/?\s*\w*(system|admin|override|bypass|injection)\w*\s*>", re.IGNORECASE),
        re.compile(r"\[\s*\w*(admin|root|system|override|bypass|debug|developer)\w*\s*\]", re.IGNORECASE),

        # Expand "act as" to catch developer / tester / QA / engineer personas:
        re.compile(r"\bact as (an?|the)?\s*[\w\s]{0,25}?(developer|tester|qa|engineer|debugger|admin|unrestricted)\b"),

        # Catch zero-price / zero-rupee semantic bypass attempts directly:
        re.compile(r"\b(zero|0)[- ]*(rupee|rs|price|cost|amount)\b"),
        
        # Llama chat-template control tokens — if these can be injected
        # directly into a prompt, they could confuse how the underlying
        # model parses instruction boundaries, independent of anything
        # PromptGuard itself would classify. <<SYS>> is a second real
        # Llama sentinel besides [INST], easy to miss if only one is
        # covered.
        re.compile(r"\[\s*/?\s*INST\s*\]", re.IGNORECASE),
        re.compile(r"<<\s*/?\s*SYS\s*>>", re.IGNORECASE),
        # Generic multi-dash delimiter smuggling — "---BEGIN
        # ADMIN---"/"---START DEBUG---" etc. Matching the dash-fence
        # structure itself, not a specific word after it, since testing
        # showed a fixed word list (just "OVERRIDE") misses new
        # variants trivially.
        re.compile(r"-{3,}\s*(BEGIN|START|END)\b", re.IGNORECASE),
        # Template-injection style curly-brace smuggling.
        re.compile(r"\{\{\s*\w*(system|admin|override|bypass)\w*\s*\}\}", re.IGNORECASE),
        # Privilege-escalation / mode-switching phrasing. \W+ instead of
        # \s+ between words — testing showed "DEVELOPER_MODE" (an
        # underscore, not a space) slips past a whitespace-only \s+.
        re.compile(r"\b(developer|debug|admin|root)\W+(mode|access)\b", re.IGNORECASE),
        re.compile(r"\bsystem\W+override\b", re.IGNORECASE),
        re.compile(r"\bpriority[_\s]?bypass\b", re.IGNORECASE),
        # Generalized "disregard/disable X limits/guardrails/caps"
        # phrasing — catches variants beyond any one exact wording.
        # Deliberately excludes "remove" from the verb list: testing
        # showed "I want to remove the item limit from my cart" is a
        # plausible genuine customer question, not an attack — a
        # narrower verb list here trades some recall for not blocking
        # ordinary support questions.
        re.compile(r"\b(disregard|ignore|disable|bypass|clear)\b.{0,30}\b(limit|guardrail|cap|safety|check)s?\b", re.IGNORECASE),
        # Roleplay / persona-hijack framing. Broadened beyond "act as"/
        # "you are a[n] unrestricted" after testing showed "roleplay
        # as", "imagine you are", "assume the identity of", and "you
        # are now in simulation mode"-style framings all slip past the
        # narrower originals.
        re.compile(r"\byou are an? (unrestricted|jailbroken|uncensored)\b", re.IGNORECASE),
        re.compile(r"\bact as (an?|the) .*(debugger|unrestricted|admin)\b", re.IGNORECASE),
        re.compile(r"\bpretend (the|that)\b.*\b(price|budget|catalog|free|zero)\b", re.IGNORECASE),
        re.compile(r"\bpretend you are\b", re.IGNORECASE),
        re.compile(r"\b(roleplay|role[- ]?play) as\b", re.IGNORECASE),
        re.compile(r"\bimagine you are\b", re.IGNORECASE),
        re.compile(r"\bassume the identity of\b", re.IGNORECASE),
        re.compile(r"\byou are (now |operating )?in .*(simulation|unrestricted|maintenance)\b", re.IGNORECASE),
        re.compile(r"\bsimulate an? (approved|authorized|verified)\b", re.IGNORECASE),
        # "Overriding checkout/limits/policy/spend/budget" — specific
        # enough that it's very unlikely in genuine customer speech,
        # unlike broader "act as a developer/agent/bot" alternatives
        # tested and rejected for false-positiving on plausible benign
        # phrasing ("act as my shopping agent", "act as a beta tester").
        re.compile(r"\boverriding\s+(checkout|limits|policy|spend|budget)\b", re.IGNORECASE),
        # Secret/key exfiltration attempts
        re.compile(r"\b(print|reveal|show|output)\b.*\b(private key|signing key|secret|credential|password)\b", re.IGNORECASE),
    ]

    def screen(self, user_prompt: str) -> Tuple[bool, str]:
        for pattern in self.PATTERNS:
            if pattern.search(user_prompt):
                return False, f"pattern_match={pattern.pattern[:50]}"
        return True, "no_pattern_match"


class CombinedGuard:
    """Blocks if EITHER the ML guard or the pattern guard flags the
    prompt — this must be an OR, not an AND. Requiring both to agree
    would only re-introduce the exact gap this exists to close, since
    the confirmed failure mode is the ML guard alone missing genuine
    attacks (scoring them as confidently benign), not the reverse.

    Pattern guard runs first: it's a local regex check (microseconds),
    the ML guard is a real network round-trip (285ms+ measured against
    the actual API) — checking the free layer first avoids an
    unnecessary API call whenever the cheap check already has an
    answer.
    """

    def __init__(self, ml_guard, pattern_guard=None):
        self.ml_guard = ml_guard
        self.pattern_guard = pattern_guard or PatternGuard()

    def screen(self, user_prompt: str) -> Tuple[bool, str]:
        pattern_safe, pattern_detail = self.pattern_guard.screen(user_prompt)
        if not pattern_safe:
            return False, f"pattern_guard: {pattern_detail}"
        return self.ml_guard.screen(user_prompt)