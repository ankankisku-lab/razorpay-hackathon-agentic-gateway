class GatewayBaseError(Exception):
    """Base for every gateway runtime error — lets FastAPI (or anything
    else) catch all of them uniformly with `except GatewayBaseError`,
    while each subclass below still supports its own specific handler
    for a distinct HTTP status / response shape.
    """


class PolicyViolationError(GatewayBaseError):
    """A mandate failed an ordinary deterministic check — budget, price
    integrity, session cap, expiry. Routine rejection, not a security
    event: the gate did its job correctly.
    """


class SecurityTamperError(GatewayBaseError):
    """Catalog signature mismatch, or a broken ledger hash chain /
    invalid signature. Kept separate from PolicyViolationError on
    purpose — this means someone or something altered signed data, not
    just that an order didn't qualify. Warrants different handling
    (alerting, possibly refusing to serve traffic) than a routine
    rejection does.
    """


class RazorpayDeclinedError(GatewayBaseError):
    """Razorpay explicitly rejected the request. Confirmed outcome —
    safe to roll back a reservation on this."""


class RazorpayAmbiguousError(GatewayBaseError):
    """Timeout, dropped connection, or 5xx. Outcome unknown — the order
    may exist on Razorpay's side even without a clean response. Never
    roll back a reservation on this; hold it for reconciliation."""


class PromptInjectionDetectedError(GatewayBaseError):
    """The guardrail classifier flagged the incoming prompt before the
    planner ever saw it. Raised, not returned as a tuple, because this
    must stop the pipeline outright — there's no partial/degraded way
    to proceed with a flagged prompt the way there is with, say, a
    budget rejection."""