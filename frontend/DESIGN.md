# Gateway Demo: UI/UX Guideline

Status: **v1.2, built and verified in a browser.** Section 12 lists the findings from cross-checking v1 against the backend. Section 13 lists what testing the built UI in Edge found and fixed.

## 1. Purpose and audience

The demo exists to make one idea visible in under five minutes: **the AI proposes, the rules approve.** A purchase request goes in. The viewer sees what the AI made of it, how deterministic code turned that into a signed mandate, which policy checks it passed, and how it settled (or didn't) on Razorpay. Every step lands in a tamper-evident audit log.

| Audience | What they need from the screen |
|---|---|
| Interviewer (technical) | Real API calls, real verdicts, raw reason codes and payloads on demand |
| Interviewer (consulting / business) | A plain-language story: risk → control → outcome, readable without knowing the code |
| The presenter | Repeatable scenarios one click away, a reset, nothing that can stall mid-demo |

## 2. Design principles

1. **Show the trust boundary.** Everything the AI produced sits in one visual zone (violet, labelled *AI proposal*). Everything code decided sits in another (teal, labelled *Rule decision*). The two never blur.
2. **Truthful by construction.** Every verdict, score, amount, ID and duration on screen comes from a backend response. Simulated events (gateway timeout or decline, webhooks) carry a visible **Simulated** tag. There is no decorative "progress" animation that implies something happened when it didn't.
3. **Plain language first, detail on demand.** Each result leads with one human sentence. The raw reason code, payloads and hashes sit one click away.
4. **Failure is a first-class outcome.** Blocked, held, declined and duplicate states get the same design care as success.
5. **One story at a time.** One pipeline view tells one request's story top to bottom; presets switch stories.

## 3. Layout

Desktop first (1280–1600 px wide), three columns under a top bar:

```
┌────────────────────────────────── Top bar ───────────────────────────────────┐
│ Agentic Commerce Gateway  [AI: Live]  [Razorpay: Sandbox]  Acting as [Alice▾] │
│                                                              [Reset demo]     │
├──────────── 320px ────┬────────────── flexible ─────────────┬──── 360px ──────┤
│ AGENT CONSOLE         │ "What to watch" hint (per scenario) │ LIVE STATE      │
│ Scenarios             │ ① Screening          AI proposal    │ Spending meter  │
│  Happy path           │ ② Understanding      AI proposal    │ Reservations    │
│  Attacks              │ ③ Product match      Rule decision  │  + actions      │
│  Failures             │ ④ Signed mandate     Rule decision  │ Audit ledger    │
│ Prompt                │   [Execute] [Attack ▾] [Simulate ▾] │  [Verify chain] │
│ [ ] Require approval  │ ⑤ Policy checks ×9   Rule decision  │                 │
│ [Draft mandate]       │ ⑥ Settlement         Razorpay       │                 │
│                       │ Outcome banner (aria-live)          │                 │
└───────────────────────┴─────────────────────────────────────┴─────────────────┘
```

Responsive behaviour: below 1100 px the Live State column moves under the pipeline. Below 760 px everything stacks into one column, and the scenario list becomes compact.

## 4. The flow: draft, then execute

This mirrors the real API. The signed request goes back to the client between steps, and that round trip is exactly what the signature protects.

1. **Draft** (`POST /api/v1/demo/intent`) fills stages ①–④.
2. **Execute** (`POST /api/v1/execute`, or the simulate route for failure scenarios) fills stages ⑤–⑥.

While a call runs, show **one** honest running state ("Screening, planning and matching…" plus a live elapsed-seconds counter). Stages appear when the response arrives, each labelled with its **measured** duration from the backend trace. The ML guard alone took about 2 s per call through Groq, so expect a draft to take 3–6 s.

| # | Stage | Zone | Shows | Details |
|---|---|---|---|---|
| ① | Screening | AI proposal | Regex filter verdict, and the ML classifier verdict with its score (or "not run" if the regex already blocked) | Matched pattern, raw score, threshold 0.5 |
| ② | Understanding | AI proposal | Extracted product query, budget (₹), quantity | Raw JSON |
| ③ | Product match | Rule decision | Top-3 catalog matches with similarity score and whether each fits the budget. The chosen one is marked, with the rule: *first match whose total fits the budget* | Prices, scores |
| ④ | Signed mandate | Rule decision | Item × quantity, total, mandate budget, **expiry countdown** (5 minutes), truncated signature | Full request JSON |
| ⑤ | Policy checks | Rule decision | The 9 checks, derived from the gate's answer (see below) | Reason code + message |
| ⑥ | Settlement | Razorpay | Order ID / awaiting approval / held / declined | Raw response |

**How the nine checks are displayed.** The gate returns either *approved* or the **first** failing reason, not a list of per-check results. So the UI shows:
- approved: all nine ✓;
- rejected with reason X: checks before X ✓, X ✗, everything after "not reached" (grey).

This is accurate as long as the UI's order matches the gate's code order:

| # | Check | Reason codes |
|---|---|---|
| 1 | Request format valid | `SCHEMA_REJECT` |
| 2 | Signature intact | `MANDATE_SIGNATURE_TAMPER_REJECT` |
| 3 | Mandate belongs to you | `USER_BINDING_REJECT` |
| 4 | Not expired | `MANDATE_EXPIRED_REJECT` |
| 5 | Product data signed by merchant | `CATALOG_REJECT`, `CATALOG_CONFIG_REJECT`, `CATALOG_TAMPER_REJECT` |
| 6 | Price matches catalog | `INTEGRITY_REJECT` |
| 7 | Within mandate budget | `AP2_BUDGET_REJECT` |
| 8 | Not a duplicate | `IDEMPOTENCY_REJECT` |
| 9 | Within your spending limit | `SESSION_CAP_REJECT` |

Checks 8 and 9 and the reservation run in one atomic database transaction; a note under the list says so. A **401** (bad key) or **429** (rate limited) happens *before* the gate, so it gets its own banner, and the checks show as "not reached".

## 5. Scenarios

Each preset fills the prompt and options and shows a **"What to watch"** hint. Two-step attacks start from a normal draft and then point at the right action button.

| Group | Scenario | How it runs | Expected outcome |
|---|---|---|---|
| Happy path | Normal purchase | Draft → Execute | Real Razorpay **sandbox** order (test mode, no money) |
| Happy path | Needs my approval | "Require approval" on | *Awaiting approval* → Confirm (real order) or Cancel (budget released) |
| Attack | Prompt injection | Draft | Blocked at ①; the planner never runs |
| Attack | Unseen attack | Draft (+ Execute if it passes) | **Depends on the live models**, and the hint says so. Either screening blocks it, or it passes and the rules still cap the damage |
| Attack | Tamper with the price | Draft → *Attack ▾ → Change price to ₹1* | 409, check 2 fails. The UI edits unit price, line total **and** cart total consistently, as a real attacker would (see §12, finding 7) |
| Attack | Replay | Execute → *Attack ▾ → Submit again* | Check 8 fails (duplicate) |
| Attack | Impersonation | Draft as Alice → *Attack ▾ → Submit as Bob* | Check 3 fails |
| Attack | Overspend | Prompt with a large stated budget | Check 9 fails (per-user cap ₹5,000) |
| Failure | Gateway timeout | *Simulate ▾ → Timeout* | Held (budget stays reserved) → *Simulated webhook* or *Run reconciler* |
| Failure | Gateway decline | *Simulate ▾ → Decline* | Rolled back, budget and key released |
| Failure | Webhook replay | On a held reservation, send the same simulated webhook twice | Second delivery ignored as a duplicate |

## 6. Live State panel

- **Spending meter:** the acting user's spend vs the per-user cap, split into *settled* and *reserved or held*.
- **Reservations:** the acting user's latest reservations with status chips (*Awaiting approval* blue, *In flight* grey, *Held* amber, *Settled* green) and actions:
  - Awaiting approval: **Confirm** / **Cancel**.
  - Held: **Simulated webhook: captured / failed**, and **Run reconciler**. The reconciler queries Razorpay by receipt. A simulated timeout never created an order, so it will honestly release the hold, and the hint says so.
- **Audit ledger:** the newest blocks first, showing event (plain language), amount, short hash, and "← links to" the previous hash. **Verify chain** shows two separate results: *chain intact* and *signatures valid*.
- **Reset demo:** clears reservations, spend, rate limits and webhook history. It **does not** clear the audit ledger: the log is append-only by design, and the UI states that.
- Refreshed **after each action**, not polled on a timer (polling would eat into the rate limit and add noise).

## 7. Visual system

- **Colour semantics** (never colour alone: always icon + word):
  - AI zone: violet. Rules zone: teal. Razorpay: indigo.
  - Pass/success: green. Blocked/declined: red. Held: amber. Awaiting approval: blue. Not reached: grey. Simulated: grey outline tag.
- **Type:** system UI font stack; monospace for IDs, hashes and reason codes; tabular numerals for money.
- **Money:** ₹ with Indian digit grouping (`en-IN`), converted from paise in one helper.
- **Spacing:** 8 px grid, 12 px card radius, one accent per zone.
- **Theme:** light by default; dark mode via `prefers-color-scheme`, all colours defined as tokens.

## 8. Interaction states and accessibility

- **Running:** action buttons disable and show an elapsed-seconds counter. Fetch timeout is 60 s, with a clear message if it's hit.
- **Errors:** distinct messages for network failure, 401, 429 (with a Retry-After countdown) and 5xx. Validation errors (422) show the field.
- **Keyboard:** Ctrl+Enter drafts. Everything is reachable by Tab with a visible focus ring. Focus moves to the outcome banner after each action.
- **Announcements:** only outcomes go to `aria-live="polite"`. The expiry countdown is *not* announced (no screen-reader spam).
- **Motion:** respect `prefers-reduced-motion`.
- **Contrast:** WCAG AA for text and status chips in both themes.

## 9. Microcopy

| Code | Headline |
|---|---|
| `SCHEMA_REJECT` | Request is malformed |
| `MANDATE_SIGNATURE_TAMPER_REJECT` | The signed request was altered: tamper detected |
| `USER_BINDING_REJECT` | This mandate belongs to someone else |
| `MANDATE_EXPIRED_REJECT` | The mandate expired before it was used |
| `CATALOG_*_REJECT` | Product data failed the merchant-signature check |
| `INTEGRITY_REJECT` | Price doesn't match the catalog |
| `AP2_BUDGET_REJECT` | Over the budget stated in the mandate |
| `IDEMPOTENCY_REJECT` | Already processed: duplicate blocked |
| `SESSION_CAP_REJECT` | Over your spending limit |
| `RESERVATION_STATE_REJECT` | That reservation can't do this any more |

Outcome headlines: "Order placed", "Waiting for your approval", "Blocked before the AI acted", "Held: outcome unknown, money stays reserved", "Declined: nothing charged, budget released".

## 10. Technical approach

- **Frontend:** plain HTML, CSS and JavaScript (`frontend/`) with no build step and no dependencies, so the repo stays clone-and-run. FastAPI serves it at `/demo/`, same origin, so no CORS is needed.
- **Real endpoints are used wherever possible:** `/api/v1/execute`, `/api/v1/simulate/execute`, `/api/v1/reservations/{key}/confirm|cancel`, `/api/v1/ledger/verify`.
- **Demo-only endpoints** (`backend/demo_routes.py`), registered **only** by the demo launcher, never by the production `create_app()`:

| Endpoint | Why it has to exist |
|---|---|
| `POST /api/v1/demo/session` | Issues API keys for the demo users (Alice, Bob) so nobody needs the CLI. Keys live in JS memory only |
| `POST /api/v1/demo/intent` | The same pipeline as `/intent/process`, plus a **trace** (guard verdicts and scores, planner output, candidates, timings). Production does not expose this: guard scores would hand attackers a tuning oracle |
| `GET /api/v1/demo/state` | Spend, cap, the user's reservations and recent ledger blocks for the right panel |
| `POST /api/v1/demo/webhook` | Browsers can't sign webhooks (that needs the secret), so the server signs a **simulated** Razorpay event and passes it through the *same* webhook handler as production |
| `POST /api/v1/demo/reconcile` | Runs the real reconciler now, with a zero grace period |
| `POST /api/v1/demo/reset` | Clears runtime state (not the ledger) |

- **Launcher:** `python demo_server.py`
  - It keeps demo state and the demo ledger in `demo_data/` (gitignored), separate from real state.
  - It sets a ₹5,000 per-user cap and enables the simulate route.
  - It disables the background reconciler (the button runs it on demand).
  - It defaults to **live AI + Razorpay sandbox**. `--offline-ai` and `--simulated-razorpay` switch either one to a labelled stand-in, so someone without keys can still run it.

## 11. Acceptance criteria

1. Every scenario in §5 runs end to end from the UI against the real backend, verified in a real browser.
2. No scenario needs a terminal once the demo is running.
3. Each outcome is understandable from its headline alone; the reason code is secondary.
4. The demo routes are absent from the production app (covered by a test).
5. Works at 1440 px and 390 px widths; keyboard-only operation works; no console errors.

## 12. Cross-check of v1: findings and resolutions

Each v1 statement was checked against the backend code (`app.py`, `backend/policy_gate.py`, `backend/two_phase_commit.py`, `backend/webhook.py`, `agents/intent_layer.py`), and two behaviours were confirmed by direct requests.

| # | v1 said | Finding | Resolution in v1.1 |
|---|---|---|---|
| 1 | "Stages animate in sequence while the request runs" | `/intent/process` is one call that returns at the end. A step-by-step animation would fake progress, breaking principle 2 | One honest running state with an elapsed timer; stages appear with **measured** durations from a trace |
| 2 | Stages ①–③ show guard scores, planner output and candidates | The production endpoint returns only the signed request; none of that data reaches the client | Demo-only `/demo/intent` returns a trace. It's kept out of production because guard scores would be an attack-tuning oracle |
| 3 | "All 9 checks with pass/fail" | The gate returns only the **first** failing reason | Derive ✓ / ✗ / *not reached* from the gate's code order, and pin that order in a test |
| 4 | Policy checks are the only rejection path | 401 and 429 reject **before** the gate | Separate banner; the checks show as *not reached* |
| 5 | "API keys for the demo users are created at launch" | The browser still has to obtain them somehow | `/demo/session` (demo-only); keys held in JS memory |
| 6 | "Simulate webhook" from the UI | Webhooks need an HMAC with the server secret, which must never reach the browser | The server signs a simulated event and routes it through the **same** handler as production, tagged *Simulated* |
| 7 | "Edit the signed cart to ₹1 → signature check fails" | **Confirmed by request:** changing only the unit price fails Pydantic validation (HTTP 422) before the signature check. Changing price, line total and cart total together returns **409 tamper** | The tamper action edits all three, like a real attacker; the hint explains why |
| 8 | Failure scenarios via the simulate route | **Confirmed by request:** the simulate route maps every failure to **400**, so a timeout and a decline look the same | Backend fix: the simulate route uses the same error→HTTP mapping as `/execute` (504 held, 402 declined, …) |
| 9 | "Reset demo clears everything" | The audit ledger is append-only by design, and wiping it mid-process isn't safe | Reset clears runtime state only; the UI says the ledger is never reset |
| 10 | Live AI scenarios have fixed outcomes | The "unseen attack" outcome depends on the live models (43% ML recall on held-out attacks) | The hint states both possible outcomes; either one teaches the point |
| 11 | Overspend preset | The mandate budget comes from the planner, and `PolicyGate`'s default cap is bound at import time | The launcher passes an explicit ₹5,000 cap; the preset states a large budget so check 7 passes and check 9 fails |
| 12 | Live panel freshness unspecified | Interval polling would spend rate-limit tokens (30/min) and add noise | Refresh after each action; the state endpoint is authenticated but not rate-limited |
| 13 | Unspecified wait times | The ML guard measured ~2.2 s per call via Groq | Elapsed counter, 60 s fetch timeout, expected 3–6 s per draft |
| 14 | Replay always rejected | After a **declined** payment the gateway deliberately frees the key, so a replay is processed again (correct behaviour) | The replay hint says to replay a *successful* or *held* request, and explains the declined case |
| 15 | Mandate expiry not considered | Mandates expire in 5 minutes; a slow presenter would hit `MANDATE_EXPIRED_REJECT` | Visible countdown on the mandate card |
| 16 | No offline story | Someone cloning the repo may lack Groq or Razorpay keys | `--offline-ai` / `--simulated-razorpay`, shown as top-bar badges |
| 17 | Demo state location unspecified | Running against the real state DB and ledger would pollute them | `demo_data/`, gitignored |

## 13. Build verification: what testing the real UI found

The built UI was driven end to end in Microsoft Edge (Playwright) against the **live** Groq models and the **real** Razorpay sandbox: every scenario in §5, the keyboard shortcut, user switching, reset, dark mode, and 1440 px and 390 px widths.

All 24 scripted steps produced the expected outcome. There were no JavaScript errors; the only console entries were the browser logging the intended 4xx/5xx responses of rejected scenarios. Testing found six problems, all fixed:

| # | Found | Fix |
|---|---|---|
| 18 | The "Working…" spinner, the hint box and an empty outcome box were **always visible**: the author `display: flex` rules beat the browser's `[hidden]` rule. The first test pass missed it because it read the `hidden` attribute, not the rendered style | Global `[hidden] { display: none !important; }`; the test now checks the computed style and asserts nothing is visible on first load |
| 19 | Real sandbox orders accumulate against the ₹5,000 cap, so after a few scenarios **unrelated ones started failing at check 9** | The cap rejection now says "press Reset demo or switch to Bob" whenever the scenario isn't Overspend; the meter already shows what's left |
| 20 | Re-rendering a stage (e.g. the mandate card after executing) **replayed its fade-in**, flashing it transparent | Only newly added stages animate (`.no-anim` on updates) |
| 21 | On a phone, the wrapped **sticky top bar covered ~45% of the screen** | The top bar stops being sticky below 760 px |
| 22 | In the 2-column phone layout, **group headings took a grid cell**, leaving holes in the scenario list | Headings span the full row |
| 23 | A scenario card and an action button share the label "Gateway decline", which is ambiguous to tests and screen readers out of context | Kept the labels (they read naturally in context), but each sits in its own landmark region (Agent console / Pipeline); the test scopes clicks by region |
