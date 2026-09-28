"""Red-team + benign evaluation of the gateway's defenses (eval v2).

    python -m evals.run_evals                    # regex + ML guard (Groq), forgery, retrieval
    python -m evals.run_evals --offline          # no Groq calls: regex layer, forgery, retrieval
    python -m evals.run_evals --skip-retrieval   # skip the embedding model

What v1 got wrong, and v2 fixes:
  - Attacks only. With no benign traffic there was no false-positive
    rate — a guard that blocked everything scored 100% containment.
    v2 adds evals/benign_corpus.json (incl. hard negatives).
  - API errors counted as "caught". PromptGuard fails closed, so a 401
    from Groq looked like a successful block. v2 records those as
    INVALID runs and excludes them from every metric, loudly.
  - Tested on the prompts the regexes were tuned against. v2 adds
    evals/heldout_attacks.json, which nothing was tuned on.
  - One blended number. v2 attributes each verdict to the regex layer,
    the ML layer, and the combination (OR, same as CombinedGuard), and
    reports recall, false-positive rate, precision and F1 per layer and
    per category, with 95% Wilson intervals, plus an ML threshold sweep.
"""
import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from pydantic import ValidationError

from agents.pattern_guard import PatternGuard
from backend.schemas import CartItem, IntentMandate

EVAL_DIR = Path(__file__).parent
MODEL_REGISTRY = {"CartItem": CartItem, "IntentMandate": IntentMandate}
_ML_ERROR_PREFIXES = ("guardrail_call_failed", "unrecognized_guardrail_response")


# --- Corpora ------------------------------------------------------------------

def _categories(path: Path, key: str) -> Dict[str, List[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))[key]
    return {name: prompts for name, prompts in data.items() if not name.startswith("_")}


def load_guard_cases() -> List[Dict[str, Any]]:
    """Every prompt with its label (attack/benign), split and category."""
    cases = []
    sources = [
        ("redteam_corpus.json", "guardrail_targets", "attack", "tuned"),
        ("heldout_attacks.json", "categories", "attack", "heldout"),
        ("benign_corpus.json", "categories", "benign", "benign"),
    ]
    for filename, key, label, split in sources:
        for category, prompts in _categories(EVAL_DIR / filename, key).items():
            cases.extend({"prompt": p, "label": label, "split": split, "category": category} for p in prompts)
    return cases


# --- Statistics ------------------------------------------------------------------

def wilson_interval(successes: int, n: int, z: float = 1.96):
    """95% Wilson score interval — unlike the naive p ± z·SE it stays
    inside [0, 1] and is sensible at 0/n and n/n, which is exactly where
    small security evals live (45/45 does not mean 100%)."""
    if n == 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def _rate(k: int, n: int) -> Dict[str, Any]:
    ci = wilson_interval(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "ci95": ci}


# --- Guard evaluation ------------------------------------------------------------

def screen_case(prompt: str, pattern_guard: PatternGuard, ml_guard=None) -> Dict[str, Any]:
    """Runs BOTH layers independently (not short-circuited like
    CombinedGuard), so each layer's recall can be measured on its own."""
    start = time.perf_counter()
    regex_safe, regex_detail = pattern_guard.screen(prompt)
    out = {
        "regex": "allowed" if regex_safe else "blocked",
        "regex_detail": regex_detail,
        "regex_ms": (time.perf_counter() - start) * 1000,
        "ml": "not_run",
        "ml_score": None,
        "ml_detail": None,
        "ml_ms": None,
    }
    if ml_guard is not None:
        start = time.perf_counter()
        ml_safe, ml_detail = ml_guard.screen(prompt)
        out["ml_ms"] = (time.perf_counter() - start) * 1000
        out["ml_detail"] = ml_detail
        if ml_detail.startswith(_ML_ERROR_PREFIXES):
            # The production guard blocks here (fail closed) — correct for
            # safety, wrong for measurement. An outage is not a detection.
            out["ml"] = "error"
        else:
            out["ml"] = "allowed" if ml_safe else "blocked"
            if ml_detail.startswith("malicious_score="):
                out["ml_score"] = float(ml_detail.split("=", 1)[1])

    # Combined = CombinedGuard's OR — measured only where the ML layer
    # produced a verdict. Counting a regex block as a valid combined
    # verdict while dropping the regex-allowed rows whose ML call failed
    # would keep exactly the rows that were blocked and discard the ones
    # in doubt: a selection bias that inflates recall (the first version
    # of this evaluator reported "100%" that way, offline).
    if out["ml"] in ("not_run", "error"):
        out["combined"] = out["ml"]
    else:
        out["combined"] = "blocked" if "blocked" in (out["regex"], out["ml"]) else "allowed"
    return out


def _layer_metrics(results: List[Dict[str, Any]], layer: str) -> Optional[Dict[str, Any]]:
    valid = [r for r in results if r[layer] in ("blocked", "allowed")]
    if not valid:
        return None
    blocked = lambda rs: sum(1 for r in rs if r[layer] == "blocked")  # noqa: E731
    by = lambda **kw: [r for r in valid if all(r[k] == v for k, v in kw.items())]  # noqa: E731

    attacks, benign = by(label="attack"), by(label="benign")
    tp, fp = blocked(attacks), blocked(benign)
    fn, tn = len(attacks) - tp, len(benign) - fp
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / len(attacks) if attacks else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None

    categories = {}
    for r in valid:
        categories.setdefault((r["split"], r["category"]), []).append(r)
    return {
        "valid": len(valid),
        "invalid": len(results) - len(valid),
        "recall_tuned": _rate(blocked(by(split="tuned")), len(by(split="tuned"))),
        "recall_heldout": _rate(blocked(by(split="heldout")), len(by(split="heldout"))),
        "recall_all_attacks": _rate(tp, len(attacks)),
        "false_positive_rate": _rate(fp, len(benign)),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "f1": f1,
        "per_category": {
            f"{split}/{cat}": _rate(blocked(rs), len(rs)) for (split, cat), rs in sorted(categories.items())
        },
    }


def threshold_sweep(results: List[Dict[str, Any]], thresholds=(0.01, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9)):
    """How the ML layer alone trades recall for false positives as its
    threshold moves — the data the 0.5 default should have been chosen
    from. Only valid (scored) runs count."""
    scored = [r for r in results if r["ml_score"] is not None]
    attacks = [r["ml_score"] for r in scored if r["label"] == "attack"]
    benign = [r["ml_score"] for r in scored if r["label"] == "benign"]
    if not attacks or not benign:
        return []
    return [{
        "threshold": t,
        "recall": sum(s >= t for s in attacks) / len(attacks),
        "false_positive_rate": sum(s >= t for s in benign) / len(benign),
    } for t in thresholds]


def evaluate_guard(cases: List[Dict[str, Any]], pattern_guard: Optional[PatternGuard] = None, ml_guard=None) -> Dict[str, Any]:
    pattern_guard = pattern_guard or PatternGuard()
    results = [{**case, **screen_case(case["prompt"], pattern_guard, ml_guard)} for case in cases]

    def pctl(values, q):
        return float(np.percentile(values, q)) if values else None

    regex_ms = [r["regex_ms"] for r in results]
    ml_ms = [r["ml_ms"] for r in results if r["ml"] in ("blocked", "allowed")]
    errors = [r["ml_detail"] for r in results if r["ml"] == "error"]
    return {
        "results": results,
        "layers": {layer: _layer_metrics(results, layer) for layer in ("regex", "ml", "combined")},
        "ml_errors": {"count": len(errors), "first": errors[0] if errors else None},
        "threshold_sweep": threshold_sweep(results),
        "latency_ms": {
            "regex": {"p50": pctl(regex_ms, 50), "p95": pctl(regex_ms, 95)},
            "ml_valid_calls": {"p50": pctl(ml_ms, 50), "p95": pctl(ml_ms, 95)},
        },
    }


# --- Downstream forgery -----------------------------------------------------------

def evaluate_forgery() -> Dict[str, Any]:
    suite = json.loads((EVAL_DIR / "redteam_corpus.json").read_text(encoding="utf-8"))
    results = []
    for case in suite.get("downstream_validation_targets", {}).get("numeric_and_structural_forgery", []):
        model_cls = MODEL_REGISTRY[case["target_model"]]
        try:
            model_cls(**case["payload"])
            rejected, reason = False, None
        except ValidationError as e:
            rejected, reason = True, str(e.errors()[0]["msg"])
        except Exception as e:
            # Not the same outcome as rejected=True — an unexpected
            # exception means a corpus/script bug or a genuine validator
            # crash, neither of which is evidence the defense worked.
            rejected, reason = False, f"UNEXPECTED {type(e).__name__}: {e}"
        results.append({"prompt": case["prompt"], "rejected": rejected, "reason": reason})
    return {"results": results, "rejected": _rate(sum(r["rejected"] for r in results), len(results))}


# --- Retrieval --------------------------------------------------------------------

def evaluate_retrieval() -> Optional[Dict[str, Any]]:
    from backend.policy_gate import load_catalog
    from retrieval.catalog_retriever import CatalogRetriever

    suite = json.loads((EVAL_DIR / "redteam_corpus.json").read_text(encoding="utf-8"))
    # retrieval_benchmarks is {"_notes": ..., "queries": [...]} — iterating
    # the dict itself would yield its keys, not the query records.
    cases = suite.get("retrieval_benchmarks", {}).get("queries", [])
    if not cases:
        return None

    # An expected_sku that isn't in the catalog makes every result
    # meaningless; this once caught 3 of 5 corpus SKUs that didn't exist.
    catalog = load_catalog()
    for case in cases:
        if case["expected_sku"] not in catalog:
            raise ValueError(f"Corpus error: expected_sku '{case['expected_sku']}' is not in the catalog. "
                             "Fix the corpus, not the retriever.")

    retriever = CatalogRetriever()
    results, latencies = [], []
    for case in cases:
        start = time.perf_counter()
        matches = retriever.search(case["query"], top_k=3)
        latencies.append((time.perf_counter() - start) * 1000)
        ranked = [item["sku"] for item, _ in matches]
        rank = ranked.index(case["expected_sku"]) + 1 if case["expected_sku"] in ranked else None
        results.append({"query": case["query"], "expected": case["expected_sku"], "retrieved": ranked, "rank": rank})

    n = len(results)
    return {
        "results": results,
        "hit_at_1": _rate(sum(r["rank"] == 1 for r in results), n),
        "hit_at_3": _rate(sum(r["rank"] is not None for r in results), n),
        "mrr": sum(1 / r["rank"] for r in results if r["rank"]) / n,
        "latency_ms": {"p50": float(np.percentile(latencies, 50)), "p95": float(np.percentile(latencies, 95))},
    }


# --- Reporting ---------------------------------------------------------------------

def _fmt(r: Optional[Dict[str, Any]]) -> str:
    if not r or r["n"] == 0:
        return "n/a"
    lo, hi = r["ci95"]
    return f"{r['k']:>3}/{r['n']:<3} {r['rate'] * 100:5.1f}%  [95% CI {lo * 100:4.1f}–{hi * 100:5.1f}%]"


def print_report(guard: Dict[str, Any], forgery: Dict[str, Any], retrieval: Optional[Dict[str, Any]]) -> None:
    line = "=" * 78
    print(f"\n{line}\nGUARDRAIL (recall = attacks blocked; FPR = benign prompts blocked)\n{line}")
    if guard["ml_errors"]["count"]:
        print(f"WARNING: {guard['ml_errors']['count']} ML-guard calls failed and are EXCLUDED as invalid runs, not "
              f"counted as blocks.\n  First error: {guard['ml_errors']['first'][:150]}")
    for layer, name in (("regex", "Regex (PatternGuard)"), ("ml", "ML (Prompt Guard 2)"), ("combined", "Combined (OR)")):
        m = guard["layers"][layer]
        print(f"\n{name}")
        if m is None:
            print("  not measured (layer not run, or every call failed)")
            continue
        print(f"  recall, tuned attacks    : {_fmt(m['recall_tuned'])}")
        print(f"  recall, HELD-OUT attacks : {_fmt(m['recall_heldout'])}")
        print(f"  false-positive rate      : {_fmt(m['false_positive_rate'])}")
        precision = f"{m['precision']:.3f}" if m["precision"] is not None else "n/a"
        f1 = f"{m['f1']:.3f}" if m["f1"] is not None else "n/a"
        print(f"  precision {precision}   F1 {f1}   confusion {m['confusion']}   invalid runs {m['invalid']}")

    regex = guard["layers"]["regex"]
    if regex:
        print("\nRegex layer by category (blocked/total):")
        for cat, r in regex["per_category"].items():
            print(f"  {cat:<42} {_fmt(r)}")
        misses = [r for r in guard["results"] if r["label"] == "attack" and r["regex"] == "allowed"]
        false_pos = [r for r in guard["results"] if r["label"] == "benign" and r["regex"] == "blocked"]
        print(f"\nRegex false positives ({len(false_pos)}):")
        for r in false_pos:
            print(f"  [{r['category']}] {r['prompt'][:70]!r}  <- {r['regex_detail'][:45]}")
        print(f"\nRegex misses on held-out attacks "
              f"({sum(1 for r in misses if r['split'] == 'heldout')}; tuned-set misses are left to the ML layer):")
        for r in misses:
            if r["split"] == "heldout":
                print(f"  [{r['category']}] {r['prompt'][:80]!r}")

    if guard["threshold_sweep"]:
        print("\nML threshold sweep (valid runs only):")
        for row in guard["threshold_sweep"]:
            print(f"  t={row['threshold']:<5} recall {row['recall'] * 100:5.1f}%   FPR {row['false_positive_rate'] * 100:5.1f}%")

    lat = guard["latency_ms"]
    print(f"\nLatency: regex p95 {lat['regex']['p95']:.3f} ms"
          + (f" · ML p95 {lat['ml_valid_calls']['p95']:.0f} ms (valid calls)" if lat["ml_valid_calls"]["p95"] else ""))

    print(f"\n{line}\nDOWNSTREAM FORGERY (schema validators)\n{line}")
    print(f"  rejected: {_fmt(forgery['rejected'])}")

    if retrieval:
        print(f"\n{line}\nRETRIEVAL\n{line}")
        print(f"  Hit@1 {_fmt(retrieval['hit_at_1'])}")
        print(f"  Hit@3 {_fmt(retrieval['hit_at_3'])}")
        print(f"  MRR   {retrieval['mrr']:.3f}      p95 {retrieval['latency_ms']['p95']:.0f} ms")
        for r in retrieval["results"]:
            if r["rank"] != 1:
                print(f"  rank {r['rank']}: {r['query'][:55]!r} expected {r['expected']}, got {r['retrieved']}")


def main(argv=None) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="skip the Groq ML guard (no network calls)")
    parser.add_argument("--skip-retrieval", action="store_true", help="skip the embedding-model retrieval benchmark")
    parser.add_argument("--json", type=Path, default=EVAL_DIR / "results" / "eval_report.json")
    args = parser.parse_args(argv)
    # The corpora include Hindi and accented text; a Windows cp1252
    # console would otherwise crash the report halfway through.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ml_guard = None
    if not args.offline:
        from agents.guardrail import PromptGuard
        ml_guard = PromptGuard()

    guard = evaluate_guard(load_guard_cases(), ml_guard=ml_guard)
    forgery = evaluate_forgery()
    retrieval = None if args.skip_retrieval else evaluate_retrieval()
    print_report(guard, forgery, retrieval)

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "mode": "offline" if args.offline else "online",
        "guard": {k: v for k, v in guard.items() if k != "results"},
        "guard_results": guard["results"],
        "forgery": forgery,
        "retrieval": retrieval,
    }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\nFull report: {args.json}")
    return report


if __name__ == "__main__":
    main()
