import json
import time
from pathlib import Path

import numpy as np
from pydantic import ValidationError

from agents.guardrail import PromptGuard
from agents.pattern_guard import CombinedGuard
from backend.policy_gate import load_catalog
from backend.schemas import CartItem, IntentMandate
from retrieval.catalog_retriever import CatalogRetriever

MODEL_REGISTRY = {"CartItem": CartItem, "IntentMandate": IntentMandate}


def run_evals():
    corpus_path = Path(__file__).parent / "redteam_corpus.json"
    with open(corpus_path, "r", encoding="utf-8") as f:
        suite = json.load(f)

    # CombinedGuard, not bare PromptGuard — matches what IntentLayer
    # actually uses by default. Confirmed concretely: a real measured
    # attack score (0.0021, genuine malicious prompt) passes as "safe"
    # under bare PromptGuard and is correctly blocked once the pattern
    # layer runs alongside it. Measuring the ML layer alone here would
    # silently understate real containment.
    guard = CombinedGuard(PromptGuard())

    guardrail_results = []
    guardrail_latencies_ms = []
    downstream_results = []
    downstream_latencies_ms = []

    # --- 1. Guardrail targets (NLP injection) ---------------------------
    for category, attacks in suite.get("guardrail_targets", {}).items():
        if category.startswith("_"):
            continue
        for prompt in attacks:
            start = time.perf_counter()
            is_safe, detail = guard.screen(prompt)
            guardrail_latencies_ms.append((time.perf_counter() - start) * 1000)
            guardrail_results.append({
                "category": category,
                "prompt": prompt,
                "blocked": not is_safe,
                "detail": detail,
            })

    # --- 2. Downstream validation targets (schema/policy layer) ---------
    downstream_cases = suite.get("downstream_validation_targets", {}).get(
        "numeric_and_structural_forgery", []
    )
    for case in downstream_cases:
        model_cls = MODEL_REGISTRY[case["target_model"]]
        start = time.perf_counter()
        try:
            model_cls(**case["payload"])
            rejected = False
            rejection_reason = None
        except ValidationError as e:
            rejected = True
            rejection_reason = str(e.errors()[0]["msg"])
        except Exception as e:
            # Not the same outcome as rejected=True — an unexpected
            # exception means a corpus/script bug or a genuine
            # validator crash, neither of which is evidence the
            # intended defense worked.
            rejected = False
            rejection_reason = f"UNEXPECTED {type(e).__name__} (not a validator rejection — investigate): {e}"

        downstream_latencies_ms.append((time.perf_counter() - start) * 1000)
        downstream_results.append({
            "target_model": case["target_model"],
            "prompt": case["prompt"],
            "rejected": rejected,
            "reason": rejection_reason,
        })

    # --- 3. Retrieval precision (Hit@3 via FAISS) ------------------------
    # retrieval_benchmarks is {"_notes": ..., "queries": [...]} — not a
    # bare list. suite.get("retrieval_benchmarks", []) would return the
    # dict itself, and iterating a dict yields its keys ("_notes",
    # "queries") as strings, not the query records — confirmed this
    # crashes with "string indices must be integers" if accessed that
    # way. Reaching into ["queries"] explicitly avoids it.
    retrieval_cases = suite.get("retrieval_benchmarks", {}).get("queries", [])
    retrieval_results = []
    retrieval_latencies_ms = []

    if retrieval_cases:
        # Sanity check first: an expected_sku that doesn't exist in the
        # real catalog makes every subsequent result meaningless. This
        # caught a real corpus error earlier in this project (3 of 5
        # expected SKUs referenced products never in the catalog at
        # all) — it must fail loudly here, not silently report
        # retrieval as "wrong" when the corpus itself was wrong.
        catalog = load_catalog()
        for case in retrieval_cases:
            if case["expected_sku"] not in catalog:
                raise ValueError(
                    f"Corpus error: expected_sku '{case['expected_sku']}' for query "
                    f"'{case['query']}' does not exist in the catalog. Fix the corpus, "
                    f"not the retriever — this is not a retrieval failure."
                )

        retriever = CatalogRetriever()
        for case in retrieval_cases:
            query = case["query"]
            expected_sku = case["expected_sku"]

            start = time.perf_counter()
            matches = retriever.search(query, top_k=3)
            retrieval_latencies_ms.append((time.perf_counter() - start) * 1000)

            retrieved_skus = [
                item[0]["sku"] if isinstance(item, tuple) else item["sku"]
                for item in matches
            ]
            hit = expected_sku in retrieved_skus

            retrieval_results.append({
                "query": query,
                "expected_sku": expected_sku,
                "retrieved_skus": retrieved_skus,
                "hit": hit,
            })

    # --- Reporting ------------------------------------------------------
    def summarize(name, results, key, latencies, label_success="CAUGHT", label_fail="MISSED"):
        total = len(results)
        success_count = sum(1 for r in results if r[key])
        rate = (success_count / total * 100) if total else 0.0
        print(f"\n{name}: {success_count}/{total} successful ({rate:.1f}%)")
        for r in results:
            marker = label_success if r[key] else label_fail
            query_str = r.get("prompt") or r.get("query") or ""
            detail = r.get("detail") or r.get("reason") or (f"Top-3: {r.get('retrieved_skus')}" if not r[key] else f"Target: {r.get('expected_sku')}")
            print(f"  {marker} [{detail}]: {query_str[:65]}")
        if latencies:
            print(f"  p95 latency: {np.percentile(latencies, 95):.2f} ms")
        return rate

    guardrail_rate = summarize("Guardrail (NLP injection)", guardrail_results, "blocked", guardrail_latencies_ms)
    downstream_rate = summarize("Downstream validation (schema/policy)", downstream_results, "rejected", downstream_latencies_ms)

    retrieval_rate = None
    if retrieval_cases:
        retrieval_rate = summarize(
            "Catalog Retrieval (Hit@3)",
            retrieval_results,
            "hit",
            retrieval_latencies_ms,
            label_success="HIT  ",
            label_fail="MISS ",
        )

    print("\n" + "=" * 58)
    print("GATEWAY PRODUCTION BENCHMARK SUMMARY")
    print("=" * 58)
    print(f"Perimeter Guardrail Containment : {guardrail_rate:.1f}%")
    print(f"Downstream Schema Containment  : {downstream_rate:.1f}%")
    if retrieval_rate is not None:
        print(f"Catalog Retrieval (Hit@3)       : {retrieval_rate:.1f}%")
    print("=" * 58)

    return {
        "guardrail_containment_pct": guardrail_rate,
        "downstream_containment_pct": downstream_rate,
        "retrieval_hit_at_3_pct": retrieval_rate,
    }


if __name__ == "__main__":
    run_evals()