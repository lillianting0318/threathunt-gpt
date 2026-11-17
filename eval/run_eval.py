"""
eval/run_eval.py — run find_group() over the evaluation dataset.

Run from the repo root (RAGEngine resolves its data files relatively):
    python -m eval.run_eval
"""

import json

from rag_engine import RAGEngine
from eval.metrics import (
    classify,
    aggregate,
    print_table,
    false_positive_rate,
)


def load_dataset(path="eval/dataset.jsonl"):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run(dataset, rag):
    results = []
    for row in dataset:
        actual = rag.find_group(row["query"])
        # Keyword args on purpose: both params are str-or-None, so swapping
        # them raises nothing and silently turns every miss into a "wrong".
        outcome = classify(expected=row["expected"], actual=actual)
        results.append({
            "id":       row["id"],
            "kind":     row["kind"],
            "query":    row["query"],
            "expected": row["expected"],
            "actual":   actual,
            "outcome":  outcome,
        })
    return results


if __name__ == "__main__":
    # Built once, outside the loop: __init__ loads the embedding model, the
    # FAISS index, and re-runs enrich_index_with_mitre() every time.
    rag = RAGEngine()

    dataset = load_dataset()
    results = run(dataset, rag)

    print_table(aggregate(results))
    print(f"\nout_of_scope false positive rate: {false_positive_rate(results):.1%}")

    failures = [r for r in results if r["outcome"] != "correct"]
    if failures:
        print(f"\n{len(failures)} failures:")
        for r in failures:
            print(f"  [{r['outcome']:6}] {r['id']:6} {r['query'][:45]!r} -> {r['actual']}")
