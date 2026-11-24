"""
eval/run_eval.py — run group resolution over an evaluation dataset.

Two datasets, two jobs:
  eval/dataset.jsonl     DEV set (57 queries). The Pass 4 thresholds were
                         tuned on it, so its scores are optimistic.
  eval/group_test.jsonl  TEST set (150 queries), held out. Report this one,
                         and do not tune thresholds against it.

Run from the repo root:
    python -m eval.run_eval                              # dev set
    python -m eval.run_eval --dataset eval/group_test.jsonl --save
"""

import argparse
import json
from collections import Counter, defaultdict

from rag_engine import RAGEngine
from eval.metrics import (
    classify,
    aggregate,
    print_table,
    false_positive_rate,
)

DEV_SET = "eval/dataset.jsonl"


def load_dataset(path=DEV_SET):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run(dataset, rag):
    results = []
    for row in dataset:
        actual, method = rag.resolve_group(row["query"])
        # Keyword args on purpose: both params are str-or-None, so swapping
        # them raises nothing and silently turns every miss into a "wrong".
        outcome = classify(expected=row["expected"], actual=actual)
        results.append({
            "id":       row["id"],
            "kind":     row["kind"],
            "query":    row["query"],
            "expected": row["expected"],
            "actual":   actual,
            "method":   method,
            "outcome":  outcome,
        })
    return results


def summarize(results):
    n = len(results)
    correct = sum(r["outcome"] == "correct" for r in results)
    in_scope = [r for r in results if r["expected"] is not None]
    wrong_in_scope = sum(r["outcome"] == "wrong" for r in in_scope)
    return {
        "n": n,
        "accuracy": correct / n if n else 0.0,
        "false_match_rate_out_of_scope": false_positive_rate(results),
        "wrong_group_rate_in_scope": wrong_in_scope / len(in_scope) if in_scope else 0.0,
        "by_method": dict(Counter(r["method"] or "none" for r in results)),
    }


def print_method_table(results):
    """Which pass answered, and how often it was right."""
    by = defaultdict(Counter)
    for r in results:
        by[r["method"] or "none"][r["outcome"]] += 1
    print(f"\n{'matched by':<16}{'n':>4}{'correct':>9}{'wrong':>7}{'missed':>8}")
    for method in ("exact", "alias", "word_boundary", "substring", "semantic", "none"):
        c = by.get(method)
        if c:
            print(f"{method:<16}{sum(c.values()):>4}{c['correct']:>9}{c['wrong']:>7}{c['missed']:>8}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=DEV_SET)
    ap.add_argument("--save", action="store_true",
                    help="write eval/results/group_<name>.json with per-query results")
    args = ap.parse_args()

    # Built once, outside the loop: __init__ loads the embedding model and
    # the (cached) enriched FAISS index.
    rag = RAGEngine()

    dataset = load_dataset(args.dataset)
    results = run(dataset, rag)
    summary = summarize(results)

    print(f"dataset: {args.dataset}\n")
    print_table(aggregate(results))
    print_method_table(results)
    print(f"\naccuracy:                          {summary['accuracy']:.1%}")
    print(f"out-of-scope false-match rate:     {summary['false_match_rate_out_of_scope']:.1%}")
    print(f"in-scope wrong-group rate:         {summary['wrong_group_rate_in_scope']:.1%}")

    failures = [r for r in results if r["outcome"] != "correct"]
    if failures:
        print(f"\n{len(failures)} failures:")
        for r in failures:
            print(f"  [{r['outcome']:6}] {r['id']:6} {r['query'].strip()[:45]!r} "
                  f"-> {r['actual']} ({r['method'] or 'none'})")

    if args.save:
        name = args.dataset.rsplit("/", 1)[-1].replace(".jsonl", "")
        out = f"eval/results/group_{name}.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "results": results}, f, indent=2, ensure_ascii=False)
        print(f"\nsaved -> {out}")


if __name__ == "__main__":
    main()
