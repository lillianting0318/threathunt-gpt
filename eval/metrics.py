"""
eval/metrics.py — group resolution evaluation metrics.

Three outcomes, not two. A wrong answer and a missed answer are both
"not correct", but they differ in severity: a wrong group silently sends
an analyst down the wrong path, while a miss merely fails to help.
Collapsing them into one accuracy number hides the trade-off that the
semantic-fallback distance threshold actually controls.
"""

from collections import defaultdict


def classify(expected, actual):
    """
    expected: ground-truth group name, or None if the query is out of scope
    actual:   whatever find_group() returned
    returns:  "correct" | "wrong" | "missed"
    """
    if actual == expected:
        return "correct"
    if actual is None:
        return "missed"
    return "wrong"


def aggregate(results):
    """results: [{"kind": str, "outcome": str}, ...] -> per-kind counts."""
    stats = defaultdict(lambda: {"n": 0, "correct": 0, "wrong": 0, "missed": 0})
    for r in results:
        kind = r["kind"]
        stats[kind]["n"] += 1
        stats[kind][r["outcome"]] += 1
    return dict(stats)


def false_positive_rate(results):
    """
    Share of out-of-scope queries that returned a group instead of None.

    This is the number the distance threshold trades against: loosening it
    lowers misses on descriptive queries and raises this rate.
    """
    oos = [r for r in results if r["kind"] == "out_of_scope"]
    if not oos:
        return 0.0
    # For out-of-scope rows classify() can only return "correct" or "wrong":
    # expected is None, so the actual-is-None case is already caught by the
    # equality check and "missed" is unreachable.
    fired = [r for r in oos if r["outcome"] == "wrong"]
    return len(fired) / len(oos)


def print_table(stats):
    header = f"{'kind':<16}{'n':>4}{'correct':>9}{'wrong':>7}{'missed':>8}"
    print(header)
    print("-" * len(header))
    total = {"n": 0, "correct": 0, "wrong": 0, "missed": 0}
    for kind, s in sorted(stats.items()):
        print(f"{kind:<16}{s['n']:>4}{s['correct']:>9}{s['wrong']:>7}{s['missed']:>8}")
        for k in total:
            total[k] += s[k]
    print("-" * len(header))
    print(f"{'TOTAL':<16}{total['n']:>4}{total['correct']:>9}{total['wrong']:>7}{total['missed']:>8}")
