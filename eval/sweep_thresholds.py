"""
eval/sweep_thresholds.py — choose the Pass 4 thresholds on the DEV set only.

Pass 4 runs only for queries of at least SEMANTIC_MIN_WORDS words, and
accepts a semantic match only if
    best distance   <= GROUP_MATCH_MAX_L2          (close enough at all)
    runner-up - best >= GROUP_MATCH_MIN_MARGIN_L2   (clearly better than #2)

Loosening either one turns misses into answers, and some of those answers
are wrong groups. This sweep shows that trade-off on eval/dataset.jsonl.

The held-out test sets (eval/group_test*.jsonl) are deliberately NOT used here:
a threshold picked by looking at the test set would make the test score
optimistic, the same way the dev score already is.

Each query's semantic_search() is computed once and cached, so the grid
costs one embedding pass, not one per grid point.

Run from the repo root:
    python -m eval.sweep_thresholds
"""

import itertools

from rag_engine import RAGEngine
from eval.run_eval import load_dataset, run, summarize, DEV_SET

MAX_L2_GRID = [1.20, 1.30, 1.40, 1.45, 1.50, 1.60, 1.80]
MIN_MARGIN_GRID = [0.00, 0.05, 0.10, 0.15, 0.20, 0.30]
MIN_WORDS_GRID = [1, 2, 3, 4, 5, 6]


def memoize_search(rag):
    original = rag.semantic_search
    cache = {}

    def cached(query, top_k=5):
        if (query, top_k) not in cache:
            cache[(query, top_k)] = original(query, top_k=top_k)
        return cache[(query, top_k)]

    rag.semantic_search = cached


def main():
    rag = RAGEngine()
    if rag._is_inner_product():
        raise SystemExit("index uses inner product; this sweep covers the L2 thresholds only")
    memoize_search(rag)
    dataset = load_dataset(DEV_SET)
    current = (rag.GROUP_MATCH_MAX_L2, rag.GROUP_MATCH_MIN_MARGIN_L2)

    rows = []
    for max_l2, margin in itertools.product(MAX_L2_GRID, MIN_MARGIN_GRID):
        rag.GROUP_MATCH_MAX_L2 = max_l2          # instance attrs shadow the class defaults
        rag.GROUP_MATCH_MIN_MARGIN_L2 = margin
        results = run(dataset, rag)
        s = summarize(results)
        wrong = sum(1 for r in results if r["outcome"] == "wrong")
        rows.append((max_l2, margin, s["accuracy"], s["false_match_rate_out_of_scope"], wrong))

    print(f"DEV set: {DEV_SET}  (current: max_l2={current[0]}, min_margin={current[1]})\n")
    print(f"{'max_l2':>7}{'margin':>8}{'accuracy':>10}{'OOS false-match':>17}{'wrong (all)':>13}")
    for max_l2, margin, acc, fp, wrong in rows:
        mark = "  <- current" if (max_l2, margin) == current else ""
        print(f"{max_l2:>7.2f}{margin:>8.2f}{acc:>10.1%}{fp:>17.1%}{wrong:>13}{mark}")

    plot(rows, current)
    sweep_min_words(rag, dataset, current)


def sweep_min_words(rag, dataset, current):
    """Pass 4 word gate, at the current distance/margin thresholds."""
    rag.GROUP_MATCH_MAX_L2, rag.GROUP_MATCH_MIN_MARGIN_L2 = current
    default = type(rag).SEMANTIC_MIN_WORDS
    print(f"\nPass 4 word gate (current: {default})\n")
    print(f"{'min_words':>10}{'accuracy':>10}{'OOS false-match':>17}{'wrong (all)':>13}{'semantic answers':>18}")
    for n in MIN_WORDS_GRID:
        rag.SEMANTIC_MIN_WORDS = n
        results = run(dataset, rag)
        s = summarize(results)
        wrong = sum(1 for r in results if r["outcome"] == "wrong")
        sem = s["by_method"].get("semantic", 0)
        mark = "  <- current" if n == default else ""
        print(f"{n:>10}{s['accuracy']:>10.1%}{s['false_match_rate_out_of_scope']:>17.1%}{wrong:>13}{sem:>18}{mark}")
    rag.SEMANTIC_MIN_WORDS = default


def plot(rows, current):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plot")
        return
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for margin in MIN_MARGIN_GRID:
        pts = [(r[4], r[2]) for r in rows if r[1] == margin]
        ax.plot([p[0] for p in pts], [p[1] for p in pts], "o-", alpha=0.8, label=f"margin ≥ {margin:.2f}")
    cur = next(r for r in rows if (r[0], r[1]) == current)
    ax.scatter([cur[4]], [cur[2]], s=160, facecolors="none", edgecolors="black", label="current")
    ax.set_xlabel("wrong groups returned (dev set, count)")
    ax.set_ylabel("accuracy (dev set)")
    ax.set_title("Pass 4 thresholds: accuracy vs wrong answers")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    out = "eval/results/threshold_sweep.png"
    fig.savefig(out, dpi=150)
    print(f"\nplot -> {out}")


if __name__ == "__main__":
    main()
