"""
eval/diagnose_margin.py — is the margin a better accept signal than the score?

diagnose.py showed the current threshold (L2 <= 1.0) sits below the entire
score distribution, so Pass 4 has never fired. But simply loosening it turns
misses into wrong answers, because the nearest cti_summary is often not the
right group.

Hypothesis: the gap between the best and second-best cti_summary separates
the confident cases from the coin-flips better than the absolute distance.

This prints, for every query, the top cti_summary candidates plus the margin,
across two sets that must behave in opposite ways:

  descriptive   -> a real group exists; we want to accept the top candidate
  out_of_scope  -> no group exists; we must reject whatever comes back

If the margin is a usable signal, descriptive-correct rows will show a large
gap and out_of_scope rows a small one. If out_of_scope rows also show large
gaps, the margin rule would confidently return a wrong group and is unusable.

Run from the repo root:
    python -m eval.diagnose_margin
"""

from rag_engine import RAGEngine

TOP_K = 20

DESCRIPTIVE = [
    ("the group behind the SolarWinds supply chain compromise", "APT29"),
    ("North Korean actors who stole funds from banks over SWIFT", "Lazarus Group"),
    ("Russian military intelligence unit that targeted the DNC in 2016", "APT28"),
    ("Chinese PLA Unit 61398", "APT1"),
    ("financially motivated group that targeted point-of-sale systems in US restaurants", "FIN7"),
    ("Iranian group that used the Shamoon wiper against Saudi energy firms", "APT33"),
]

OUT_OF_SCOPE = [
    "Sandworm Team",
    "Volt Typhoon",
    "Wizard Spider",
    "Kimsuky",
    "Charming Kitten",
    "Equation Group",
    "Turla",
    "qwertyuiop",
    "what is the weather in Vancouver today",
    "how do I reset my password",
]


def group_candidates(rag, query):
    """Top cti_summary hits only, in rank order, as (title, score)."""
    hits = rag.semantic_search(query, top_k=TOP_K)
    return [
        (h.get("title", ""), h["score"])
        for h in hits
        if h.get("source_type") == "cti_summary"
    ]


def report(rag, query, want):
    cands = group_candidates(rag, query)
    best = cands[0] if cands else None
    second = cands[1] if len(cands) > 1 else None

    if best is None:
        margin = None
    elif second is None:
        margin = float("inf")   # no competitor inside top_k
    else:
        margin = second[1] - best[1]

    hit = (best is not None and want is not None and best[0] == want)

    print(f"\n{query[:68]}")
    print(f"  want: {want}")
    for i, (title, score) in enumerate(cands[:4], 1):
        mark = " <- top" if i == 1 else ""
        mark += " <- WANTED" if title == want else ""
        print(f"    {i}. {score:7.3f}  {title[:34]}{mark}")
    if not cands:
        print("    (no cti_summary in top_k)")

    m = "n/a" if margin is None else ("inf" if margin == float("inf") else f"{margin:.3f}")
    print(f"  best={best[1]:.3f} " if best else "  best=n/a ", end="")
    print(f"margin={m}  top-is-correct={hit}")

    return {"query": query, "want": want, "best": best, "margin": margin, "hit": hit}


def simulate(rows, max_dist, min_margin):
    """Apply (score <= max_dist AND margin >= min_margin) and score the outcome."""
    correct = wrong = missed = 0
    for r in rows:
        best, margin = r["best"], r["margin"]
        accept = (
            best is not None
            and best[1] <= max_dist
            and margin is not None
            and margin >= min_margin
        )
        if not accept:
            # returning None is correct for out_of_scope, a miss otherwise
            if r["want"] is None:
                correct += 1
            else:
                missed += 1
        elif best[0] == r["want"]:
            correct += 1
        else:
            wrong += 1
    return correct, wrong, missed


def main():
    rag = RAGEngine()
    print(f"current threshold: L2 <= {rag.GROUP_MATCH_MAX_L2}")

    print("\n" + "=" * 78)
    print("DESCRIPTIVE — a real group exists, we want to accept")
    print("=" * 78)
    desc = [report(rag, q, w) for q, w in DESCRIPTIVE]

    print("\n" + "=" * 78)
    print("OUT OF SCOPE — no group exists, we must reject")
    print("=" * 78)
    oos = [report(rag, q, None) for q in OUT_OF_SCOPE]

    rows = desc + oos

    print("\n" + "=" * 78)
    print("SWEEP — outcome over these 16 rows")
    print("=" * 78)
    print(f"{'max_dist':>9}{'min_margin':>12}{'correct':>9}{'wrong':>7}{'missed':>8}")
    for max_dist in (1.0, 1.10, 1.35, 1.45, 1.60):
        for min_margin in (0.0, 0.05, 0.10, 0.20):
            c, w, m = simulate(rows, max_dist, min_margin)
            print(f"{max_dist:>9.2f}{min_margin:>12.2f}{c:>9}{w:>7}{m:>8}")


if __name__ == "__main__":
    main()
