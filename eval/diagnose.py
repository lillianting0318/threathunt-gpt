"""
eval/diagnose.py — why does the semantic fallback never fire?

run_eval showed 0/6 on descriptive queries, all of them misses. Two causes
are possible and they need opposite fixes:

  A. The threshold is too tight — the right group IS retrieved but
     _close_enough() rejects its score.
  B. The right group is never retrieved at all — Pass 4 only accepts
     entries whose source_type is "cti_summary", and the index also holds
     ~900 MITRE technique entries that may crowd the top_k.

This prints the raw neighbours so you can tell which one it is.

Run from the repo root:
    python -m eval.diagnose
"""

from rag_engine import RAGEngine

QUERIES = [
    ("the group behind the SolarWinds supply chain compromise", "APT29"),
    ("North Korean actors who stole funds from banks over SWIFT", "Lazarus Group"),
    ("Russian military intelligence unit that targeted the DNC in 2016", "APT28"),
    ("Chinese PLA Unit 61398", "APT1"),
    ("financially motivated group that targeted point-of-sale systems in US restaurants", "FIN7"),
    ("Iranian group that used the Shamoon wiper against Saudi energy firms", "APT33"),
]

TOP_K = 10


def main():
    rag = RAGEngine()

    print(f"\nthreshold: L2 <= {rag.GROUP_MATCH_MAX_L2} | IP >= {rag.GROUP_MATCH_MIN_IP}")
    print(f"index entries: {rag.index.ntotal} | metadata rows: {len(rag.metadata)}\n")

    for query, want in QUERIES:
        print("=" * 78)
        print(f"{query}")
        print(f"want: {want}")
        hits = rag.semantic_search(query, top_k=TOP_K)

        summary_rank = None
        want_rank = None
        for i, h in enumerate(hits, 1):
            stype = h.get("source_type", "?")
            title = h.get("title", "")
            mark = ""
            if stype == "cti_summary":
                if summary_rank is None:
                    summary_rank = i
                mark += " <- cti_summary"
            if title == want and want_rank is None:
                want_rank = i
                mark += " <- WANTED"
            print(f"  {i:2}. {h['score']:8.3f}  {stype:15} {title[:38]}{mark}")

        print(f"  first cti_summary at rank: {summary_rank}")
        print(f"  wanted group at rank:      {want_rank}")
        if want_rank:
            score = hits[want_rank - 1]["score"]
            passes = rag._close_enough(score)
            print(f"  wanted score {score:.3f} -> _close_enough: {passes}")
        print()


if __name__ == "__main__":
    main()
