"""
TTP-mapping evaluation for ThreatHunt-GPT.

Task: given one CTI sentence, predict its MITRE ATT&CK Enterprise technique ID.

Configs
    faiss     nearest technique from the existing FAISS index (no LLM)
    llm_20b    gpt-oss-20b, no retrieval
    llm_120b   gpt-oss-120b, no retrieval
    rag_20b    top-k FAISS technique candidates -> 20B picks one
    rag_120b   top-k FAISS technique candidates -> 120B picks one
    cascade    rag_20b, escalating uncertain rows to rag_120b (computed in `report`)

Usage (from the repo root; needs GROQ_API_KEY):
    python eval/run_ttp_eval.py run --configs faiss rag_20b rag_120b llm_20b llm_120b
    python eval/run_ttp_eval.py run --configs rag_120b --limit 20     # smoke test
    python eval/run_ttp_eval.py report

Every LLM call is cached in eval/cache.jsonl, so an interrupted run (e.g. a
Groq rate limit) resumes where it stopped and `report` never re-calls the API.
"""

import argparse
import csv
import hashlib
import json
import math
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

RESULTS = HERE / "results"
CACHE_PATH = HERE / "cache.jsonl"
EVAL_SET = HERE / "eval_set.jsonl"

MODELS = {"20b": "openai/gpt-oss-20b", "120b": "openai/gpt-oss-120b"}
# USD per 1M tokens (input, output). Verify at https://groq.com/pricing before
# reporting numbers; only the small:large ratio matters for the cascade comparison.
# Reasoning tokens are billed as output tokens and are included in out_tok.
PRICES = {
    "openai/gpt-oss-20b": (0.10, 0.50),
    "openai/gpt-oss-120b": (0.15, 0.75),
}
# gpt-oss models reason before answering; "low" keeps cost/latency down.
REASONING_EFFORT = "low"
TOP_K = 10
ALL_CONFIGS = ["faiss", "llm_20b", "llm_120b", "rag_20b", "rag_120b"]
ID_RE = re.compile(r"T1\d{3}(?:\.\d{3})?")

SYSTEM = ("You are a cyber threat intelligence analyst. You map descriptions of "
          "adversary behavior to MITRE ATT&CK Enterprise techniques.")

LLM_ONLY_PROMPT = """Map this CTI sentence to the single most specific MITRE ATT&CK Enterprise technique ID. Use a sub-technique (e.g. T1059.001) when one fits.

Sentence: {text}

Respond with JSON only: {{"technique_id": "T....", "confidence": <number from 0 to 1>}}"""

RAG_PROMPT = """Candidate techniques:
{candidates}

Pick the candidate that best matches the CTI sentence below. Choose ONLY from the candidate IDs above.

Sentence: {text}

Respond with JSON only: {{"technique_id": "T....", "confidence": <number from 0 to 1>}}"""


# ── data ──────────────────────────────────────────────────────────────
def load_jsonl(path: Path) -> list:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path: Path, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ── retrieval ─────────────────────────────────────────────────────────
def retrieve(engine, text: str, k: int = TOP_K) -> list:
    """Top-k enterprise technique entries from the existing FAISS index.

    The index mixes CTI group summaries and technique descriptions, so we
    over-fetch and keep technique entries only (ICS T0xxx IDs are excluded
    because the test set is enterprise-only).
    """
    out = []
    for r in engine.semantic_search(text, top_k=k * 6):
        tid = r.get("title", "")
        if r.get("source_type") == "mitre_technique" and ID_RE.fullmatch(tid):
            out.append({"id": tid, "name": r.get("name", ""),
                        "text": r.get("text", ""), "score": float(r["score"])})
            if len(out) == k:
                break
    return out


# ── LLM calls with cache + retry ──────────────────────────────────────
class LLM:
    def __init__(self):
        from groq import Groq
        import groq
        self.client = Groq()
        self.retryable = (groq.RateLimitError, groq.APIConnectionError,
                          groq.InternalServerError, groq.APITimeoutError)
        self.bad_request = groq.BadRequestError
        self.cache = {}
        if CACHE_PATH.exists():
            for row in load_jsonl(CACHE_PATH):
                self.cache[row["key"]] = row["value"]

    def __call__(self, model: str, user: str) -> dict:
        key = hashlib.sha256(json.dumps([model, SYSTEM, user]).encode()).hexdigest()
        if key in self.cache:
            return self.cache[key]
        value = None
        for attempt in range(7):
            try:
                t0 = time.time()
                r = self.client.chat.completions.create(
                    model=model, temperature=0, max_tokens=2048,
                    extra_body={"reasoning_effort": REASONING_EFFORT},
                    response_format={"type": "json_object"},
                    messages=[{"role": "system", "content": SYSTEM},
                              {"role": "user", "content": user}],
                )
                value = {"text": r.choices[0].message.content or "",
                         "in_tok": r.usage.prompt_tokens,
                         "out_tok": r.usage.completion_tokens,
                         "latency": time.time() - t0}
                break
            except self.bad_request as e:      # e.g. model broke JSON mode: count as no answer
                value = {"text": "", "in_tok": 0, "out_tok": 0, "latency": 0.0,
                         "error": str(e)[:200]}
                break
            except self.retryable as e:
                wait = min(5 * 2 ** attempt, 120)
                print(f"  {type(e).__name__}; retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
        if value is None:
            raise RuntimeError("LLM call failed after retries; rerun to resume from cache")
        self.cache[key] = value
        with open(CACHE_PATH, "a") as f:
            f.write(json.dumps({"key": key, "value": value}) + "\n")
        return value


def parse(text: str):
    """Return (technique_id or None, confidence)."""
    tid, conf = None, 0.0
    try:
        d = json.loads(text)
        m = ID_RE.search(str(d.get("technique_id", "")).upper())
        tid = m.group(0) if m else None
        conf = float(d.get("confidence", 0) or 0)
    except (ValueError, TypeError, AttributeError):
        m = ID_RE.search((text or "").upper())
        tid = m.group(0) if m else None
    return tid, max(0.0, min(conf, 1.0))


def cost(model: str, in_tok: int, out_tok: int) -> float:
    p_in, p_out = PRICES[model]
    return in_tok * p_in / 1e6 + out_tok * p_out / 1e6


# ── run ───────────────────────────────────────────────────────────────
def run(configs: list, limit) -> None:
    from rag_engine import RAGEngine

    items = load_jsonl(EVAL_SET)[: limit or None]
    engine = RAGEngine()
    needs_llm = any(c != "faiss" for c in configs)
    llm = LLM() if needs_llm else None
    rows = {c: [] for c in configs}

    for i, item in enumerate(items, 1):
        cands = retrieve(engine, item["text"])
        cand_ids = [c["id"] for c in cands]
        margin = abs(cands[0]["score"] - cands[1]["score"]) if len(cands) > 1 else 0.0
        base = {"id": item["id"], "cand_ids": cand_ids,
                "faiss_top1": cand_ids[0] if cand_ids else None, "margin": margin}

        for c in configs:
            if c == "faiss":
                rows[c].append({**base, "pred": base["faiss_top1"], "conf": None,
                                "in_tok": 0, "out_tok": 0, "latency": 0.0, "cost": 0.0})
                continue
            mode, size = c.split("_")
            model = MODELS[size]
            if mode == "llm":
                prompt = LLM_ONLY_PROMPT.format(text=item["text"])
            else:
                lines = "\n".join(f"- {x['id']}: {x['text'][:250]}" for x in cands)
                prompt = RAG_PROMPT.format(candidates=lines, text=item["text"])
            out = llm(model, prompt)
            pred, conf = parse(out["text"])
            rows[c].append({**base, "pred": pred, "conf": conf, "raw": out["text"],
                            "in_tok": out["in_tok"], "out_tok": out["out_tok"],
                            "latency": out["latency"],
                            "cost": cost(model, out["in_tok"], out["out_tok"])})
        if i % 20 == 0 or i == len(items):
            print(f"{i}/{len(items)}", file=sys.stderr)

    for c, r in rows.items():
        write_jsonl(RESULTS / f"{c}.jsonl", r)
    print(f"wrote {', '.join(configs)} -> {RESULTS}", file=sys.stderr)


# ── report ────────────────────────────────────────────────────────────
def ci95(p: float, n: int) -> float:
    return 1.96 * math.sqrt(p * (1 - p) / n) if n else 0.0


def score(rows: list, gold: dict, valid: set) -> dict:
    n = len(rows)
    exact = sum(r["pred"] == gold[r["id"]] for r in rows) / n
    parent = sum(bool(r["pred"]) and r["pred"].split(".")[0] == gold[r["id"]].split(".")[0]
                 for r in rows) / n
    halluc = sum(bool(r["pred"]) and r["pred"] not in valid for r in rows) / n
    no_ans = sum(not r["pred"] for r in rows) / n
    return {"n": n, "exact": exact, "exact_ci": ci95(exact, n), "parent": parent,
            "halluc": halluc, "no_answer": no_ans,
            "cost_per_1k": 1000 * sum(r["cost"] for r in rows) / n,
            "latency": sum(r["latency"] for r in rows) / n}


def cascade(small: list, large: list, gold: dict, valid: set) -> list:
    """Escalate rag_20b rows to rag_120b under three uncertainty signals.

    Computed offline from the two full runs: valid because calls are
    temperature-0 and independent. In production only escalated rows would
    hit the 120B model, which is exactly the cost counted here.
    """
    big = {r["id"]: r for r in large}
    margins = sorted(r["margin"] for r in small)
    rules = [("disagree w/ FAISS top-1", lambda r: r["pred"] != r["faiss_top1"])]
    for q in (0.25, 0.5, 0.75):
        t = margins[int(q * (len(margins) - 1))]
        rules.append((f"FAISS margin < p{int(q * 100)}", lambda r, t=t: r["margin"] < t))
    for t in (0.7, 0.8, 0.9):
        rules.append((f"20B confidence < {t}", lambda r, t=t: (r["conf"] or 0) < t))

    out = []
    for name, rule in rules:
        merged, n_esc = [], 0
        for r in small:
            esc = (not r["pred"]) or (r["pred"] not in valid) or rule(r)
            n_esc += esc
            b = big[r["id"]]
            merged.append({"id": r["id"], "pred": b["pred"] if esc else r["pred"],
                           "cost": r["cost"] + (b["cost"] if esc else 0.0),
                           "latency": r["latency"] + (b["latency"] if esc else 0.0)})
        s = score(merged, gold, valid)
        s.update({"rule": name, "escalated": n_esc / len(small)})
        out.append(s)
    return out


def error_rows(rows: list, items: dict, engine_lookup: dict, valid: set, is_rag: bool) -> list:
    out = []
    for r in rows:
        g = items[r["id"]]["gold"]
        if r["pred"] == g:
            continue
        if not r["pred"]:
            cat = "no_answer"
        elif r["pred"] not in valid:
            cat = "hallucinated_id"
        elif is_rag and g not in r["cand_ids"]:
            cat = "retrieval_miss"
        elif r["pred"].split(".")[0] == g.split(".")[0]:
            cat = "sibling_subtechnique"
        else:
            cat = "reasoning_miss" if is_rag else "wrong_technique"
        out.append({"id": r["id"], "text": items[r["id"]]["text"], "gold": g,
                    "gold_name": engine_lookup.get(g, {}).get("name", ""),
                    "pred": r["pred"],
                    "pred_name": engine_lookup.get(r["pred"] or "", {}).get("name", ""),
                    "gold_in_candidates": g in r["cand_ids"],
                    "auto_category": cat, "manual_label": ""})
    return out


def report(error_config: str) -> None:
    items = {x["id"]: x for x in load_jsonl(EVAL_SET)}
    gold = {k: v["gold"] for k, v in items.items()}
    with open(ROOT / "combined_mitre.json") as f:
        lookup = {e["id"]: e for e in json.load(f)["entries"] if "id" in e}
    valid = {t for t in lookup if ID_RE.fullmatch(t)}

    runs = {c: load_jsonl(RESULTS / f"{c}.jsonl")
            for c in ALL_CONFIGS if (RESULTS / f"{c}.jsonl").exists()}
    if not runs:
        sys.exit("no results yet; run `python eval/run_ttp_eval.py run` first")
    scores = {c: score(r, gold, valid) for c, r in runs.items()}

    lines = ["## TTP mapping: single configs", "",
             "| config | n | exact acc (95% CI) | parent acc | hallucinated ID | no answer | $ / 1k queries | latency (s) |",
             "|---|---|---|---|---|---|---|---|"]
    for c, s in scores.items():
        lines.append(f"| {c} | {s['n']} | {s['exact']:.1%} ± {s['exact_ci']:.1%} | {s['parent']:.1%} | "
                     f"{s['halluc']:.1%} | {s['no_answer']:.1%} | {s['cost_per_1k']:.3f} | {s['latency']:.2f} |")

    if "faiss" in runs:
        fr = runs["faiss"]
        lines += ["", "## Retrieval recall (gold technique in FAISS top-k)", ""]
        for k in (1, 5, TOP_K):
            rec = sum(gold[r["id"]] in r["cand_ids"][:k] for r in fr) / len(fr)
            lines.append(f"- recall@{k}: {rec:.1%}")

    cas = []
    if "rag_20b" in runs and "rag_120b" in runs:
        cas = cascade(runs["rag_20b"], runs["rag_120b"], gold, valid)
        ref = scores["rag_120b"]
        lines += ["", "## Cascade: rag_20b -> rag_120b", "",
                  "| escalation rule | escalated | exact acc | % of 120B acc | % of 120B cost |",
                  "|---|---|---|---|---|"]
        for s in cas:
            pct_acc = s["exact"] / ref["exact"] if ref["exact"] else 0
            pct_cost = s["cost_per_1k"] / ref["cost_per_1k"] if ref["cost_per_1k"] else 0
            lines.append(f"| {s['rule']} | {s['escalated']:.0%} | {s['exact']:.1%} | "
                         f"{pct_acc:.0%} | {pct_cost:.0%} |")

    if error_config in runs:
        errs = error_rows(runs[error_config], items, lookup, valid, error_config.startswith("rag"))
        with open(RESULTS / f"errors_{error_config}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(errs[0].keys()) if errs else ["id"])
            w.writeheader()
            w.writerows(errs)
        counts = {}
        for e in errs:
            counts[e["auto_category"]] = counts.get(e["auto_category"], 0) + 1
        lines += ["", f"## Error categories ({error_config}, {len(errs)} errors)", ""]
        for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
            lines.append(f"- {cat}: {n} ({n / len(errs):.0%})")

    summary = "\n".join(lines) + "\n"
    (RESULTS / "summary.md").write_text(summary)
    print(summary)
    plot(scores, cas)


def plot(scores: dict, cas: list) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plot", file=sys.stderr)
        return
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for c, s in scores.items():
        ax.errorbar(s["cost_per_1k"], s["exact"], yerr=s["exact_ci"], fmt="o", capsize=3)
        ax.annotate(c, (s["cost_per_1k"], s["exact"]), textcoords="offset points", xytext=(6, 4))
    if cas:
        pts = sorted((s["cost_per_1k"], s["exact"]) for s in cas)
        ax.plot([p[0] for p in pts], [p[1] for p in pts], "s--", alpha=0.7, label="cascade 20B→120B")
        ax.legend()
    ax.set_xlabel("USD per 1k queries")
    ax.set_ylabel("exact technique accuracy")
    ax.set_title("ThreatHunt-GPT TTP mapping: quality vs cost")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(RESULTS / "quality_cost.png", dpi=150)
    print(f"plot -> {RESULTS / 'quality_cost.png'}", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--configs", nargs="+", default=ALL_CONFIGS, choices=ALL_CONFIGS)
    r.add_argument("--limit", type=int, default=None)
    p = sub.add_parser("report")
    p.add_argument("--errors-for", default="rag_120b", choices=ALL_CONFIGS)
    args = ap.parse_args()
    if args.cmd == "run":
        if "faiss" not in args.configs:
            args.configs = ["faiss"] + args.configs   # retrieval recall needs it; free
        run(args.configs, args.limit)
    else:
        report(args.errors_for)


if __name__ == "__main__":
    main()
