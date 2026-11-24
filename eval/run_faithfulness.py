"""
eval/run_faithfulness.py — is the LLM hunt summary faithful to its input?

The summary is the only LLM-written part of a hunt. It is given the group's
CTI summary and its first SUMMARY_TTP_LIMIT techniques, and asked to write a
brief. Two ways it can go wrong:

  1. it cites technique IDs it was not given (checked automatically)
  2. it states facts that are in neither the CTI summary nor the techniques
     (checked by hand, because no regex can catch an invented claim)

Steps (run from the repo root):
    python -m eval.run_faithfulness generate   # 1 summary per group; needs GROQ_API_KEY
    python -m eval.run_faithfulness check      # automatic ID check + writes the labeling sheet
    # fill in the `label` and `reason` columns of eval/results/faithfulness_labels.csv
    python -m eval.run_faithfulness report     # automatic + manual results

Generated summaries are saved and reused, so labels always refer to the
exact text that was labeled. `generate --force` makes new ones.
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter

SUMMARIES = "eval/results/faithfulness_summaries.jsonl"
LABELS = "eval/results/faithfulness_labels.csv"
LABEL_CHOICES = ("faithful", "minor_issue", "unsupported_claim")

ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


# ── pure helpers (unit-tested) ─────────────────────────────────────────

def extract_ids(text):
    """Technique IDs mentioned in `text`, in order, without duplicates."""
    seen = []
    for tid in ID_RE.findall(text or ""):
        if tid not in seen:
            seen.append(tid)
    return seen


def classify_ids(mentioned, prompt_ids, group_ids, valid_ids):
    """Sort each mentioned ID into one bucket.

    in_prompt          given to the model                   -> fine
    parent_of_prompt   parent of a sub-technique it was given (T1114 for
                       T1114.001) -> a generalization, still supported
    group_not_prompt   the group's, but not in the prompt   -> recalled from memory, unverified
    not_in_group       real ATT&CK ID, not this group's     -> unsupported
    invalid            not an ATT&CK ID at all              -> hallucinated
    """
    prompt_ids, group_ids, valid_ids = set(prompt_ids), set(group_ids), set(valid_ids)
    prompt_parents = {p.split(".")[0] for p in prompt_ids if "." in p}
    out = {"in_prompt": [], "parent_of_prompt": [], "group_not_prompt": [],
           "not_in_group": [], "invalid": []}
    for tid in mentioned:
        if tid in prompt_ids:
            out["in_prompt"].append(tid)
        elif tid in prompt_parents:
            out["parent_of_prompt"].append(tid)
        elif tid in group_ids:
            out["group_not_prompt"].append(tid)
        elif tid in valid_ids:
            out["not_in_group"].append(tid)
        else:
            out["invalid"].append(tid)
    return out


def is_error_text(summary):
    """_call_llm() returns a '⚠ ...' message instead of raising."""
    return (summary or "").lstrip().startswith("⚠")


# ── steps ──────────────────────────────────────────────────────────────

def load_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def generate(force):
    from rag_engine import RAGEngine
    from pipeline import run_pipeline
    from agents.answer_agent import SUMMARY_TTP_LIMIT, LLM_MODEL

    existing = {} if force else {r["group"]: r for r in load_jsonl(SUMMARIES)}
    rag = RAGEngine()
    rows = []
    for group in rag.get_group_names():
        if group in existing and not is_error_text(existing[group]["summary"]):
            rows.append(existing[group])
            continue
        result = run_pipeline(group, rag)
        if result.get("status") != "ok":
            print(f"  skip {group}: {result.get('message')}", file=sys.stderr)
            continue
        ttps = result["ttp"]["ttps"]
        rows.append({
            "group": group,
            "model": LLM_MODEL,
            "cti_summary": result["cti"]["summary"],
            "prompt_ttp_ids": [t["id"] for t in ttps[:SUMMARY_TTP_LIMIT]],
            "group_ttp_ids": [t["id"] for t in ttps],
            "summary": result["answer"]["hunt_summary"],
        })
        print(f"  generated {group}", file=sys.stderr)

    os.makedirs(os.path.dirname(SUMMARIES), exist_ok=True)
    with open(SUMMARIES, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    errors = sum(is_error_text(r["summary"]) for r in rows)
    print(f"{len(rows)} summaries -> {SUMMARIES}" + (f"  ({errors} LLM errors; rerun generate)" if errors else ""))


def auto_check(rows, valid_ids):
    checked = []
    for r in rows:
        if is_error_text(r["summary"]):
            checked.append({**r, "error": True})
            continue
        ids = classify_ids(extract_ids(r["summary"]), r["prompt_ttp_ids"], r["group_ttp_ids"], valid_ids)
        checked.append({**r, "error": False, "ids": ids})
    return checked


def valid_attack_ids():
    with open("combined_mitre.json", encoding="utf-8") as f:
        ids = {e["id"] for e in json.load(f)["entries"] if "id" in e}
    from rag_engine import ICS_TECHNIQUES
    return ids | set(ICS_TECHNIQUES)


def print_auto(checked):
    ok = [c for c in checked if not c["error"]]
    n = len(ok)
    totals = Counter()
    with_problem = 0
    for c in ok:
        for k, v in c["ids"].items():
            totals[k] += len(v)
        if c["ids"]["not_in_group"] or c["ids"]["invalid"]:
            with_problem += 1
    mentioned = sum(totals.values())
    print(f"summaries checked: {n}  (LLM errors skipped: {len(checked) - n})")
    print(f"technique IDs mentioned: {mentioned}")
    for k in ("in_prompt", "parent_of_prompt", "group_not_prompt", "not_in_group", "invalid"):
        share = totals[k] / mentioned if mentioned else 0.0
        print(f"  {k:<17}{totals[k]:>4}  ({share:.0%})")
    print(f"summaries citing an ID outside the group or not in ATT&CK: {with_problem}/{n}")
    for c in ok:
        bad = c["ids"]["not_in_group"] + c["ids"]["invalid"]
        if bad:
            print(f"  {c['group']}: {', '.join(bad)}")


def write_label_sheet(checked):
    """Create or refresh the labeling CSV, keeping labels already filled in."""
    old = {}
    if os.path.exists(LABELS):
        with open(LABELS, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                old[row["group"]] = row
    fields = ["group", "label", "reason", "ids_outside_prompt", "summary", "cti_summary", "prompt_ttp_ids"]
    with open(LABELS, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for c in checked:
            if c["error"]:
                continue
            prev = old.get(c["group"], {})
            same_text = prev.get("summary") == c["summary"]
            w.writerow({
                "group": c["group"],
                "label": prev.get("label", "") if same_text else "",
                "reason": prev.get("reason", "") if same_text else "",
                "ids_outside_prompt": " ".join(c["ids"]["group_not_prompt"] + c["ids"]["not_in_group"] + c["ids"]["invalid"]),
                "summary": c["summary"],
                "cti_summary": c["cti_summary"],
                "prompt_ttp_ids": " ".join(c["prompt_ttp_ids"]),
            })
    print(f"\nlabeling sheet -> {LABELS}  (fill `label` with one of: {', '.join(LABEL_CHOICES)})")


def report_manual():
    if not os.path.exists(LABELS):
        print("no labeling sheet yet; run `check` first")
        return
    with open(LABELS, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    labels = Counter(r["label"].strip() for r in rows)
    done = sum(labels[c] for c in LABEL_CHOICES)
    bad = [r for r in rows if r["label"].strip() and r["label"].strip() not in LABEL_CHOICES]
    print(f"\nmanual labels: {done}/{len(rows)} done")
    for c in LABEL_CHOICES:
        share = labels[c] / done if done else 0.0
        print(f"  {c:<18}{labels[c]:>4}  ({share:.0%})")
    if bad:
        print(f"  unrecognized labels in: {', '.join(r['group'] for r in bad)}")
    for r in rows:
        if r["label"].strip() in ("minor_issue", "unsupported_claim"):
            print(f"  [{r['label'].strip()}] {r['group']}: {r['reason'].strip()}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--force", action="store_true", help="regenerate every summary")
    sub.add_parser("check")
    sub.add_parser("report")
    args = ap.parse_args()

    if args.cmd == "generate":
        generate(args.force)
        return
    rows = load_jsonl(SUMMARIES)
    if not rows:
        sys.exit("no summaries yet; run `python -m eval.run_faithfulness generate` first")
    checked = auto_check(rows, valid_attack_ids())
    print_auto(checked)
    if args.cmd == "check":
        write_label_sheet(checked)
    else:
        report_manual()


if __name__ == "__main__":
    main()
