"""
Build a labeled TTP-mapping test set from MITRE ATT&CK procedure examples.

Each "intrusion-set USES attack-pattern" relationship in ATT&CK carries a short
CTI-style description (e.g. "APT28 has used Mimikatz to dump credentials"),
labeled with the technique it describes. That gives a free, expert-labeled
test set for "CTI sentence -> technique ID".

Usage (from the repo root):
    python eval/build_eval_set.py --n 200

Output: eval/eval_set.jsonl  (one {"id","text","gold","gold_parent","group"} per line)
"""

import argparse
import json
import random
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
HERE = Path(__file__).parent
TID_RE = re.compile(r"^T1\d{3}(?:\.\d{3})?$")          # enterprise techniques only
LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")          # [Mimikatz](https://...) -> Mimikatz
CITE_RE = re.compile(r"\(Citation:[^)]*\)")


def clean(text: str) -> str:
    text = LINK_RE.sub(r"\1", text)
    text = CITE_RE.sub("", text)
    text = text.replace("<code>", "").replace("</code>", "")
    return re.sub(r"\s+", " ", text).strip()


def external_id(obj: dict):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--mitre", default="combined_mitre.json",
                    help="ThreatHunt-GPT technique file; gold IDs missing from it are dropped")
    ap.add_argument("--out", default=str(HERE / "eval_set.jsonl"))
    args = ap.parse_args()

    print("Downloading MITRE ATT&CK STIX (~50 MB)...", file=sys.stderr)
    with urllib.request.urlopen(STIX_URL) as resp:
        bundle = json.load(resp)
    objs = {o["id"]: o for o in bundle["objects"]}

    # Only keep techniques the pipeline actually knows about, so a "miss" is
    # never caused by an ATT&CK version mismatch.
    known = None
    if Path(args.mitre).exists():
        with open(args.mitre) as f:
            known = {e["id"] for e in json.load(f)["entries"] if "id" in e}
    else:
        print(f"warning: {args.mitre} not found; not filtering by known IDs", file=sys.stderr)

    # text -> set of technique IDs (a sentence labeled with >1 technique is ambiguous)
    labels = defaultdict(set)
    group_of = {}
    for o in bundle["objects"]:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or not active(o):
            continue
        src, tgt = objs.get(o.get("source_ref")), objs.get(o.get("target_ref"))
        if not src or not tgt:
            continue
        if src.get("type") != "intrusion-set" or tgt.get("type") != "attack-pattern":
            continue
        if not active(src) or not active(tgt):
            continue
        tid = external_id(tgt)
        if not tid or not TID_RE.match(tid) or (known is not None and tid not in known):
            continue
        text = clean(o.get("description", ""))
        if len(text) < 40:
            continue
        labels[text].add(tid)
        group_of[text] = src["name"]

    pool = [
        {"text": t, "gold": next(iter(ids)), "gold_parent": next(iter(ids)).split(".")[0],
         "group": group_of[t]}
        for t, ids in labels.items() if len(ids) == 1
    ]
    pool.sort(key=lambda x: x["text"])           # deterministic before shuffling
    random.Random(args.seed).shuffle(pool)
    sample = pool[: args.n]
    for i, item in enumerate(sample):
        item["id"] = f"q{i:04d}"

    with open(args.out, "w") as f:
        for item in sample:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    n_ambig = sum(1 for ids in labels.values() if len(ids) > 1)
    n_sub = sum("." in x["gold"] for x in sample)
    print(f"pool: {len(pool)} sentences ({n_ambig} multi-label dropped)", file=sys.stderr)
    print(f"sample: {len(sample)} -> {args.out}", file=sys.stderr)
    print(f"unique techniques: {len({x['gold'] for x in sample})}, "
          f"sub-techniques: {n_sub / max(len(sample), 1):.0%}", file=sys.stderr)
    print("top parents:", Counter(x["gold_parent"] for x in sample).most_common(5), file=sys.stderr)


if __name__ == "__main__":
    main()
