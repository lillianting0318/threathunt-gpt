# Evaluation

Two evaluations live here. They measure different parts of ThreatHunt-GPT.

| Eval | What it measures | Data | Runner |
|---|---|---|---|
| Group resolution | Does `resolve_group()` map a query to the right threat group, or to none? | `dataset.jsonl` (dev, 87), `group_test.jsonl` (test v1, 150), `group_test_v2.jsonl` (test v2, 100, sealed) | `run_eval.py`, `sweep_thresholds.py` |
| Technique mapping | Can a model map one CTI sentence to the right ATT&CK technique? (experimental classifier, not wired into the app) | `eval_set.jsonl` (200, built from MITRE procedure examples) | `run_ttp_eval.py` |

---

## 1. Group resolution

### Outcomes

Every query ends in one of three outcomes (`metrics.py`):

- **correct** — the expected group, or `None` for an out-of-scope query
- **wrong** — a group was returned, but not the expected one
- **missed** — nothing was returned for an in-scope query

Wrong is worse than missed. A miss tells the analyst "I don't know"; a wrong group sends them hunting for the wrong actor. So the headline numbers are:

- **out-of-scope false-match rate**: share of out-of-scope queries that returned a group
- **in-scope wrong-group rate**: share of in-scope queries that returned the wrong group
- accuracy, reported but not optimized on its own

### Dev set vs test sets

| | `dataset.jsonl` (dev) | `group_test.jsonl` (test v1) | `group_test_v2.jsonl` (test v2) |
|---|---|---|---|
| Size | 87 (57 + 30 added Nov 24) | 150 | 100 |
| Used to design or tune | yes | used once, then for diagnosis | **no — sealed** |
| Its score is | optimistic | the honest "before" number | the honest "after" number |

The dev set is where thresholds and rules are chosen, so its score overstates real performance. A test set is run once on a finished design. Once its failures have been read and used to change the code, it stops being a test set — which is what happened to v1 (see below), and why v2 exists.

The `exact` bucket of the test set shares group names with the dev set in a different case. That does not leak anything, because exact matching has no tunable parameter.

### Test set buckets (150)

| Bucket | n | What it checks |
|---|---|---|
| `exact` | 30 | case and whitespace variants of the 24 group names |
| `alias` | 40 | MITRE aliases not used in the dev set (`Sofacy`, `Nobelium`, `ZINC`, ...) |
| `substring_trap` | 20 | a group name inside a longer query (`APT1 indicators` must not become APT12) |
| `typo_or_variant` | 20 | typos and spacing variants (`APT 28`, `Lazerus Group`, `Cozy Bera`) |
| `out_of_scope` | 40 | real groups not in the data (`APT41`, `FIN6`), near-collisions (`APT38`, `FIN70`), tools (`Cobalt Strike`), and noise |

### Run

```bash
python -m eval.run_eval                                         # dev set
python -m eval.sweep_thresholds                                 # dev only: distance/margin grid + word gate
python -m eval.run_eval --dataset eval/group_test_v2.jsonl --save  # run ONCE, after the dev results are final
```

### Results

**Before (Nov 24, thresholds from Nov 17):**

| Set | Accuracy | OOS false-match rate | In-scope wrong-group rate |
|---|---|---|---|
| dev (57) | 93.0% | 0.0% | 0.0% |
| test v1 (150) | 86.0% | **32.5%** | 0.9% |

The dev set said the out-of-scope false-match rate was 0%. On held-out data it was 32.5%: 13 of 40 queries that should have returned nothing returned a group. The dev set had been tuned against, and it contained almost no short, unknown names — exactly where the failures were.

**Diagnosis (from test v1):** Pass 4 answered 20 queries and got 13 wrong. Nearly all were short, name-like strings — `FIN6 → FIN7`, `APT290 → APT29`, `LockBit → FIN7`, `Microsoft → admin@338`. A one- or two-word name gives the embedding almost nothing to work with, so the nearest group is picked by surface similarity. Pass 4 was built for descriptions, not names.

**Changes (designed on the dev set):**

1. **Pass 1.7, separator-insensitive matching.** `APT 28`, `apt_33`, `Hidden-Cobra` are the same identifiers written differently. They now match by whole-string equality after removing spaces, hyphens, underscores and dots, instead of falling through to Pass 4.
2. **Pass 4 word gate.** Pass 4 runs only for queries of at least `SEMANTIC_MIN_WORDS` (4) words. A shorter query that misses Passes 1–3 returns no match. A miss is safer than a confident wrong group.
3. **Dev set extended** with 20 short unknown names and 10 separator variants. These are new queries of the same *types* as the v1 failures, not copies of them.

**After:** run test v2 once, after the dev results are final.

| Set | Accuracy | OOS false-match rate | In-scope wrong-group rate |
|---|---|---|---|
| dev (87) | | | |
| test v2 (100) | | | |

### Known failures not fixed by these changes

- `Akira Kurosawa films` resolves to the ransomware group **Akira** via Pass 2. Passes 1–3 match strings, not meaning, so any query containing a group name is accepted. No threshold can fix this.
- `APT` alone resolves to **APT-C-23** via Pass 3, because `APT` appears as a whole token inside that name. This was seen while checking the labels of test v2, so v2 is not perfectly blind on this one query; it is recorded here rather than fixed, so the v2 run stays a fair test of the changes above.
- Typos (`Lazerus Group`, `Cozy Bera`) are missed. Fuzzy matching could recover them, but it must refuse digit changes or `FIN6` would match `FIN7` again.

---

## 2. Technique mapping

Maps one CTI sentence to a MITRE ATT&CK technique ID, comparing retrieval-only, LLM-only and RAG setups with gpt-oss-20b / gpt-oss-120b on Groq. Results: [`results/summary.md`](results/summary.md).

```bash
python eval/build_eval_set.py --n 200                 # rebuild eval_set.jsonl from MITRE STIX
python eval/run_ttp_eval.py run                       # needs GROQ_API_KEY; responses cached in eval/cache.jsonl
python eval/run_ttp_eval.py report                    # tables + results/quality_cost.png, no API calls
```

Limitation: gpt-oss may have seen ATT&CK procedure examples during pretraining, which could inflate the LLM-only scores.
