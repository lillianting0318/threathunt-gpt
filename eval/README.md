# Evaluation

Two evaluations live here. They measure different parts of ThreatHunt-GPT.

| Eval | What it measures | Data | Runner |
|---|---|---|---|
| Group resolution | Does `resolve_group()` map a query to the right threat group, or to none? | `dataset.jsonl` (dev, 87), `group_test.jsonl` (test v1, 150), `group_test_v2.jsonl` (test v2, 100, sealed) | `run_eval.py`, `sweep_thresholds.py` |
| Summary faithfulness | Does the LLM hunt summary stick to the CTI summary and techniques it was given? | one generated summary per group (24) | `run_faithfulness.py` |
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

**After (test v2 run once, on the committed design):**

| Set | Accuracy | OOS false-match rate | In-scope wrong-group rate |
|---|---|---|---|
| dev (87) | 95.4% | 0.0% | 0.0% |
| test v2 (100) | 89.0% | **2.5%** | 0.0% |

The out-of-scope false-match rate fell from 32.5% (test v1) to 2.5% (test v2). The one remaining false match is `APT → APT-C-23`, recorded below before v2 was run. All 10 misses are typos, which no pass handles yet. Accuracy is not comparable across v1 and v2 because their bucket mixes differ; the false-match rate is, since both have 40 out-of-scope queries.

Limitation: v2 contains no descriptive queries, so Pass 4 never fired on it. v2 shows that short queries no longer produce confident wrong answers; it does not measure Pass 4 on descriptions. The next test set should include them. The word gate of 4 also rests on only 6 descriptive dev queries (5 would already block a correct one).

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

---

## 3. Summary faithfulness

The hunt summary is the only text in a hunt written by the LLM. The model is given the group's CTI summary and its first 10 techniques (`SUMMARY_TTP_LIMIT` in `agents/answer_agent.py`). The question is whether the summary stays within that input.

### Automatic check: technique IDs

Every technique ID in the summary is sorted into one bucket:

| Bucket | Meaning |
|---|---|
| `in_prompt` | the model was given it — fine |
| `parent_of_prompt` | the parent of a sub-technique it was given (`T1114` for `T1114.001`) — a generalization, still supported |
| `group_not_prompt` | belongs to the group, but was not in the prompt — recalled from training, not verified |
| `not_in_group` | a real ATT&CK technique, but not this group's — unsupported |
| `invalid` | not an ATT&CK ID at all — hallucinated |

### Manual check: claims

No regex can tell whether "the group targets European defense contractors" is supported. Each summary is labeled by hand in `results/faithfulness_labels.csv`:

| Label | Use when |
|---|---|
| `faithful` | every claim is supported by the CTI summary or the given techniques |
| `minor_issue` | supported overall, but one detail is vague, overstated, or slightly off |
| `unsupported_claim` | at least one specific claim (a target, date, tool, motive, or technique) is in neither input |

Write the reason in one line, quoting the claim. Label against the input shown in the sheet, not against outside knowledge: a true fact the model was not given is still `unsupported_claim`, because the pipeline cannot vouch for it.

### Run

```bash
python -m eval.run_faithfulness generate   # one summary per group; needs GROQ_API_KEY
python -m eval.run_faithfulness check      # automatic check + labeling sheet
# fill label / reason in eval/results/faithfulness_labels.csv
python -m eval.run_faithfulness report
```

Summaries are saved, so labels always refer to the text that was labeled. Re-running `check` keeps existing labels for unchanged summaries.

### Results

### Results

| Prompt | faithful | minor_issue | unsupported_claim |
|---|---|---|---|
| v1: asks for "profile and motivation" | 0 | 1 | 23 |
| v2: use only the given input; no unstated motive, sponsor, targets or tools | 1 | 9 | 14 |

Technique IDs: 136/136 supported in v1 (one is the parent of a given sub-technique).

**v1:** most unsupported claims (about 19 of 23) were motives. The prompt asked for "motivation", which the CTI summaries rarely state, so the model supplied one.

**v2:** stated motives nearly disappeared, but unsupported detail moved elsewhere: added target sectors (6), kill-chain steps beyond the given techniques (5), aliases and tool names from memory (4, including the likely invented alias "APT-Iran-13"), and one misclassification. These cluster in groups with only one or two techniques, where the prompt still asks for 2-3 sentences of kill chain.

One error the ID check cannot catch: the ALLANITE summary maps screen capture to T0859 instead of T0852. Both IDs were in the prompt, so only a human read finds it.

Limits: one annotator (the author), not blind to the prompt version. Prompt v2 was written after reading the v1 failures on the same 24 groups, so the v2 numbers are optimistic. There are no further groups to hold out.

### Limits

- 24 summaries, one per group, labeled by one person (the author). Expect noise, and no inter-annotator agreement.
- Temperature is 0.3, so a regenerated summary can differ. The numbers describe this saved set.
- The ID check only sees IDs written out; a technique described in words without its ID is invisible to it.
