## TTP mapping: single configs

| config | n | exact acc (95% CI) | parent acc | hallucinated ID | no answer | $ / 1k queries | latency (s) |
|---|---|---|---|---|---|---|---|
| faiss | 200 | 30.0% ± 6.4% | 38.5% | 0.0% | 0.0% | 0.000 | 0.00 |
| llm_20b | 200 | 38.0% ± 6.7% | 53.5% | 5.5% | 0.5% | 0.117 | 1.95 |
| llm_120b | 200 | 48.5% ± 6.9% | 63.5% | 3.0% | 0.0% | 0.141 | 0.57 |
| rag_20b | 200 | 56.5% ± 6.9% | 63.0% | 0.0% | 2.0% | 0.123 | 5.19 |
| rag_120b | 200 | 57.0% ± 6.9% | 65.0% | 0.0% | 0.5% | 0.174 | 0.74 |

## Retrieval recall (gold technique in FAISS top-k)

- recall@1: 30.0%
- recall@5: 58.0%
- recall@10: 70.5%

## Cascade: rag_20b -> rag_120b

| escalation rule | escalated | exact acc | % of 120B acc | % of 120B cost |
|---|---|---|---|---|
| disagree w/ FAISS top-1 | 62% | 56.0% | 98% | 134% |
| FAISS margin < p25 | 26% | 57.5% | 101% | 99% |
| FAISS margin < p50 | 50% | 57.5% | 101% | 122% |
| FAISS margin < p75 | 75% | 57.5% | 101% | 147% |
| 20B confidence < 0.7 | 6% | 56.5% | 99% | 78% |
| 20B confidence < 0.8 | 8% | 56.5% | 99% | 80% |
| 20B confidence < 0.9 | 12% | 57.0% | 100% | 84% |

## Error categories (rag_120b, 86 errors)

- retrieval_miss: 58 (67%)
- reasoning_miss: 18 (21%)
- sibling_subtechnique: 9 (10%)
- no_answer: 1 (1%)
