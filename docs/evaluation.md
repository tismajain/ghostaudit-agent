# Evaluation and honest impact

These are historical aggregate measurements from the development project. The underlying competition data, canonical answers, outputs and raw traces are excluded because redistribution permission was not established. The synthetic demo tests behavior; it cannot reproduce or validate the historical benchmark scores.

## Clean measurements

| Variant | Status accuracy | Step F1 | Exact |
|---|---:|---:|---:|
| Strict early baseline, DEV | 9.09% | 10.32% | 0/22 |
| Best-effort baseline, DEV | 95.45% (21/22) | 87.41% | 5/22 |
| Guarded agent v3, DEV | 95.45% (21/22) | 87.41% | 5/22 |
| First untouched holdout | 90.00% (9/10) | 71.79% | 3/10 |

DEV v3 made 127 model calls and 79 tool calls, proposed 33 findings, and produced ten guard-confirmed planner facts. Final predictions changed zero times; 98 protected HIGH-confidence steps had zero regressions. The model's investigation capability did **not** demonstrate a metric improvement.

Untouched holdout precision was 87.50%, recall 60.87%, field accuracy 46.67%, and sequence-prefix accuracy 45.00%. There were 18 missing and four extra steps. HIGH-confidence precision was 93.75%, LOW was 81.25%. DEV minus holdout step-F1 gap was 15.61 percentage points. Ten holdout cases are a small generalization sample.

## Clean versus contaminated

The first holdout result stays the clean result. Later mechanical corrections addressed global binary routing and escaped log scalar values. The subsequent all-32 check is explicitly POST-HOLDOUT / CONTAMINATED: status 30/32, step precision 94.19%, recall 75.65%, F1 83.91%, exact 8/32, field accuracy 60.39%, sequence-prefix 44.63%. Public predictions were unchanged. No optional semantic tuning rule was adopted from the bounded posthoc analysis.

## Final runtime, not a new accuracy benchmark

- 518 requests; 286 routed for genuine live investigation.
- 1,470 model calls: 1,469 primary and one repair.
- 951 tool calls; 258 proposals; 119 CONFIRMED, 134 REJECTED, five UNVERIFIABLE verdicts.
- Zero final prediction changes; 286 gate-inclusive fallbacks. The failed promotion gate remained closed.
- 3,173,723 input + 119,523 output = 3,293,246 tokens using `gpt-4.1-mini`.
- No-key output matched byte-for-byte; exact-archive clean-room reproduction and final invariants passed.

No final 518-case accuracy is claimed without ground-truth evaluation. Model-call counts and guard confirmations are operational measurements, not accuracy gains. Dollar cost is not reconstructed from guessed historical prices.

The early overlapping-schema/context design used 489,689 tokens on DEV; v3 used 293,161, a 40.1% reduction. That combines avoided repair failures and context improvements; it is not an isolated experiment proving that compaction alone caused the reduction.

## Limitations

Ambiguous historical ownership, ungrounded resources, incomplete secondary-copy retrieval and PDF/PNG corroboration remain difficult. Earlier N/A supervision was limited; those annotations are not included here. The synthetic examples are small, fictional and intentionally transparent. Invariants check format, order, references and cutoff constraints, not exhaustive deletion completeness or legal compliance.
