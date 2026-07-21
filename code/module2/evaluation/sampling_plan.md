# Evaluation Case Set — Sampling Plan (v1.0.0)

Design authority for `export_cases.py`. This document is frozen together with the
exported case sets; changing either requires a new version and invalidates
comparisons across evaluation runs.

## Population

Attack alerts from `code/results/alerts_full.parquet` **restricted to the held-out
test split**, reconstructed via `module1_exports.reconstruct_stage_b_split_indices()`
(alerts_full covers all 400k attack rows, including rows the model trained on;
evidence and probabilities for training rows would flatter the pipeline).
Features and ground-truth `label_type` join from `code/nbaiot_sampled.parquet` by
row index (= `sample_id`).

## Strata

Selection is fully deterministic: seed 42, candidate pools sorted by `sample_id`
before any sampling; device spread implemented as round-robin over devices sorted
alphabetically, taking lowest `sample_id` first within each device.

| Stratum | Definition | Size |
|---|---|---|
| `assertive_correct` | margin ≥ 0.9, `y_pred == label_type`, top-2 ≠ {gafgyt_tcp, gafgyt_udp}; 7 per each of the 8 non-pair attack classes, spread round-robin across the devices where that class exists | 56 |
| `assertive_error` | margin ≥ 0.9, `y_pred != label_type` (the calibrated-but-wrong case studies; ~3 expected on held-out) | all, cap 5 |
| `hedged_pair` | margin < 0.9, top-2 = {gafgyt_tcp, gafgyt_udp}; balanced 18/18 by ground-truth member (label_type tcp vs udp), each half spread round-robin across devices — the balance guarantees ≈50% within-pair disagreement, the natural error rate the hedged register must survive | 36 |
| `hedged_generic` | margin < 0.9, top-2 ≠ pair (33 such alerts exist library-wide; held-out subset expected single-digit) | all, cap 6 |

Frozen set target ≈ 100. **Dev set: 12 cases** (8 = one per non-pair class from
`assertive_correct` criteria; 4 = `hedged_pair` criteria, 2 per ground-truth member),
sampled from the same pools **after** removing every frozen-set `sample_id` —
disjointness is structural, not checked after the fact.

`stage_a_flagged` is recorded as per-case metadata and **never used as a filter**:
the Stage A gate preferentially misses exactly the low-confidence ambiguous-pair
alerts this evaluation most needs, so filtering on it would bias the study
population (see README, "Stage A is a production-gate demonstration only").

## Evidence screen rule (v1)

Evidence items come from `explain_alert(..., top_k=5)` (top SHAP families with
representative feature, actual value, and per-device benign reference). Each item
maps to a generation-layer `EvidenceItem` with `screen` assigned as:

- `discriminative` iff **all** of:
  1. `direction == "supports_pred_class"`;
  2. `z_score_vs_benign >= 3` **or** `actual_value > benign p99`;
  3. the alert is **not** an ambiguous-pair alert.
- otherwise `contextual`.

Rationale:
- Conditions 1–2 demand the feature both pushed the model toward the asserted class
  and sits far outside the device's benign envelope — anomaly alone is not
  discriminativeness, and SHAP prominence alone is not evidential value.
- The blanket demotion for ambiguous-pair alerts (condition 3) encodes this
  project's central finding: no feature separates the pair (per-device AUC ∈
  [0.4987, 0.5013]), and the pair's SHAP-prominent features (H_weight, H_variance)
  are carriers of per-device pole selection, not evidence. A pair report's
  identification rests on the calibrated pair probability; its evidence items
  describe anomaly against baseline only. This is the language-level enforcement of
  "SHAP prominence ≠ evidential value".
- Leakage screens 1–2 of the README's triple screen are inherited upstream:
  `explain_alert` already excludes timestamp-leak families via
  `is_explainable_feature`, and the post-audit fingerprint screen found no further
  disjoint-band features.

**v2 improvement, out of scope here**: generalise the marginal-separability screen
(triple-screen condition 3) from the tcp/udp pair to a full per-class ×
per-feature univariate AUC table, replacing the z-score/p99 proxy in condition 2.

## Case identity and format

`case_id = f"{stratum}-{sample_id}"`. Output is the generation layer's `AlertCase`
JSON (loadable by `module2.generation.cases.load_cases`) plus a parallel
`metadata` block per case: `stratum`, `label_type` (ground truth), `stage_a_flagged`,
`atypicality_score`, `sample_id`, `split="frozen"|"dev"`.

Files: `code/module2/evaluation/cases/eval_cases_frozen.json`,
`code/module2/evaluation/cases/eval_cases_dev.json`. Export must be idempotent —
re-running produces byte-identical output. The freeze point is the git commit of
these files together with this plan.
