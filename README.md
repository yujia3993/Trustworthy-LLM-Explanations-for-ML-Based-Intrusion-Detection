# Trustworthy LLM Explanations for ML-Based Intrusion Detection

**Grounding, confidence calibration, and hallucination evaluation — a case study on IoT botnet traffic (N-BaIoT), including a dataset leakage audit triggered by the explanation layer itself**

---

## What this project is about

Machine learning detectors are good at flagging attacks but bad at telling analysts *why*. The obvious fix — using an LLM with retrieval-augmented generation (RAG) to write the explanation — introduces a new failure mode: in a security context, a fluent but hallucinated report is worse than no report at all.

This project treats that tension as a research problem rather than an engineering afterthought. The central question is:

> **How do we make LLM-generated explanations of ML detections *trustworthy* — and how do we prove that they are?**

Concretely, it investigates three questions:

- **RQ1 — Hallucination & faithfulness.** How often does a RAG pipeline fabricate or mis-attribute claims when explaining intrusion detections? Which design interventions — evidence grounding in raw feature values, hybrid (BM25 + dense) retrieval with reranking, and a post-generation self-check loop — reduce the hallucination rate, and by how much? Claims are scored under a three-way taxonomy — **supported / unsupported-but-true / unsupported-and-false** — because Mirai/Gafgyt are well covered by LLM parametric knowledge, so *faithfulness to context* and *factual accuracy* decouple and must be measured separately. Feature-value claims are machine-verified against reference tables; knowledge claims go to an LLM judge. *(Evaluated via a controlled ablation across 4 pipeline configurations.)*

- **RQ2 — Confidence transfer.** A calibrated classifier emits a probability; an analyst reads prose. Can the calibrated confidence of the upstream ML model be faithfully propagated into the *language* of the report, and can the consistency between stated certainty and actual confidence be verified? On this task the clean model's confidence structure is natively **two-regime** (see below), so RQ2 validates language-register consistency across that boundary with three machine-checkable audit gates.

- **RQ3 — Can we trust the evaluator?** LLM-as-judge scoring is convenient but unproven for this task. Judge scores are validated against a human rubric (factual accuracy, actionability, hallucination check) on a 20-case set, with inter-rater agreement reported as Cohen's κ — an evaluation of the evaluation itself. The judge uses a different model family from the generator/self-checker to avoid the pipeline optimising the judge's own scoring function.

A fourth finding emerged unplanned and became central to the project's argument: **the explanation layer caught a dataset leakage that every standard detection-side validation missed** (see the leakage audit below). Faithful explanation is not just a downstream consumer of the detector — it is an audit surface for it.

## Headline results

| Question | Result |
|---|---|
| Leakage audit (triggered by evidence grounding) | **7 epoch-scale timestamp features found; removing them: row-level macro-F1 0.998 → 0.908, LODO 0.997 → 0.855. Damage confined entirely to gafgyt_tcp/udp (all other classes \|ΔF1\| < 2×10⁻⁴); binary attack recall ≈ 1.0 unaffected** |
| gafgyt_tcp vs gafgyt_udp separability (clean features) | **None found: single-feature separation AUC ∈ [0.4987, 0.5013] across all 9 devices × 5 time windows, pooled AUC ≈ 0.50** |
| Pair-level assertion calibration (p_pair = p_tcp + p_udp) | **ECE = 4.4×10⁻⁵, Brier = 3.3×10⁻⁵ (held-out, 89k samples, 18k pair-positives)** |
| Confidence regime structure (clean model, held-out) | **Two regimes, empty middle: margin < 0.9 → error rate 50.65% (≈ within-pair coin flip); margin ≥ 0.9 → error rate 0.005%. Calibration honest in both** |
| Hallucination rate, naive RAG → full pipeline | TBD |
| Retrieval Recall@5, naive → hybrid+rerank | TBD |
| LLM-judge ↔ human agreement (κ) | TBD |

## The leakage audit

**Discovery path.** While building evidence grounding — searching for analyst-citable features that discriminate gafgyt_tcp from gafgyt_udp — a single feature, `HH_jit_L0.01_mean`, showed a "perfect" single-variable AUC of 0.9988 with a suspicious geometry: the two classes' central 80% intervals did not overlap but were separated by a clean gap, and all 122 of the model's tcp→udp misclassifications fell *inside* that gap. The values themselves gave it away: ≈ 1.5059×10⁹ — Unix epoch timestamps from September 2017, the N-BaIoT capture period. The `HH_jit_*_mean` family (and two epoch-scale `HH_jit_*_variance` features) encode **capture time, not jitter statistics**. The apparent tcp/udp separability came from the attacks being recorded in separate sessions ~67 seconds apart; the model had learned a timestamp threshold.

**Impact, quantified.** Retraining Stage B on the clean feature set (108 traffic features, 7 removed):

| Metric | With timestamp features | Clean |
|---|---:|---:|
| Row-level macro-F1 | 0.998 | 0.908 |
| LODO macro-F1 (mean) | 0.997 | 0.855 |
| Binary attack recall | ≈ 1.0 | ≈ 1.0 |
| gafgyt_tcp F1 | 0.989 | 0.467 |
| gafgyt_udp F1 | 0.989 | 0.522 |
| All other 9 classes | — | \|ΔF1\| < 2×10⁻⁴ |

The leakage was **ecosystem-wide, not model-specific**: Stage A's unsupervised Isolation Forests exploited the same features (attack-session timestamps fall outside the benign training window, so "different time" masqueraded as "anomalous behaviour"); retraining Stage A clean drops weighted attack recall from 0.925 to 0.740. Both the supervised and unsupervised paths were caught by the same audit.

**Why every standard check missed it.** The leakage was invisible to row-level splits, leave-one-device-out validation, confusion matrices, and calibration analysis. LODO is *structurally blind* to temporal leakage because session recording order is consistent across devices — a validation method only excludes leakage along the axis it is designed around. The pre-audit LODO scored 0.997 and was (reasonably, and wrongly) read as "no leakage". The audit that worked was the explanation layer's grounding workflow: the process of finding evidence an analyst could cite doubles as a human review of what the model actually depends on. **This is a self-demonstrating instance of the project's core thesis.**

**Fallout, fully traced.** The formerly reported "residual weakness" — asymmetric tcp→udp confusion, corroborated three ways and localised to three devices — is superseded: the asymmetry was a one-sided effect of the learned timestamp threshold, and the device-specificity was a capture-session artefact. A post-audit fingerprint screen over the clean model's top-SHAP features (flagging any disjoint class-conditional bands with clean gaps) found no further directly-encoded leakage. Residual time-correlation of genuine class differences is an irreducible property of sequentially-recorded capture data and is documented as a limitation rather than cleaned into invisibility.

## Revised conclusions on the detection task

**Detection is saturated; typing is saturated for 9 of 11 classes.** Binary attack recall is ≈ 1.0 under both row-level and clean LODO evaluation, and 9 attack-type classes remain at ceiling. The one exception is genuinely informative:

**gafgyt_tcp vs gafgyt_udp are inseparable in this feature space.** After cleanup, no single feature separates the pair: pooled AUC ≈ 0.50, and per-device AUC across all 9 devices × 5 time windows spans [0.4987, 0.5013]. The cause is structural — N-BaIoT's statistical features do not encode the transport-layer protocol field. What the model does instead is **per-device pole selection**: with no evidence to use, each device collapses to predicting one class of the pair (Danmini and SimpleHome-1002 → udp; the other seven devices → tcp), which fully explains the residual ~50% row-level within-pair accuracy and the LODO collapse (a held-out device inherits the global pole). The cleanest single piece of evidence: two **identical-hardware** SimpleHome XCS7 cameras (1002 vs 1003) exhibit *opposite* polarity — the pole is determined by capture instance, not device behaviour. SHAP-prominent flow features (H_weight, H_variance) are the mechanism *carrier* of pole selection (interactions with device one-hots), not marginal evidence: **SHAP prominence ≠ evidential value**, a second, subtler decoupling of faithfulness from truth caught by the grounding workflow.

**Model knowledge boundary → assertion boundary.** On these alerts the probability mass is fully complementary within the pair (p_tcp + p_udp ≈ 1) and pair-vs-rest separation is perfect (all out-of-pair precision ≈ 1.0). The model *knows* "this is a Gafgyt tcp-or-udp flood" and *does not know* which. Reports therefore assert at the pair level with **p_pair = p_tcp + p_udp** (separately calibration-checked: ECE 4.4×10⁻⁵), explicitly state within-pair indistinguishability, present both candidates **symmetrically with no ordering language** (within-pair preference derives from non-generalisable capture-instance proxies), and give the analyst the shortest disambiguation path: a single packet's IP protocol field in the raw pcap resolves the ambiguity.

## Confidence structure (foundation for RQ2)

The clean calibrated model's margin (p₁ − p₂) distribution on held-out alerts is natively two-regime with an empty middle:

| Margin band | n | Error rate | gafgyt_tcp/udp share |
|---|---:|---:|---:|
| ≤ 0.5 | 17,993 | 50.65% | 99.96% |
| 0.5 – 0.9 | 4 | 25% | 0% |
| 0.9 – 0.99 | 2 | 0% | 0% |
| 0.99 – 1.0 | 62,001 | 0.005% | 0.02% |

Actual error rates differ by **four orders of magnitude** across the register boundary, and calibration is honest in both regimes (the hedged regime's 50.65% is exactly the within-pair coin flip the model reports). The register threshold (0.9) is insensitive — only 6 samples lie anywhere in (0.5, 0.99). Consequences for RQ2:

- **Two language registers, matching the data**: assertive (margin ≥ 0.9; 78% of alerts) and hedged-differential (margin < 0.9; ~pure ambiguous-pair alerts). A finer gradation would have no population to apply to.
- **Three machine-checkable audit gates**: (1) margin band → register mapping is correct; (2) every hedged report contains the indistinguishability disclosure and the pcap action; (3) no hedged report contains within-pair ordering language. A runtime guard flags any ambiguous-pair alert with margin > 0.9 for review (empty set on current data).
- The 3 high-confidence errors in the assertive regime are retained as case studies: calibrated ≠ infallible, and faithful confidence transfer is not a correctness guarantee — this bounds what RQ2 can claim.
- Low-confidence evaluation cases no longer need synthetic construction; the hedged regime supplies ~18k natural samples.

## System at a glance

```
Network traffic sample
        │
        ▼
┌─ Module 1: Detection (infrastructure, leakage-audited) ─────┐
│  Stage A: per-device Isolation Forest (clean features,      │
│     benign-only trained) — production gate ONLY; the        │
│     research evaluation path samples Stage B directly       │
│            │                                                │
│            ▼                                                │
│  Stage B: global XGBoost, 108 clean traffic features +      │
│     device one-hots, isotonic calibration (11 classes)      │
│     └─ attack type + calibrated p-vector, margin, p_pair    │
│  Exports: per-alert evidence block (top SHAP feature        │
│     families w/ actual values vs per-device benign          │
│     reference stats, atypicality), triple-screened          │
└────────────┼─────────────────────────────────────────────────┘
             ▼
┌─ Module 2: Explanation layer (research focus) ──────────────┐
│  Retrieval: hybrid BM25 + dense (MiniLM-L6-v2), cross-      │
│     encoder rerank, metadata filtering, per-section         │
│     query decomposition, ChromaDB; KB seeded with           │
│     distractors so retrieval is fallible and measurable     │
│  Generation: evidence-grounded, two-register confidence-    │
│     aware Markdown report; pair-level assertion for         │
│     ambiguous-pair alerts; optional self-check loop         │
└────────────┬─────────────────────────────────────────────────┘
             ▼
┌─ Module 3: Evaluation (research focus) ─────────────────────┐
│  4-config generation ablation + component-level retrieval   │
│  micro-ablation · three-way claim taxonomy (machine-        │
│  verified feature claims + judged knowledge claims) ·       │
│  RQ2 audit gates · judge from a different model family,     │
│  validated against human rubric (Cohen's κ)                 │
└──────────────────────────────────────────────────────────────┘
```

## The role of the detection pipeline

The two-stage detector is **infrastructure, not the contribution**. It exists to give the explanation layer realistic inputs — genuine attack classifications, calibrated probabilities, and per-sample feature evidence — rather than synthetic prompts. Its headline number is deliberately the *clean* one (macro-F1 0.908, LODO 0.855): the explanation layer cannot be simultaneously faithful and truthful on a model whose decisions depend on leaked timestamps, so the leaked model is retained only as the "before" column of the audit. The 11-class taxonomy is kept (no tcp/udp merge): merging would hide a genuine finding inside label design and break comparability with the N-BaIoT literature — and the inseparable pair is RQ2's best natural material.

**Stage A is a production-gate demonstration only.** Evaluation sets for Modules 2/3 are sampled directly from Stage B outputs, stratified across confidence regimes, with `stage_a_flagged` recorded as metadata — otherwise the gate's selection bias (it preferentially misses exactly the low-confidence, ambiguous-pair samples the research most needs) would contaminate the study population. The clean gate's 26% miss rate (concentrated in the ambiguous pair) and its redesign for deployment are documented and out of scope.

**Scope boundary.** LODO validates *cross-device* generalisation only. Cross-family generalisation (a previously unseen botnet toolkit) remains untested — a property of the dataset, not the split. Stated here rather than discovered by a reviewer.

## Dataset

**N-BaIoT** — 9 commercial IoT devices, 115 statistical traffic features per sample, aggregated over multiple time windows.

- Attack families: **Mirai** (ack, scan, syn, udp, udpplain) and **Gafgyt** (combo, junk, scan, tcp, udp)
- 7 devices have both families; 2 (Ennio Doorbell, Samsung SNH-1011-N Webcam) have Gafgyt only
- Labels derived from file paths: `label_binary`, `label_type` (11 classes), `device_name`
- Sampling: stratified, 5,000 rows per (device, label_type) cell → ~445k rows, saved as `nbaiot_sampled.parquet`
- **Known artefact (found by this project):** the `HH_jit_*_mean` family and two `HH_jit_*_variance` features contain epoch-scale capture timestamps. Because attack sessions were recorded sequentially, *any* per-class statistic computed on the raw feature set risks temporal contamination. Users of this dataset should screen for epoch-scale values before per-class analysis.

## Module 1 — Detection pipeline (complete, sealed after leakage audit)

**Stage A — per-device Isolation Forest.** One model per device, trained on benign traffic only, clean features. Weighted attack recall 0.740, benign FPR 0.125 (pre-audit: 0.925 / 0.117 — the difference is the unsupervised path's share of the timestamp leakage). Production gate only; not on the evaluation path.

**Stage B — global XGBoost + isotonic calibration (canonical).** 11-class classifier on 108 clean traffic features + 9 one-hot device columns; isotonic calibration on a held-out calibration split; all calibration summaries computed on a strictly held-out test split (quantile-binned ECE with per-bin counts, reflecting the extreme bimodality of the confidence distribution).

**Explainability exports** (`module1_exports.py`) — the interface contract consumed by Module 2:

- `alerts_full.parquet`: per-alert full calibrated probability vector, margin, entropy, p_pair, top-2 candidates, `stage_a_flagged`, `is_ambiguous_pair`.
- Two-layer SHAP: **global profiles** (predicted-class conditioned — mean signed and absolute SHAP per feature *family*, aggregating the 5 time-window variants of each statistic so near-duplicate features don't dilute rankings) answer "what does the model usually rely on for class X"; **local SHAP per alert** supplies the actual values the report cites. Device one-hots are excluded from citable evidence.
- Per-device **benign reference statistics** (median / std / p99): every cited feature value is expressed relative to the device's own benign baseline ("40× the benign median, above p99"), making feature claims machine-verifiable.
- **Atypicality score**: overlap between an alert's local top families and its class's global profile — a cheap, API-free signal for "classified as X on unusual evidence".
- **Triple evidence screen** — a feature enters *discriminative* claim templates ("this value indicates X") only if it passes all of: (1) no epoch-scale values; (2) no disjoint-band leakage fingerprint; (3) **marginal separability** — class-conditional univariate AUC above threshold with a per-device spot-check, *in addition to* SHAP relevance. Features passing SHAP but failing marginal separability are demoted to *contextual* statements. Screens (1)–(2) exist because of the timestamp leakage; screen (3) exists because H_weight/H_variance demonstrated that SHAP attribution in a global model with device one-hots can be prominent without evidential value.

**Design-decision log highlights.** Clean model as canonical despite the F1 drop (headline honesty > headline size). Register threshold chosen from data and shown to be insensitive. Pre-audit LODO's 0.997 recorded as a methodological lesson: LODO only rules out leakage along its own axis (device), not orthogonal axes (time).

## Module 2 — Explanation layer (in progress)

- **Knowledge base**: ~28 self-authored markdown documents (Mirai/Gafgyt variants, IoT remediation, device categories, attack concepts) as a precision core, expanded with external material (MITRE ATT&CK techniques, public botnet analyses, CVE entries, vendor advisories) to 300+ chunks — **including 20–30% deliberate distractors** (other botnet families, near-duplicate variant docs, plausible-but-off-target hardening advice) so that retrieval is fallible and the ablation has headroom to measure. New KB documents encode this project's own findings where analysts need them (protocol field absent from features; pcap disambiguation procedure; pair-level assertion rationale; temporal artefacts in capture datasets). Metadata schema (attack_family incl. `generic`, device_categories, doc_type, source, is_distractor) frozen before ingestion.
- **Retrieval**: per-report-section query decomposition; hybrid BM25 + dense (sentence-transformers/all-MiniLM-L6-v2, local) fused with reciprocal rank fusion; cross-encoder reranking (ms-marco-MiniLM-L-6-v2, local); ChromaDB with metadata filtering on attack family and device category — applied per-section, not as a hard filter, so generic remediation docs remain reachable.
- **Evidence grounding**: triple-screened discriminative features with actual values expressed against per-device benign baselines, injected via fixed templates; the LLM is instructed not to extrapolate beyond template semantics. Contextual features are barred from "this value indicates X" phrasing. Every key claim must cite a retrieved chunk or a feature value.
- **Confidence-aware generation (two registers)**: margin ≥ 0.9 → assertive report; margin < 0.9 → hedged-differential report asserting the pair superclass with p_pair, stating within-pair indistinguishability, presenting candidates symmetrically, and escalating to the pcap protocol-field check.
- **Case memory loop — demo-only**: confirmed-incident write-back is retained as a product demonstration but **excluded from all research configurations and ablations**: it recirculates LLM-generated text into future retrieval context (a hallucination-amplification loop — the precise failure mode this project studies), and no genuine incident-confirmation ground truth exists.
- **LLM**: provider-swappable OpenAI-compatible client (default gpt-4.1-mini; temperature 0), outputs cached by (config_hash, case_id, prompt_version) for cost-free re-evaluation. Fallback to raw retrieved chunks if the API is unavailable.
- **Output**: structured Markdown report — Threat Assessment, Attack Mechanism, Observable Indicators, Immediate Actions, Longer-term Remediation, Confidence Notes.

## Module 3 — Evaluation protocol (planned)

- **Generation ablation**: no-RAG baseline → naive RAG → hybrid + rerank RAG → + self-check loop, scored on faithfulness, factual accuracy, actionability, and hallucination rate under the three-way claim taxonomy. Feature-value claims are verified mechanically against the reference tables; knowledge claims go to an LLM judge **from a different model family** than the generator/self-checker.
- **Retrieval evaluated separately** from generation, at two granularities: the 4-configuration view, plus a **component-level micro-ablation** (dense-only / +BM25+RRF / +rerank / +decomposition) — free to run locally and necessary to attribute gains. Gold set (attack type × report section → expected documents) built alongside KB authoring and **git-frozen before any retrieval tuning**; Recall@5 and MRR per configuration.
- **Evaluation case set**: frozen before prompt iteration begins; stratified across confidence regimes and classes; the hedged regime is naturally populated (~18k candidates). A separate small dev set is used for prompt debugging so the frozen set stays untouched.
- **RQ2 audit**: the three machine-checkable gates above, plus a p_pair-language consistency check; the 3 high-confidence errors documented as the limit of what confidence transfer can promise.
- **Judge validation**: LLM-judge vs human rubric on 20 cases, Cohen's κ, with stated caveats (wide CI at n=20; second rater sought, single-rater fallback disclosed). Actionability is decomposed into concrete sub-criteria (device-specific action present; immediate vs long-term separated; advice matches device category) rather than scored as a gestalt.
- **Prompt iteration log**: prompt versions, the failure mode each revision targets, and the measured delta — the engineering process itself is part of the evidence.
- **Demo**: Streamlit, multi-panel (detection → retrieval traces → generated report), with an analyst feedback control whose log feeds the prompt iteration record.

## Repository structure

All source lives under `code/`. Module 1 scripts sit at the top of `code/`;
Modules 2 and 3 live in the `code/module2/` package. Raw data (`N-BaIoT/`) and the
sampled parquet are gitignored. `PROJECT_STATE.md` (repo root) tracks working state,
commit-by-commit progress, and next steps.

```
.
├── PROJECT_STATE.md               # working-state document (progress, decisions, next steps)
├── requirements.txt
├── code/
│   ├── dataloader.py              # dataset walk, stratified sampling → nbaiot_sampled.parquet
│   ├── train_stage_a.py           # per-device Isolation Forests (clean features)
│   ├── train_stage_b.py           # global XGBoost + isotonic calibration (canonical, clean)
│   ├── lodo_experiment.py         # leave-one-device-out validation
│   ├── lodo_experiment_no_time.py # LODO on the clean (timestamp-free) feature set
│   ├── leakage_filters.py         # clean-feature selection, epoch-scale family screen
│   ├── leakage_audit_stage_b_no_time.py  # clean-vs-leaked retrain audit
│   ├── clean_model_diagnostics.py # post-audit clean-model diagnostics
│   ├── tcp_udp_per_device_auc.py  # within-pair separability (per device × window)
│   ├── tcp_udp_polarity_diagnostic.py    # per-device pole-selection diagnostic
│   ├── module1_exports.py         # alerts_full, SHAP profiles, benign reference stats,
│   │                              #   calibration summaries, evidence screens, explain_alert
│   ├── models/                    # saved detectors, scalers, encoders (gitignored data → results/)
│   ├── results/                   # metrics, confusion matrices, LODO tables, calibration,
│   │                              #   shap_*, tcp_udp diagnostics, module1_export_schema.json
│   └── module2/                   # Module 2 (explanation) + Module 3 (evaluation)
│       ├── config.py              # frozen constants: CLASS_ORDER, REGISTER_THRESHOLD, pair
│       ├── contracts.py           # validated loaders for the Module 1 export artifacts
│       ├── kb_loader.py           # KB frontmatter parsing + schema validation
│       ├── kb/                    # FROZEN v1.0.0: metadata_schema.json, gold_set.json,
│       │                          #   docs/ (28 core + 10 distractor markdown docs)
│       ├── retrieval/             # chunking, ChromaDB ingest, 4-config ablation, evaluate
│       │                          #   (index/ is gitignored)
│       ├── generation/            # register-aware report pipeline
│       │   ├── prompts/           # FROZEN v1.0.0: system, sections, 3 registers, self-check
│       │   ├── audit_rules.json   # the four machine-checkable RQ2 gates
│       │   ├── cases.py registers.py prompt_builder.py llm_client.py cache.py
│       │   ├── pipeline.py        # GEN_NO_RAG / NAIVE_RAG / FULL_RAG / SELF_CHECK
│       │   └── audit.py
│       ├── evaluation/            # Module 3
│       │   ├── sampling_plan.md   # FROZEN case-set design
│       │   ├── cases/             # FROZEN v1.0.0: eval_cases_frozen.json (101) + dev (12)
│       │   ├── eval_protocol.md   # FROZEN: three-way taxonomy, scoring routes, rubric
│       │   ├── prompts/ judge_rubric.json
│       │   ├── export_cases.py claims.py feature_verify.py judge.py metrics.py
│       │   ├── run_eval.py rq3_sheet.py
│       │   └── results/           # per-config summary / claims / RQ2-audit CSVs
│       └── tests/                 # pytest suite (78 tests)
├── results_lodo/                  # pre-audit (leaked) LODO tables, retained as audit evidence
└── results_lodo_no_time/          # clean LODO tables + per-class confusion matrices
```

## Reproducing

Module 1 (detection artifacts consumed by Module 2):

```bash
pip install -r requirements.txt
cd code
python dataloader.py           # expects N-BaIoT CSVs; writes nbaiot_sampled.parquet
python train_stage_a.py
python train_stage_b.py
python lodo_experiment.py       # optional, ~10–30 min on CPU
python module1_exports.py       # explainability artifacts consumed by Module 2
```

Module 2/3 (from `code/`, as package modules):

```bash
python -m module2.retrieval.ingest        # build the ChromaDB index
python -m module2.retrieval.evaluate      # retrieval micro-ablation → results CSVs
python -m module2.evaluation.export_cases # (re)build the frozen evaluation case set
python -m module2.evaluation.run_eval --split dev --mock   # end-to-end harness, no API key
python -m pytest tests -q                 # 78 tests
```

Real-LLM evaluation runs (generation + judge) additionally require `OPENAI_API_KEY`
for the generator and `JUDGE_API_KEY` / `JUDGE_BASE_URL` / `JUDGE_MODEL` (a different
model family) for the judge; see `PROJECT_STATE.md` §6.