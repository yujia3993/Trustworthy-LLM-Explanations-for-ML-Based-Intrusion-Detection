# Evaluation Protocol (v1.0.0)

Design authority for the Module 3 evaluation harness. Frozen alongside
`prompts/claim_extraction.md`, `prompts/judge.md`, and `judge_rubric.json` — a
change to any is a new protocol version and invalidates prior evaluation runs.

## 1. The three-way claim taxonomy (RQ1)

Every atomic claim in a generated report receives exactly one label:

| Label | Grounded in provided material? | Factually true? |
|---|---|---|
| `supported` | yes (EVIDENCE item, CONTEXT chunk, or ALERT DATA) | (implied by grounding) |
| `unsupported_but_true` | no | yes |
| `unsupported_and_false` | no | no |

The two-axis design is the point: Mirai/Gafgyt are well covered by LLM parametric
knowledge, so *faithfulness to context* and *factual accuracy* decouple. A pipeline
can look "accurate" while ignoring its evidence entirely; only the taxonomy makes
that visible. **Hallucination rate = unsupported_and_false / all claims.
Faithfulness = supported / all claims.**

Grounding criterion: a claim is `supported` iff the cited [E#]/[C#] material (or
ALERT DATA) actually entails the claim's content. A citation attached to material
that does not entail the claim does NOT count as grounding (mis-attribution =
unsupported; its truth then decides which unsupported label).

## 2. Claim types and scoring routes

| Type | Definition | Scored by |
|---|---|---|
| `feature_claim` | Any claim quoting a numeric feature value, baseline statistic, probability, or a comparison derived from them | **machine** (`feature_verify.py`) |
| `knowledge_claim` | Malware family behaviour, protocol mechanics, attack semantics | LLM judge |
| `procedural_claim` | Response/remediation steps (isolation, pcap check, hardening) | LLM judge |

Claims are extracted and typed by a claim-extraction LLM pass
(`prompts/claim_extraction.md`), which extracts and classifies but never judges.
Machine-verifiable claims are routed away from the judge so the judge's error
surface covers only what machines cannot check.

## 3. Machine verification of feature claims

Deterministic, implemented in `feature_verify.py`, no LLM involved:

1. **Numeric fidelity.** Extract every numeric token from the report (excluding
   section numbering, list indices, [E#]/[C#] indices, and protocol constants
   6/17/23/2323 in pcap/Telnet context). Each must match, at the formatting used
   by the prompt builder (probabilities `{:.4f}`, feature values `{:.4g}`, ratios
   `{:.1f}`), a value in the case's allowed set: evidence values, benign
   median/std/p99, derived ratios, p_top1/p_top2/p_pair/margin, entropy.
   Non-matching numeric tokens are **fabricated numbers**.
2. **Citation validity.** Every [E#] must index an existing evidence item; every
   [C#] must index a chunk actually provided to the generator
   (`chunk_ids_by_section`). Out-of-range references are violations.
3. **Contextual misuse.** A CONTEXTUAL evidence feature named in the same sentence
   as phrasing that ties it to a specific attack type ("indicates", "confirms",
   "characteristic of", "signature of" + class name) is a violation — the
   language-level enforcement of the evidence screen.

Feature-claim verdicts: fabricated number ⇒ `unsupported_and_false`; correct value
with valid citation ⇒ `supported`; correct value, no/invalid citation ⇒
`unsupported_but_true` (the number is right but not attributed).

## 4. LLM judge (knowledge and procedural claims)

- Judge receives: the claim list, the report, the case's ALERT DATA + EVIDENCE,
  and the exact CONTEXT chunks the generator saw. It labels each claim with the
  taxonomy and scores the report-level rubric (`judge_rubric.json`):
  - `factual_accuracy` 1–5;
  - `actionability` decomposed into three 0/1 sub-criteria: device-specific action
    present; immediate vs long-term separated; advice matches device category;
  - `hallucination_check`: judge's independent count of fabricated content.
- **Independence rule:** the judge must be from a **different model family** than
  the generator/self-checker (env `JUDGE_API_KEY`/`JUDGE_BASE_URL`/`JUDGE_MODEL`,
  separate from `OPENAI_*`). Rationale: a same-family judge lets the pipeline
  optimise the judge's own scoring function.
- Judge outputs are cached by sha256(judge_model | case_id | config_name |
  eval_prompt_version); temperature 0.

## 5. Metrics and aggregation

Per (generation config × case split): taxonomy distribution, hallucination rate,
faithfulness, fabricated-number rate (machine), citation-violation rate,
contextual-misuse rate, actionability sub-scores, factual accuracy mean, RQ2 gate
pass rates (all four gates, from `generation.audit`), fallback/needs_review
counts. Primary comparison: the 4-config ladder no_rag → naive_rag → full_rag →
self_check on the frozen set.

## 6. RQ2 audit batch

`audit_report` runs on every (case × config) report — this is LLM-independent and
produces real numbers immediately (with MockLLM now, real models later). A hedged
report failing any gate is a pipeline defect; the per-gate pass-rate table is the
RQ2 headline artefact.

## 7. RQ3: judge validation against humans

- 20 cases (stratified: ≥8 hedged_pair, ≥2 assertive_error if available, remainder
  assertive_correct/hedged_generic), scored by human rater(s) on the same rubric
  via the exported scoring sheet (`rq3_sheet.py`).
- Agreement: **Cohen's κ** on the three-way claim labels (primary) and on
  actionability sub-criteria (secondary). Weighted κ (linear) on factual_accuracy.
- Stated caveats, fixed in advance: n=20 gives wide confidence intervals; a second
  human rater is sought, single-rater fallback is disclosed as a limitation.

## 8. What this protocol does not decide

Real generator/judge model choices (step 3); prompt iteration (dev set only, with
the prompt-iteration log recording version, targeted failure mode, measured
delta); any change to the frozen case set or gold set.
