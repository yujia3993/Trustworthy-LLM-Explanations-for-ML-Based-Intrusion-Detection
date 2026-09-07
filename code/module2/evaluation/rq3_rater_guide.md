# RQ3 human rater guide

**Version 1.0 · 2026-07-24 · operational supplement, not a protocol change**

This guide tells a human rater how to fill the RQ3 scoring sheets. It **does not modify**
the frozen evaluation protocol (`eval_protocol.md` v1.0.0), the judge prompt
(`prompts/judge.md`), or `judge_rubric.json`. It was written **after** the frozen
101-case run completed, so it cannot have influenced any generated report or judge
verdict; it only operationalises how a human applies the already-frozen rubric.

---

## 1. What RQ3 measures, and why the rubric must be shared

RQ3 validates the LLM judge against a human rater by reporting Cohen's κ between them.
That number is only interpretable if **both raters applied the same rubric to the same
material**. Two consequences:

- **Use the judge's rubric, quoted verbatim below** — not your own standard of a "good
  report". If you apply a different scale, κ measures the gap between two rubrics, not
  the judge's validity.
- The pipeline guarantees the *material* is identical: the sheets were exported through
  the same caches the frozen run wrote, and all 602 claim texts were verified
  byte-identical to `eval_frozen_claims.csv`. Your job is to make the *rubric* identical.

### Blind-scoring discipline

- **Do not open `rq3_judge_reference.csv`.** It contains the judge's answers. Opening it
  invalidates RQ3.
- Score every item before running the `score` command.
- Known, disclosable exposure: the rater had already seen the judge's *aggregate*
  `factual_accuracy` mean (4.48 for `full_rag`, PROJECT_STATE §11.1) before scoring. This
  is a marginal statistic over 101 cases × 4 configs, not per-item information, and κ is
  chance-corrected against marginals — so it cannot manufacture per-item agreement. It is
  recorded here for disclosure rather than treated as disqualifying.

---

## 2. The sheets

| File | Rows | You fill |
|---|---|---|
| `results/rq3_scoring_sheet_reports.csv` | 20 (one per case) | `factual_accuracy`, `actionability_device_specific`, `actionability_phases_separated`, `actionability_matches_category` |
| `results/rq3_scoring_sheet_claims.csv` | 602 (one per judge-routed claim) | `human_label` |
| `results/rq3_case_materials.md` | 20 sections | nothing — **read-only reference** (§6.1) |
| `results/rq3_judge_reference.csv` | — | **nothing — do not open** |

`rq3_case_materials.md` holds the ALERT DATA / EVIDENCE / CONTEXT the judge was given, so
you can apply the `supported` entailment test. It contains no judge answers — it is safe,
and necessary, to read.

Sample: 20 cases, seed-42 stratified — 12 `hedged_pair`, 6 `assertive_correct`,
2 `assertive_error`. Reports are `full_rag` only. The full report text is in the
`report_md` column of the reports sheet.

When finished:

```bash
cd code && python -m module2.evaluation.rq3_sheet score
```

It aligns on `(case_id, claim_index)`, computes the three κ statistics, writes
`results/rq3_agreement.csv`, and **names the offending key** on any unfilled,
out-of-domain, or misaligned cell rather than silently producing a wrong coefficient.

---

## 3. The single most important distinction: truth vs grounding

This project's whole taxonomy separates two axes that are easy to conflate. Keep them
apart:

| Axis | Where you score it | The question |
|---|---|---|
| **Grounding / faithfulness** | `human_label` in the claims sheet | Is this claim *entailed by the provided material*? |
| **Factual accuracy** | `factual_accuracy` in the reports sheet | Does the report contain *false statements*? |

> **A claim that is uncited but correct does NOT reduce `factual_accuracy`.**
> It is labelled `unsupported_but_true` in the claims sheet and has **no effect** on the
> report-level factual score. Only *falsehood* reduces `factual_accuracy`.

The label `unsupported_but_true` exists precisely to hold this distinction. Because this
project spends most of its attention on citation behaviour, conflating the two is the
most likely rater error — check yourself on it.

---

## 4. `factual_accuracy` (integer 1–5)

### 4.1 The frozen anchors (verbatim from `prompts/judge.md`)

> "factual_accuracy": integer 1-5. **5 = no false statements; 3 = minor errors not
> affecting response; 1 = errors that would misdirect the response.**

**Only 5, 3, and 1 are anchored.** 4 and 2 are unanchored in the frozen rubric. The judge
faced the same under-specification and interpolated them on its own.

### 4.2 Operational scale

Use the **full 1–5 range**. Treat 4 and 2 as *ordinal interpolations between the frozen
anchors* — not as new criteria:

| Score | Definition |
|---|---|
| **5** | *(frozen)* No false statements. Vague, uncited, or unremarkable content is fine as long as it is true. |
| **4** | *(interpolated)* Short of 5, not yet 3 — no clear falsehood, but something makes you hesitate to call it clean: an overstatement, an absolute where a hedge belongs, an imprecision you would flag but not correct. |
| **3** | *(frozen)* Contains a definite minor error that does **not** change what a responder would do. |
| **2** | *(interpolated)* Worse than "minor", not yet misdirecting — an error that could cost a wasted step or mild confusion. |
| **1** | *(frozen)* Contains an error that would **actively misdirect** the response. |

When genuinely torn, prefer the anchored points (5/3/1); reach for 4 or 2 when you can
state the specific reason.

### 4.3 Why the full range, and not just the three anchored points

Restricting the human to {5, 3, 1} looks more principled but is measurably worse. The
judge assigns 4 or 2 in **39.8%** of cached judgements (n=530 across all runs):

| Judge score | 5 | 4 | 3 | 2 |
|---|---|---|---|---|
| share | 57.2% | **33.2%** | 3.0% | **6.6%** |

So a third of all items could never be an exact match. Simulating a rater whose
perception agrees with the judge *perfectly*, and who is limited only by the scale used
(20-case vector drawn to the observed marginals; linear-weighted κ):

| Rater scale | κ under perfect latent agreement | κ with realistic ±1 noise on 4/20 |
|---|---|---|
| **1–5** | **1.000** | **0.823** |
| {5,3,1}, rounding 4→5 | 0.420 | 0.429 |
| {5,3,1}, rounding 4→3 | 0.636 | — |

Restricting the scale roughly **halves κ** for a reason that has nothing to do with the
judge's accuracy, and κ ≈ 0.42 would be misread as "only moderate agreement".

There is also a degeneracy risk: the judge's scores concentrate at 4–5, so a three-point
rater may end up assigning 5 almost everywhere. A rater with no variance carries no
information and the chance correction drives κ to exactly **0.000** regardless of how
correct they were.

*(The simulation used a judge vector matching the observed marginal distribution, not the
20 RQ3 cases' actual values, which were deliberately not inspected. The magnitude depends
on the true distribution; the direction does not.)*

---

## 5. Actionability (0 / 1 each, verbatim from `prompts/judge.md`)

> - **"actionability_device_specific"**: 1 if at least one immediate action is specific to
>   this device category (not generic "isolate the device" boilerplate), else 0.
> - **"actionability_phases_separated"**: 1 if immediate containment and longer-term
>   hardening are clearly distinguished, else 0.
> - **"actionability_matches_category"**: 1 if the advice fits the device category (no
>   desktop/server advice for a camera; no irrelevant platform guidance), else 0.

These are binary and independent of factual accuracy — advice can be well-targeted and
still contain a factual error, or be flawless and generic.

---

## 6. Claim labels (602 rows, verbatim from `prompts/judge.md`)

> - **"supported"**: the claim's cited [E#]/[C#] material (or the ALERT DATA) actually
>   entails the claim. A citation that does not entail the claim does NOT make it
>   supported — judge entailment, not the presence of a citation marker.
> - **"unsupported_but_true"**: not entailed by any provided material, but factually
>   correct per established security knowledge (Mirai/Gafgyt behaviour, TCP/UDP mechanics,
>   standard IoT response practice).
> - **"unsupported_and_false"**: not entailed by any provided material, and factually
>   wrong, fabricated, or unverifiable-and-specific (invented ports, CVEs, dates,
>   capabilities).
>
> Judging notes: be strict about entailment but not pedantic about paraphrase; generic
> security truisms ("IoT devices are often insecure") are unsupported_but_true, not
> supported, unless cited material states them. When genuinely uncertain whether a
> specific factual claim is true, label it unsupported_and_false only if it asserts
> something concrete and checkable that you believe is wrong; otherwise
> unsupported_but_true.

### 6.1 Where to find the material a claim must be judged against

The judge is shown three blocks per case — ALERT DATA, EVIDENCE `[E#]`, and CONTEXT
`[C#]`. You get the same three, byte-identical, in **`results/rq3_case_materials.md`**
(one section per case, generated by the same `prompt_builder` helpers `judge.py` uses). It
contains no judge answers.

Workflow for one claim row:

1. Read `cited_refs` — a JSON list such as `["C3"]`, `["E1","E2"]`, or `[]`.
2. Open `rq3_case_materials.md` and **search for the `case_id`** (do not navigate by the
   table of contents — KB chunks carry their own `##` headings, so heading levels collide).
3. Read the referenced `[C#]` / `[E#]` entry in that case's section.
4. Decide **entailment**, per 6.2.

393 of the 602 claims (65%) carry at least one citation.

### 6.2 The marker is a pointer, not a gate

A citation marker is **neither necessary nor sufficient** for `supported`. The rubric says
so directly — *"judge entailment, not the presence of a citation marker"* — and its
definition of `unsupported_but_true` is *"not entailed by **any** provided material"*, not
"not cited". So:

| Situation | Verdict |
|---|---|
| Cites `[C3]`, and `[C3]` entails the claim | `supported` |
| Cites `[C3]`, but `[C3]` is merely *related* and does not entail it | **not** supported — mis-attribution |
| Cites nothing, but ALERT DATA or some provided `[E#]`/`[C#]` entails it | `supported` |
| Cites nothing, entailed by nothing provided, but true in the world | `unsupported_but_true` |
| Entailed by nothing provided, and wrong or fabricated | `unsupported_and_false` |

This is how the judge actually behaves. Over the `full_rag` knowledge/procedural claims of
the **81 cases outside your sample** (n=2278, so this discloses nothing about the items you
are scoring):

- **55.0%** of *uncited* claims were judged `supported` → a marker is not required;
- **9.7%** of *cited* claims were judged not-supported → a marker is not sufficient.

Do not shortcut to "no marker ⇒ unsupported". That single mistake would systematically
disagree with the judge on roughly half of the uncited claims.

### 6.3 Entailment vs relevance — the actual test

Ask: **"could I write this sentence using only the provided material, without adding a
fact of my own?"**

- **Yes** → `supported`.
- **No, I had to bring in outside knowledge** → `unsupported_but_true` (if the outside
  knowledge is correct) or `unsupported_and_false` (if it is not).

Being *on the same topic* is not entailment. A chunk describing Gafgyt's general flood
behaviour does not entail a specific claim about ICMP port-unreachable responses; a chunk
about credential hygiene does not entail a specific rotation interval. Per the rubric, be
strict about entailment but not pedantic about paraphrase — a faithful restatement of the
chunk's content is supported; a plausible extension of it is not.

**ALERT DATA is citable material even though it has no `[#]` token.** Classifier outputs —
`p_top1`, `p_pair`, `margin`, entropy, the device name — carry no citation marker because
of how the prompt renders them, so a claim resting on them will normally show
`cited_refs: []`. It is still `supported` if the ALERT DATA entails it. (This is the same
structural gap that the Round-2 scorer fix addressed for feature claims; those are
machine-verified and are not in your sheet, but the reasoning carries over.)

---

## 7. Decision procedure for one report

1. Read the report once, **looking only for false statements** — ignore whether they are
   cited.
2. For each error found, ask: **"if an analyst acted on this sentence, would they do the
   wrong thing?"**
   - No → 3-band
   - Yes → 1–2 band
3. No falsehoods at all → 5, or 4 if something is overstated.
4. Score the three actionability criteria independently.
5. Then label that case's claims for grounding.

---

## 8. Domain-specific calls

**Correct hedging is not an error.** On `hedged_pair` cases the classifier can identify
the `gafgyt tcp-or-udp` pair but not which member. A report saying the two candidates
cannot be distinguished because the feature set does not record the transport protocol is
**correct** — that earns a 5, not a deduction.

**Asserting within the ambiguous pair is a 1.** If a `hedged_pair` report states the
attack *is* TCP (or *is* UDP) as fact, that would send an analyst toward the wrong
forensics. This is the failure the register rules and RQ2 gate 3 exist to prevent.

**Invented statistics that do not misdirect land in the 3-band.** The frozen/dev runs
contain e.g. *"a long-run error rate of 0.005% in this high-confidence regime"* — a
calibration figure appearing nowhere in the case data. It is definitely false, but an
analyst would not act differently because of it.

**Template phrasing that reads oddly is not automatically a factual error.** Evidence
lines render as e.g. *"H_L0.01_weight = 1, which is 0.1x below the device's benign median
of 12.62 and within the benign 99th percentile of 18.37; anomalous relative to
baseline"*. "Within the 99th percentile" is trivially true for a low value and sits
awkwardly beside "anomalous", but the numbers are faithful transcriptions of the case data
and "anomalous" is the evidence screen's own verdict, not a claim about the world. Not an
error — note it in your own log if it bothers you.

---

## 9. Practical workflow

- Score **all 20 reports first** (one mental mode), **then** the 602 claim labels. Mixing
  the two invites cross-contamination between the truth axis and the grounding axis.
- Keep a private note of your reason for every 4 and every 2. You will need them for the
  limitations section.
- Claims are pre-sorted by `(case_id, claim_index)`; fill straight down.
- ~30 claims per case. Budget accordingly.

---

## 10. Text to disclose in the write-up

> The frozen judge rubric anchors `factual_accuracy` at 5, 3, and 1 only; 4 and 2 are
> unanchored. Both the judge and the human rater therefore interpolated these two points
> independently. The rater used the full 1–5 range to match the judge's response space —
> the judge assigned 4 or 2 in 39.8% of cached judgements, so restricting the rater to the
> three anchored points would have introduced a scale-mismatch artefact (simulated κ loss
> ≈ 0.40 under perfect latent agreement, with a degenerate κ = 0 in the zero-variance
> case). Agreement is reported from a single rater; a second rater was sought and not
> obtained, and this is disclosed as a limitation per `eval_protocol.md` §7.
