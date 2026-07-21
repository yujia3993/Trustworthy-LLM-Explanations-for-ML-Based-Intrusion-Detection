# Module 2 Generation Layer — Register Language Rules (v1.0.0)

This directory holds the confidence-aware report generation pipeline. This README is
the human-readable specification of the **two-register language design**; the
machine-readable counterparts are `prompts/register_*.md` (LLM-facing) and
`audit_rules.json` (audit-gate regexes). All three carry version 1.0.0 and must be
versioned together — a change to any is a new prompt version and invalidates cached
generations.

## Why two registers

The clean detector's confidence distribution is natively two-regime with an empty
middle: held-out margin < 0.9 has a 50.65% error rate (almost entirely the
gafgyt_tcp/udp pair, where within-pair assignment is a coin flip), margin ≥ 0.9 has
0.005%. Report language is matched to that structure — a finer gradation would have
no population to apply to. The register threshold (0.9) is insensitive: only 6 of
80k held-out alerts fall anywhere in (0.5, 0.99).

## The registers

| Register | Trigger | Identification language | Probability figure |
|---|---|---|---|
| `assertive` | margin ≥ 0.9 | attack type named directly, no hedging | p_top1 |
| `hedged_pair` | margin < 0.9 and top-2 = {gafgyt_tcp, gafgyt_udp} | pair superclass only, members symmetric | p_pair = p_tcp + p_udp |
| `hedged_generic` | margin < 0.9, other candidates (rare: 4 samples) | neither candidate asserted, both presented | p_top1 and p_top2 |

Runtime guard: an ambiguous-pair alert with margin ≥ 0.9 stays assertive but is
flagged `needs_review` (empty set on current data; a non-empty set signals drift).

## Core commitments (what makes this RQ2 material)

1. **Assert exactly what the model knows.** The pair-level identification is
   genuinely confident (p_pair calibration: ECE 4.4×10⁻⁵) and is asserted without
   hedging; the within-pair split carries no evidence and is never voiced. Claiming
   less, honestly, beats claiming more, plausibly.
2. **Symmetry is enforced, not preferred.** Within-pair ordering language is
   forbidden by regex (audit gate 3) because the model's apparent preferences are
   capture artefacts that demonstrably do not generalise.
3. **Every hedged report carries its own resolution path**: one packet's IP
   protocol field (6=TCP, 17=UDP) settles the pair; containment is identical for
   both and never waits for it.
4. **Numbers are format-locked.** All probabilities render at 4 decimal places in
   prompts and are string-checked in reports (gate 4), so an altered or invented
   confidence figure is mechanically detectable.

## The audit gates (RQ2, machine-checkable)

1. **Register mapping** — margin band ↔ register used (structural check).
2. **Hedged disclosures** — indistinguishability + pcap action + pair probability
   all present (regex).
3. **No ordering language** — forbidden-pattern list (regex).
4. **Probability consistency** — required formatted figures present; within-pair
   split figures absent (string match).

Known limitation, stated up front: 3 high-confidence errors exist in the assertive
regime's held-out data. Faithful confidence transfer is not a correctness guarantee;
the gates verify the report says what the model believes, not that the model is
right.

## Pipeline configs (RQ1 generation ablation)

`no_rag` → `naive_rag` (dense retrieval) → `full_rag` (hybrid+rerank+decomposition)
→ `self_check` (full_rag + post-generation self-check loop, prompts/self_check.md).

## Layout

```
generation/
├── README.md               # this spec
├── audit_rules.json        # gate definitions (v1.0.0)
├── prompts/                # LLM-facing templates (v1.0.0, see version.txt)
│   ├── system.md           # role + grounding rules + output format
│   ├── sections.md         # per-section content instructions
│   ├── register_*.md       # the three register rule blocks
│   ├── self_check.md       # self-check loop instructions
│   └── evidence_templates.json  # fixed evidence-injection templates + number formats
├── cases.py / registers.py / prompt_builder.py / llm_client.py
├── cache.py / pipeline.py / audit.py        # (implementation)
└── cache/                  # generation cache, gitignored
```
