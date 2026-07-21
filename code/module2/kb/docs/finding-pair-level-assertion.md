---
doc_id: finding-pair-level-assertion
title: "Pair-Level Assertion: How Reports Handle the Ambiguous Gafgyt Flood Pair"
attack_family: gafgyt
attack_types: ["gafgyt_tcp", "gafgyt_udp"]
device_categories: ["generic"]
doc_type: project_finding
source: self_authored
is_distractor: false
---

# Pair-Level Assertion: How Reports Handle the Ambiguous Gafgyt Flood Pair

## The rule

When the detector's evidence stops at the pair boundary, the report's language must stop
there too. For gafgyt_tcp/gafgyt_udp alerts, reports assert the **pair superclass** -
"a Gafgyt tcp-or-udp flood" - quantified by the pair probability
**p_pair = p(gafgyt_tcp) + p(gafgyt_udp)**, and explicitly decline to pick a member.

## Why p_pair is trustworthy

On these alerts the model's probability mass is fully complementary within the pair
(p_tcp + p_udp ≈ 1) and pair-vs-rest separation is essentially perfect. The pair-level
probability was calibration-checked separately on held-out data: ECE 4.4×10⁻⁵, Brier
3.3×10⁻⁵ (89k samples). The model genuinely knows "this is a Gafgyt tcp-or-udp flood";
it genuinely does not know which - the report asserts exactly the first and never the
second.

## Language requirements for hedged pair reports

1. Assert the pair superclass with its p_pair value; do not report the individual
   p_tcp/p_udp split as if it were evidence.
2. State the indistinguishability and its cause (the feature space omits the transport
   protocol - see the companion finding).
3. Present the two candidates **symmetrically**. No ordering language: not "most
   likely tcp", not "leaning udp", not listing one candidate first with qualifiers.
   Within-pair preferences in the model derive from per-device capture artefacts that
   demonstrably do not generalise.
4. Include the disambiguation action: one packet's IP protocol field from the raw
   capture resolves the pair (see the packet-capture procedure).
5. Note that containment is identical for both candidates, so response proceeds at
   full speed despite the ambiguity.

## The two-register connection

These alerts populate the hedged register (top-1 margin < 0.9); nearly all hedged-regime
alerts are pair alerts. Assertive-register reports (margin ≥ 0.9) never need pair
language; hedged reports on pair alerts always do. A report mixing registers - hedged
margin with assertive language, or vice versa - indicates a pipeline fault and fails the
confidence-consistency audit.

## Why this matters beyond this dataset

Pair-level assertion is an instance of a general principle: calibrated abstention at the
model's knowledge boundary. Claiming less, honestly, outperforms claiming more,
plausibly - the difference between an explanation an analyst can act on and one that
launders a coin flip into confident prose.
