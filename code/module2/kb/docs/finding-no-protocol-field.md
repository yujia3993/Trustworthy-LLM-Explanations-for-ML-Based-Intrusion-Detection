---
doc_id: finding-no-protocol-field
title: "Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space"
attack_family: gafgyt
attack_types: ["gafgyt_tcp", "gafgyt_udp"]
device_categories: ["generic"]
doc_type: project_finding
source: self_authored
is_distractor: false
---

# Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space

## The finding

In the N-BaIoT statistical feature space, gafgyt_tcp and gafgyt_udp cannot be separated.
After removal of leaked timestamp features, no single traffic feature separates the
pair: class-conditional single-feature AUC lies in [0.4987, 0.5013] across all 9 devices
and all 5 time windows - statistically indistinguishable from coin-flipping - and pooled
AUC is ≈ 0.50.

## Why: the features never see the protocol

N-BaIoT features are stream aggregates - packet counts, size means and variances, and
timing statistics computed over recent traffic windows. **No feature encodes the IP
header's protocol field.** Both attacks are template-built maximum-rate floods from the
same codebase, so their aggregate statistics coincide; the one bit that separates them
(protocol 6 = TCP vs protocol 17 = UDP) is simply absent from the representation. The
limitation is structural to the feature design, not a model weakness - no classifier on
these inputs can do better than chance within the pair.

## What the model actually knows

The detector's knowledge boundary is clean: pair-vs-rest separation is essentially
perfect (out-of-pair precision ≈ 1.0, p_tcp + p_udp ≈ 1 on pair alerts), while
within-pair assignment carries no evidence. Apparent within-pair preferences are
per-device capture artefacts that do not generalise - two identical-hardware cameras in
the dataset exhibit opposite preferences - and must not be voiced in reports.

## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
