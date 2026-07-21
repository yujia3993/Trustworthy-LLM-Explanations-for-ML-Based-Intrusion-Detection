---
doc_id: finding-temporal-artefacts
title: "Temporal Artefacts in Capture Datasets: The N-BaIoT Timestamp Leakage"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: project_finding
source: self_authored
is_distractor: false
---

# Temporal Artefacts in Capture Datasets: The N-BaIoT Timestamp Leakage

## The finding

Seven N-BaIoT features presented as jitter statistics (the HH_jit mean family and two
HH_jit variance features) actually contain epoch-scale capture timestamps - values
around 1.5×10⁹, Unix time for September 2017, the dataset's capture period. Because the
dataset's attack sessions were recorded sequentially (some only ~67 seconds apart), any
model trained on these features can learn *recording time* as a proxy for *attack
class*. In this project, a "perfect" single-feature separation of the Gafgyt tcp/udp
pair (AUC 0.9988) turned out to be a learned timestamp threshold; removing the seven
features dropped row-level macro-F1 from 0.998 to 0.908 and revealed the pair as
genuinely inseparable.

## Why standard validation missed it

Row-level splits, leave-one-device-out validation, confusion matrices, and calibration
analysis all scored the leaked model as excellent. Each validation axis excludes leakage
only along its own dimension - LODO rules out device-specific leakage but is
structurally blind to temporal leakage, because session recording order is consistent
across devices. The leakage was caught only when the explanation workflow demanded
analyst-citable evidence and the "best feature's" values turned out to be timestamps.

## Screening guidance for sequentially captured datasets

- **Value-scale screen**: flag any feature whose values sit at epoch scale (~10⁹) or
  otherwise far outside its documented semantic range; jitter measured in seconds has
  no business near 1.5×10⁹.
- **Fingerprint screen**: flag features whose class-conditional distributions form
  disjoint bands separated by clean gaps - genuine traffic statistics overlap;
  bookkeeping artefacts partition.
- Treat *any* per-class statistic computed on sequentially recorded captures as
  temporally contaminated until shown otherwise; residual time-correlation of genuine
  class differences is an irreducible property of such data and should be documented
  as a limitation rather than assumed away.

## The transferable lesson

A validation method only excludes leakage along the axis it is designed around, and
aggregate metrics cannot flag a feature whose *meaning* is wrong. Requiring
explanations to ground in actual feature values - evidence a human analyst could cite -
doubles as a leakage audit that aggregate validation structurally cannot perform. That
is the sense in which a faithful explanation layer audits its detector, not just
explains it.
