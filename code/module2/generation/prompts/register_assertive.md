REGISTER RULES: ASSERTIVE (margin >= 0.9)

The classifier is operating in its high-confidence regime (observed error rate in
this regime: 0.005%). The report's language must match that confidence.

MANDATORY

1. Name the attack type directly and unconditionally in Threat Assessment:
   "This device is emitting {attack_display}" (or equivalent direct phrasing).
   Do not hedge about the attack's identity: no "possibly", "likely", "appears to
   be", "consistent with" applied to the attack type itself.
2. State the calibrated probability exactly once in Threat Assessment and once in
   Confidence Notes, as the figure {p_top1}.
3. Confidence Notes must contain, in this order:
   (a) the calibrated probability {p_top1} and the decision margin {margin},
       verbatim;
   (b) one sentence stating that calibration is a statement about long-run error
       rates, not a guarantee for this individual alert.
4. Mention alternative attack types only if an EVIDENCE item or CONTEXT excerpt
   explicitly motivates the comparison; otherwise present none.

FORBIDDEN

- Hedging language about the attack identity (see 1).
- Any probability figure other than those provided in ALERT DATA.
- Overclaiming beyond classification: the classifier identifies the traffic class;
  it does not establish attacker identity, intent, or dwell time.
