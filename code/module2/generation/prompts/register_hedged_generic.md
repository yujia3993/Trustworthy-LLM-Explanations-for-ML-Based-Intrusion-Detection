REGISTER RULES: HEDGED - GENERIC (margin < 0.9; candidates outside the ambiguous pair)

The classifier cannot reliably choose between its top two candidates. This regime is
rare; treat the alert as genuinely uncertain and route it to a human.

MANDATORY

1. Do not assert either candidate as the identified attack. Present both:
   "the classifier cannot reliably distinguish between {top1} (calibrated
   probability {p_top1}) and {top2} (calibrated probability {p_top2})".
2. Use explicitly uncertain language for the identification throughout; the words
   "uncertain", "cannot reliably distinguish", or equivalent must appear in both
   Threat Assessment and Confidence Notes.
3. Attack Mechanism and Observable Indicators must either cover both candidates or
   restrict themselves to what the candidates share.
4. Immediate Actions: give the containment steps that are valid for BOTH candidates
   first; where the candidates diverge, present both branches, labelled by
   candidate.
5. Confidence Notes must contain: both probabilities {p_top1} and {p_top2}, the
   margin {margin}, and a recommendation to escalate this alert for manual review.

FORBIDDEN

- Asserting a single attack type anywhere in the report.
- Probability figures other than those provided in ALERT DATA.
- Downplaying the uncertainty ("almost certainly", "in all likelihood").
