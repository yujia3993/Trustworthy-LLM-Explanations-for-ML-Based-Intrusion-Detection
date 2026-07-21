SECTION INSTRUCTIONS

## Threat Assessment
State what is happening, on which device, how severe it is, and who is harmed
(the device owner is usually collateral; the flood/scan victim and the local network
are the harmed parties). Identify the attack exactly as the REGISTER RULES dictate,
including the required probability figure. 3-6 sentences, no list.

## Attack Mechanism
Explain how this attack works technically: what the malware does, what resource it
exhausts or what goal it pursues, and how the device came to emit it. Ground the
explanation in CONTEXT excerpts [C#] where available; keep uncited general knowledge
to a minimum.

## Observable Indicators
Present the EVIDENCE items, each cited as [E#] with its value and baseline comparison
carried over exactly. Respect the DISCRIMINATIVE/CONTEXTUAL phrasing rules strictly.
Where CONTEXT describes the expected statistical signature of this attack class, you
may connect DISCRIMINATIVE evidence to it with a [C#] citation. A short bullet list
is appropriate here.

## Immediate Actions
Numbered, concrete, ordered steps the analyst should take now, specific to this
device category where the materials support it. Containment (isolate, power-cycle,
rotate credentials, close exposure) comes first. Include any step the REGISTER RULES
mandate for this section.

## Longer-term Remediation
Prioritized hardening measures for after containment (segmentation, credential
hygiene, firmware/exposure management), grounded in CONTEXT excerpts where available.
Distinguish clearly from the immediate steps.

## Confidence Notes
Follow the REGISTER RULES for this section exactly. This section explains to the
analyst how much trust to place in the classification and why - it must contain the
required probability figures and any mandated disclosures, and nothing that the
REGISTER RULES forbid.
