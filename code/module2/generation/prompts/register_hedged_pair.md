REGISTER RULES: HEDGED - AMBIGUOUS PAIR (margin < 0.9; gafgyt_tcp / gafgyt_udp)

The classifier's evidence stops at the pair boundary: it is confident this is a
Gafgyt flood from the tcp/udp pair, and it has NO evidence for which member. Your
language must assert exactly the first and never the second.

MANDATORY

1. Identify the attack ONLY at the pair level: call it "a Gafgyt flood over TCP or
   UDP (the tcp-or-udp pair)" or equivalent pair-level phrasing. The only
   probability you may attach to the identification is the pair probability
   {p_pair} - use it in Threat Assessment and in Confidence Notes.
2. State explicitly, in BOTH Threat Assessment and Confidence Notes, that the two
   candidates cannot be distinguished from the available traffic features, and give
   the structural reason: the feature set does not record the transport protocol.
3. Present gafgyt_tcp and gafgyt_udp symmetrically, always as an unordered pair
   ("gafgyt_tcp and gafgyt_udp"). Attach no rank, preference, or likelihood to
   either member, in any section.
4. Immediate Actions must include this step, after containment: capture any single
   packet of the flood traffic (e.g. tcpdump at the gateway) and read the IP header
   protocol field - protocol 6 means gafgyt_tcp, protocol 17 means gafgyt_udp.
   State that containment is identical for both candidates and must not wait for
   this check.
5. Confidence Notes must contain: the pair probability {p_pair}; the
   indistinguishability statement (see 2); and one sentence stating that any
   within-pair probability split carries no evidential value because it derives
   from capture artefacts that do not generalise.

FORBIDDEN - any occurrence fails the report

- Ordering or preference language between the pair members: "more likely",
  "most likely", "probably tcp/udp", "leaning", "favors", "suggests tcp/udp",
  "primary candidate", "leading candidate", "top candidate", "best guess",
  "we believe it is".
- Reporting p(gafgyt_tcp) or p(gafgyt_udp) individually, or any phrasing implying
  one exceeds the other.
- Listing the members with rank markers ("first candidate", "second candidate").
- Hedging about the PAIR-level identification itself - that part is confident:
  the pair probability is {p_pair}. Do not write "possibly a Gafgyt flood".
