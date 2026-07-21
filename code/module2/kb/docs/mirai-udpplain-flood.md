---
doc_id: mirai-udpplain-flood
title: "Mirai UDP-Plain Flood Attack (High-PPS Variant)"
attack_family: mirai
attack_types: ["mirai_udpplain"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Mirai UDP-Plain Flood Attack (High-PPS Variant)

## Threat assessment

The infected device is running Mirai's optimised UDP flood. Severity is high and
equivalent to the generic UDP flood: the device is attacking a third party under botnet
control, at the maximum packet rate its hardware can produce.

## Mechanism

"UDP plain" is Mirai's stripped-down UDP attack. Where the generic UDP flood rebuilds
configurable header options for every packet, udpplain removes most options and reuses a
single pre-built packet template, spending CPU only on the send loop. On weak embedded
processors this raises achievable packets-per-second substantially - the attack is
optimised for PPS rather than per-packet flexibility. It is the variant of choice when
the operator wants raw packet rate against a single target port.

## Observable indicators

- The most extreme outbound packet rates of any Mirai attack class on the same
  hardware - the defining signature of this variant.
- An essentially degenerate packet-size distribution: every packet is built from the
  same template, so outbound size variance collapses to near zero.
- Extremely regular inter-arrival times, tighter than the generic UDP flood because no
  per-packet option handling perturbs the send loop.
- Single fixed destination address and port for the duration of the attack command.

## Response priorities

Identical to the generic UDP flood: isolate immediately (the uplink is likely
saturated), power-cycle to clear the memory-resident bot, rotate credentials, and remove
Telnet exposure before reconnecting. See the immediate containment guide.

## Analyst note on classification

udpplain and udp differ in implementation efficiency, not in protocol semantics. The
statistical distinction visible to a traffic-feature classifier is the packet-rate and
timing profile, which is why the two remain separable classes in this dataset.
