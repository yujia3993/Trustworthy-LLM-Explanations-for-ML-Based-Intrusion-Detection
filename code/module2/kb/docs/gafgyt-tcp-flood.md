---
doc_id: gafgyt-tcp-flood
title: "Gafgyt TCP Flood Attack"
attack_family: gafgyt
attack_types: ["gafgyt_tcp"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.

## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.

## Observable indicators

- Sustained outbound packet rate far above the device's benign baseline, lasting for
  the commanded attack duration.
- Near-constant packet sizes - flood segments are built from a single template, so the
  outbound packet-size distribution has close to zero variance.
- Machine-regular inter-arrival times, unlike the bursty cadence of benign device
  traffic.
- Traffic aimed at a single victim address/port unrelated to the device's normal cloud
  endpoints.

## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
