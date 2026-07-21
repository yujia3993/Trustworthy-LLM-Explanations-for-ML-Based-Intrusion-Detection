---
doc_id: gafgyt-udp-flood
title: "Gafgyt UDP Flood Attack"
attack_family: gafgyt
attack_types: ["gafgyt_udp"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.

## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.

## Observable indicators

- Extreme sustained outbound packet rate - among the highest-volume traffic the device
  can produce, orders of magnitude above its benign baseline.
- Near-degenerate outbound packet-size distribution around the configured payload size.
- Near-constant inter-arrival times from the template send loop.
- A single victim destination, with total outbound byte volume vastly exceeding the
  device's normal telemetry and streaming profile.

## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.
