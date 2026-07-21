---
doc_id: mirai-ack-flood
title: "Mirai ACK Flood Attack"
attack_family: mirai
attack_types: ["mirai_ack"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

## Mechanism

An ACK flood sends TCP segments with the ACK flag set that belong to no established
connection. The victim (or an intermediate stateful firewall/load balancer) must look up
each segment in its connection table before discarding it, exhausting CPU and state-table
capacity. Because ACK segments look like the middle of legitimate sessions, they pass
filters that only guard against connection-opening (SYN) traffic. Mirai's ACK flood
builds packets in a tight loop with randomised source ports and sequence numbers and a
configurable payload size.

## Observable indicators

- Sustained outbound TCP packet rate orders of magnitude above the device's benign
  baseline (thousands of packets per second from a device that normally emits a few).
- Very low variance in packet size: flood packets are built from one template, so the
  outbound packet-size distribution collapses to a near-constant value.
- Near-constant inter-arrival times - the regular cadence of a packet-generation loop
  rather than the bursty request/response pattern of benign device traffic.
- Traffic concentrated on one or a few destination hosts, unrelated to the device's
  normal cloud endpoints.

## Response priorities

Isolate the device from the network to stop the outbound flood, then follow standard IoT
containment: power-cycle to clear the memory-resident bot, change default credentials,
and block WAN-side Telnet before reconnecting. See the immediate containment and
long-term hardening guides.
