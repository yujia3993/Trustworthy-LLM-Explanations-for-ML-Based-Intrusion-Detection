---
doc_id: mirai-syn-flood
title: "Mirai SYN Flood Attack"
attack_family: mirai
attack_types: ["mirai_syn"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Mirai SYN Flood Attack

## Threat assessment

The infected device is emitting a TCP SYN flood as part of a coordinated DDoS attack.
Severity is high: the device is under botnet command and control and actively attacking a
third party.

## Mechanism

A SYN flood abuses the TCP three-way handshake. The bot sends a continuous stream of SYN
(connection-request) segments, typically with randomised source ports, and never
completes the handshake. Each SYN forces the victim to allocate a half-open connection
entry and hold it until timeout; at sufficient rate the victim's backlog is exhausted and
legitimate connections are refused. Mirai's implementation generates SYNs in a tight
loop, giving extremely high packet rates from even modest hardware, and can randomise
header fields to defeat simple signatures.

## Observable indicators

- Outbound TCP packet rate far above the device's benign baseline, sustained for the
  duration of the attack command.
- Minimal packet sizes with almost no variance: SYN segments carry no payload, so
  outbound mean packet size drops toward the TCP/IP header minimum and the size
  distribution becomes nearly degenerate.
- Machine-regular inter-arrival times from the packet-generation loop.
- No corresponding inbound data volume - the device sends handshake openers but never
  transfers data, inverting the usual request/response symmetry of benign traffic.

## Response priorities

Disconnect or isolate the device immediately to stop participation in the attack, then
power-cycle, rotate credentials, and remove WAN-exposed Telnet/management services before
returning it to the network. See the immediate containment and long-term hardening
guides.
