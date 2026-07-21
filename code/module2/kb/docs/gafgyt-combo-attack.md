---
doc_id: gafgyt-combo-attack
title: "Gafgyt Combo Attack (Junk Payloads + Connection Opening)"
attack_family: gafgyt
attack_types: ["gafgyt_combo"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Gafgyt Combo Attack (Junk Payloads + Connection Opening)

## Threat assessment

The infected device is running Gafgyt's "combo" attack: it repeatedly opens TCP
connections to a victim IP and port while pushing junk payload data through them.
Severity is high - the device is under botnet control and attacking a third party with a
technique aimed at application/connection-handling resources rather than raw bandwidth.

## Mechanism

Where a plain flood transmits template packets statelessly, combo drives the victim's
full connection stack: each cycle establishes a TCP connection (completing handshakes),
writes a stream of random junk bytes, and moves on, keeping many connections churning
simultaneously. This consumes the victim's accept queues, per-connection buffers, and
application worker capacity, and can degrade services behind proxies that raw SYN floods
do not reach. Payload junk defeats naive content-based filtering.

## Observable indicators

- Elevated outbound packet rate - high, but typically below the raw flood classes,
  because handshake round-trips throttle the loop.
- A **mixed** outbound packet-size distribution: handshake-sized control segments
  interleaved with junk-payload data segments, giving higher size variance than
  template floods (which are near-degenerate).
- Bidirectional traffic with the victim: unlike stateless floods, combo completes
  handshakes, so inbound ACK traffic from the target accompanies the outbound stream.
- Repeated short-lived connections to a single destination address and port.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. See the immediate containment and long-term hardening
guides.
