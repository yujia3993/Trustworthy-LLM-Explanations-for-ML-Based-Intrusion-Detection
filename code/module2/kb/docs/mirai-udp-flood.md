---
doc_id: mirai-udp-flood
title: "Mirai UDP Flood Attack"
attack_family: mirai
attack_types: ["mirai_udp"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Mirai UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a DDoS attack.
Severity is high: the device is under external control and its uplink is being used to
saturate a victim's bandwidth.

## Mechanism

A UDP flood overwhelms a target with connectionless datagrams. Because UDP requires no
handshake, the bot can transmit at line rate immediately; the damage is volumetric
(bandwidth exhaustion) and, secondarily, CPU load on the victim generating ICMP
port-unreachable responses. Mirai's generic UDP attack supports configurable payload
sizes, destination ports, and header options, letting operators tune packet size against
packet rate for the chosen target.

## Observable indicators

- Extreme sustained outbound packet rate - typically the highest-volume attack class a
  device emits, far above any benign baseline.
- Tightly clustered packet sizes determined by the configured payload; the outbound
  size distribution shows near-zero variance around the template size.
- Near-constant inter-arrival times characteristic of a transmission loop running as
  fast as the hardware allows.
- Traffic directed at one victim address (or small set), on ports unrelated to the
  device's normal services; total outbound byte volume dwarfs the device's usual
  telemetry.

## Response priorities

Isolate the device to stop the flood - a single infected IoT device can saturate a home
or branch uplink by itself, so containment also restores local connectivity.
Power-cycle, rotate credentials, and eliminate WAN-exposed Telnet before reconnecting.
See the immediate containment and long-term hardening guides.
