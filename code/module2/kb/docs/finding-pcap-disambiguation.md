---
doc_id: finding-pcap-disambiguation
title: "Packet-Capture Procedure: Resolving the Gafgyt TCP/UDP Ambiguity"
attack_family: gafgyt
attack_types: ["gafgyt_tcp", "gafgyt_udp"]
device_categories: ["generic"]
doc_type: project_finding
source: self_authored
is_distractor: false
---

# Packet-Capture Procedure: Resolving the Gafgyt TCP/UDP Ambiguity

## Purpose

When an alert is classified as the Gafgyt tcp-or-udp flood pair, the statistical
features cannot determine which flood it is (the feature space omits the transport
protocol). One packet of raw capture resolves it deterministically. This is the shortest
disambiguation path and should be the standard analyst follow-up on hedged pair alerts.

## The procedure

1. Capture (or retrieve from a rolling buffer) any single packet of the flood traffic
   from the flagged device during the attack window. On the gateway:
   `tcpdump -c 20 -w flood_sample.pcap host <device_ip>`
   Twenty packets is ample; one suffices.
2. Read the IP header's protocol field:
   `tcpdump -r flood_sample.pcap -n | head` shows the transport protocol per packet, or
   inspect the Protocol column in Wireshark.
3. Interpret: **protocol 6 (TCP) → gafgyt_tcp; protocol 17 (UDP) → gafgyt_udp.**
   Flood traffic is homogeneous, so any attack-stream packet gives the answer;
   inspect a few to confirm they are flood packets (single destination, template
   sizes) rather than the device's benign cloud traffic.

## Practical notes

- Capture at the network gateway or a switch mirror port; no access to the compromised
  device is required (its shell should be considered hostile anyway).
- If the attack has already stopped, check whether the router, IDS, or flow collector
  retains protocol-annotated flow records (NetFlow/sFlow) for the alert window - the
  protocol field survives in flow summaries too.
- The result is definitive, not probabilistic: this check terminates the ambiguity and
  the report's hedged register with it.

## Priority relative to containment

Run this **after** isolation, not before. Containment for both flood types is identical,
so disambiguation adds forensic precision but zero response value; never delay
quarantine to collect the sample.
