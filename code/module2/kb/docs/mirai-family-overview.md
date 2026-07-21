---
doc_id: mirai-family-overview
title: "Mirai Botnet Family Overview"
attack_family: mirai
attack_types: ["mirai_ack", "mirai_scan", "mirai_syn", "mirai_udp", "mirai_udpplain"]
device_categories: ["generic"]
doc_type: family_overview
source: self_authored
is_distractor: false
---

# Mirai Botnet Family Overview

Mirai is a self-propagating IoT botnet first observed in August 2016 and responsible for
some of the largest DDoS attacks on record, including the September 2016 attack on
krebsonsecurity.com (~620 Gbps), the OVH attack (~1 Tbps), and the October 2016 Dyn DNS
attack that disrupted major internet services across the US east coast. Its source code
was leaked publicly in September 2016, spawning a large family of derivatives.

## Threat assessment

A Mirai infection means the device has been conscripted into a DDoS botnet under external
command and control (C2). The device owner is rarely the target; the harm is outbound
attack traffic, bandwidth saturation, and exposure of the local network. Infected devices
remain fully functional from the user's point of view, so infections persist unnoticed.
Mirai resides only in memory: a reboot removes the binary, but reinfection typically
occurs within minutes if the device remains reachable with unchanged credentials.

## Propagation and infection

Mirai spreads by scanning the IPv4 space for devices exposing Telnet on TCP ports 23 and
2323, then brute-forcing a hard-coded dictionary of roughly 60 factory-default
username/password pairs (e.g. root/xc3511, admin/admin). Successful logins are reported
to a loader that pushes an architecture-matched binary. Once resident, the bot kills
competing malware and processes bound to common remote-access ports, connects to its C2,
and awaits attack commands. Consumer IoT devices - IP cameras, DVRs, home routers,
doorbells, and baby monitors - form the bulk of its victims.

## Attack repertoire (classes present in this dataset)

- **mirai_scan** - Telnet scanning/propagation traffic seeking new victims.
- **mirai_syn** - TCP SYN flood: connection-request exhaustion against a target.
- **mirai_ack** - TCP ACK flood: state-table exhaustion, also used to bypass naive SYN filters.
- **mirai_udp** - generic UDP flood with configurable payloads.
- **mirai_udpplain** - UDP flood with a stripped-down packet-building loop and fewer
  options, optimised for maximum packets-per-second.

## Analyst notes

Mirai attack traffic is machine-generated and highly regular: fixed or narrowly
distributed packet sizes, extreme packet rates, and near-constant inter-arrival times
that differ sharply from the bursty, low-volume traffic profile of a benign IoT device.
