---
doc_id: mozi-botnet-overview
title: "Mozi IoT Botnet Overview"
attack_family: other_botnet
attack_types: []
device_categories: ["generic"]
doc_type: threat_intel
source: public_analysis
is_distractor: true
---

# Mozi IoT Botnet Overview

Mozi is a peer-to-peer IoT botnet that emerged around late 2019 and grew to dominate IoT
botnet traffic in 2020-2021. It reuses source code from Mirai, Gafgyt, and the earlier
IoT Reaper botnet, illustrating how heavily this malware ecosystem forks and recombines.

## Architecture and propagation

Mozi's defining feature is its use of a BitTorrent-like distributed hash table (DHT) for
peer-to-peer command and control, giving it Hajime-style resilience against takedown.
Beyond default-credential Telnet brute forcing, Mozi actively exploits known CVEs in
specific device families - Netgear, D-Link, and Huawei routers, and various DVRs -
using published remote-code-execution vulnerabilities as an additional propagation path
alongside weak credentials.

## Capabilities

Mozi nodes support DDoS attacks (multiple flood types), payload execution, and data
exfiltration. Its scale made it a persistent source of internet background scanning
noise. Reports in 2021 indicated the botnet's original operators were arrested, and a
kill-switch payload was later observed propagating, though residual infected nodes
persisted well afterward because the malware achieves persistence on some device models.

## Relevance to defenders

Mozi is a useful counter-example to the assumption that IoT botnets rely on default
credentials alone: its CVE-exploitation path means firmware patching, not just
credential hygiene, matters for the specific device families it targets. For devices
outside those families the standard controls - credential rotation, Telnet-exposure
removal, network segmentation - remain the effective defence.
