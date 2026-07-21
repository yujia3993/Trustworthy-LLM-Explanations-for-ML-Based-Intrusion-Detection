---
doc_id: gafgyt-family-overview
title: "Gafgyt (BASHLITE) Botnet Family Overview"
attack_family: gafgyt
attack_types: ["gafgyt_combo", "gafgyt_junk", "gafgyt_scan", "gafgyt_tcp", "gafgyt_udp"]
device_categories: ["generic"]
doc_type: family_overview
source: self_authored
is_distractor: false
---

# Gafgyt (BASHLITE) Botnet Family Overview

Gafgyt - also tracked as BASHLITE, Qbot, Torlus, and LizardStresser - is an IoT DDoS
botnet family that predates Mirai, first appearing in 2014. Early variants exploited the
Shellshock bash vulnerability; the family soon shifted to Telnet credential brute forcing
against embedded Linux devices. Gafgyt's C source code leaked in 2015, making it one of
the most forked IoT malware codebases; it was the engine behind the LizardSquad
"stresser" services.

## Threat assessment

A Gafgyt infection places the device under external command and control for
DDoS-for-hire style attacks. As with Mirai, the device owner is collateral: the risks are
outbound flood traffic, bandwidth exhaustion, degraded device performance, and a foothold
inside the local network. The malware is memory-resident on most devices; a power cycle
clears it, but exposed devices with default credentials are reinfected quickly.

## Propagation and infection

Gafgyt scans for open Telnet services and brute-forces a short list of factory-default
credentials. Compared with Mirai, its scanner is simpler and its credential list smaller,
but the operational pattern is the same: gain a shell, download an
architecture-appropriate payload, connect to a hard-coded C2 (classically over a
plain-text IRC-like protocol), and wait for attack commands.

## Attack repertoire (classes present in this dataset)

- **gafgyt_scan** - scanning for new Telnet-exposed victims.
- **gafgyt_junk** - flood of junk/garbage payload data sent to the target.
- **gafgyt_combo** - combined attack: sends junk payloads while repeatedly opening
  connections to a target IP and port.
- **gafgyt_tcp** - TCP flood against a target.
- **gafgyt_udp** - UDP flood against a target.

## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
