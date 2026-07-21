---
doc_id: concept-scanning-recon
title: "Network Scanning and Botnet Propagation Concepts"
attack_family: generic
attack_types: ["gafgyt_scan", "mirai_scan"]
device_categories: ["generic"]
doc_type: concept
source: self_authored
is_distractor: false
---

# Network Scanning and Botnet Propagation Concepts

## What scanning is

Scanning is the discovery phase of automated compromise: probing many addresses to find
hosts running a service the attacker can enter. For IoT botnets the target service is
overwhelmingly Telnet (TCP 23/2323), because embedded devices expose it with
factory-default credentials. A bot's scanner is its growth engine - every infected
device recruits, so the botnet compounds.

## How IoT botnet scanners work

The loop is: generate a pseudo-random IPv4 address, send a TCP SYN to the Telnet port,
and on response attempt logins from a built-in credential dictionary. Successful logins
are reported to the operator's loader infrastructure, which delivers an
architecture-matched binary to the new victim. Scanners run continuously in the
background, including while the bot idles between attack commands - which is why
scan-class traffic, once started, persists indefinitely.

## Scanning versus flooding: the statistical contrast

Flood traffic is high-volume toward one destination. Scan traffic inverts this: **modest
volume fanned out across a very large number of destinations**, with small,
header-dominated packets (probes and brief login exchanges). Against a benign IoT
baseline - a handful of fixed vendor endpoints - the many-destinations pattern is the
defining anomaly, even though total bandwidth may look unremarkable. Rate is elevated
but sustained, lacking the burst-and-idle rhythm of event-driven device traffic.

## Why detecting scanning matters more than its bandwidth suggests

A scanning device is a confirmed compromise doing active harm: it recruits new victims
on the internet, and it probes its own LAN first-hop neighbourhood, so adjacent devices -
especially identical models - are at immediate risk. Scan detection is also the earliest
practical catch point: infection is typically detected either here or not until the
device joins a flood.

## Defensive leverage

Two controls neutralise most of this phase: blocking outbound Telnet at the network edge
(benign devices never need it; rule hits double as a high-precision infection alarm),
and eliminating default credentials so inbound scans that do arrive find no way in.
