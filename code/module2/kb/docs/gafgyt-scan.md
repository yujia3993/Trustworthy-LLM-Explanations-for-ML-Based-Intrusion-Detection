---
doc_id: gafgyt-scan
title: "Gafgyt Telnet Scanning / Propagation"
attack_family: gafgyt
attack_types: ["gafgyt_scan"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Gafgyt Telnet Scanning / Propagation

## Threat assessment

The infected device is scanning for new victims on behalf of a Gafgyt (BASHLITE)
botnet. This is propagation, not attack traffic: modest bandwidth, but the device is
confirmed compromised and actively recruiting new bots - including, potentially,
neighbouring devices on the same LAN.

## Mechanism

Gafgyt's scanner probes IPv4 addresses for open Telnet services and attempts logins from
a short list of factory-default credentials (the classic root/root, admin/admin class of
pairs). Successful shells receive a download command that fetches an
architecture-matched bot binary. Compared with Mirai's scanner, Gafgyt's is simpler -
fewer credentials, less randomisation - but operationally identical, and it runs
continuously while the bot idles between attack commands.

## Observable indicators

- Outbound connection attempts spread across many distinct destination addresses - a
  fan-out pattern opposite to the benign profile of an IoT device, which contacts a few
  fixed cloud endpoints.
- Small, header-dominated packets (probes and brief Telnet exchanges), keeping mean
  outbound packet size low relative to streaming or flood traffic.
- Moderate, indefinitely sustained packet rate - elevated above baseline but far below
  flood classes.
- Possible probing of neighbouring LAN address space on Telnet ports.

## Response priorities

Treat as an active compromise. Isolate the device, sweep sibling devices on the same
network segment for infection, power-cycle, rotate credentials, and eliminate Telnet
exposure. See the immediate containment guide and network segmentation guidance.
