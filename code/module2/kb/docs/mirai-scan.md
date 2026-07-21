---
doc_id: mirai-scan
title: "Mirai Telnet Scanning / Propagation"
attack_family: mirai
attack_types: ["mirai_scan"]
device_categories: ["generic"]
doc_type: attack_mechanism
source: self_authored
is_distractor: false
---

# Mirai Telnet Scanning / Propagation

## Threat assessment

The infected device is scanning for new victims on behalf of the Mirai botnet. Unlike a
flood attack, scanning is the botnet's growth phase: every reachable device with default
Telnet credentials that this device finds may become a new bot. Severity is high even
though bandwidth use is modest, because the device is confirmed compromised and is
actively expanding the botnet - potentially into the local network.

## Mechanism

Mirai's scanner emits TCP SYN probes to pseudo-random IPv4 addresses on ports 23 and 2323
(with a hard-coded blocklist for some ranges). When a probe answers, the bot attempts a
Telnet login using a dictionary of roughly 60 factory-default credential pairs. Working
credentials are forwarded to a report server; a separate loader then infects the new
victim. Scanning runs continuously in the background while the bot awaits attack
commands.

## Observable indicators

- Outbound connection attempts fanned out across a very large number of distinct
  destination addresses - the opposite of a benign IoT device, which talks to a handful
  of fixed cloud endpoints.
- Small, header-dominated packets (SYN probes and short Telnet exchanges), keeping mean
  outbound packet size low.
- Elevated but not extreme packet rate, sustained indefinitely rather than in
  attack-length bursts.
- Possible internal-network probing: connection attempts toward neighbouring LAN
  addresses on ports 23/2323.

## Response priorities

Treat as an active compromise, not merely suspicious traffic. Isolate the device, check
sibling devices on the same LAN for infection (scanning frequently hits neighbours),
power-cycle, rotate credentials, and disable Telnet exposure. See the immediate
containment guide.
