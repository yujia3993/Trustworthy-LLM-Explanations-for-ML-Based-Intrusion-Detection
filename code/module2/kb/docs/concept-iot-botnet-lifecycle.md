---
doc_id: concept-iot-botnet-lifecycle
title: "The IoT Botnet Lifecycle: Infection to Attack"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: concept
source: self_authored
is_distractor: false
---

# The IoT Botnet Lifecycle: Infection to Attack

Understanding where an observed behaviour sits in the botnet lifecycle tells an analyst
what has already happened and what comes next.

## Stage 1 - Discovery and intrusion

A scanning bot elsewhere on the internet finds the device's exposed Telnet or management
service and logs in with factory-default credentials. This takes minutes of exposure,
not days: the entire IPv4 space is swept continuously by competing botnets.

## Stage 2 - Loading

The successful login is reported to the operator's infrastructure. A loader connects,
identifies the device's CPU architecture (ARM, MIPS, x86 variants), and delivers a
matching bot binary, which typically runs from memory only.

## Stage 3 - Residence and C2

The bot connects to its command-and-control server and idles awaiting instructions. Many
strains kill competing malware and bind the ports they entered through - burglars
locking the door behind them. The device functions normally from the owner's
perspective; the only external sign is its network behaviour.

## Stage 4 - Propagation

The bot scans for new victims (see the scanning concepts guide). This runs continuously
and is often the first detectable stage: sustained connection attempts to many
destinations, unlike anything in a benign IoT profile.

## Stage 5 - Attack

On command, the bot emits flood traffic - the UDP/TCP/SYN/ACK and junk/combo classes
documented in this knowledge base - at an operator-chosen victim for an operator-chosen
duration, then returns to idle-and-scan.

## Lifecycle implications for response

- Observing **scan** traffic means stages 1-3 are complete: the device is compromised
  and under C2, not merely "probing".
- Observing **flood** traffic means the full chain is operating; expect scan-class
  behaviour to resume when the attack command ends.
- Memory residence (stage 3) is why a power-cycle clears the bot, and stage 1's
  mechanics are why it returns unless credentials and exposure change first.
- Between commands the device may look entirely quiet - absence of attack traffic
  after an incident is not evidence of disinfection.
