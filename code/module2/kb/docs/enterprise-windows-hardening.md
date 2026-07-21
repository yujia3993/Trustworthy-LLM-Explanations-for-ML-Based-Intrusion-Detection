---
doc_id: enterprise-windows-hardening
title: "Enterprise Windows Endpoint Hardening"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: remediation
source: public_analysis
is_distractor: true
---

# Enterprise Windows Endpoint Hardening

This guide covers baseline hardening for managed Windows workstations and servers in an
enterprise Active Directory environment. It addresses a completely different asset class
from embedded IoT devices and is not applicable to IoT botnet incident response.

## Identity and access

- Enforce least privilege: remove local administrator rights from standard users and use
  a privileged-access workstation model for admin tasks.
- Deploy the Local Administrator Password Solution (LAPS) so each machine has a unique,
  rotated local admin password.
- Require multi-factor authentication for all interactive and remote logons; disable
  legacy authentication protocols.

## Attack-surface reduction

- Enable Microsoft Defender attack-surface-reduction rules to block common malware
  behaviours (Office macros spawning processes, credential theft from LSASS, etc.).
- Enforce application control (WDAC or AppLocker) to allow only approved executables.
- Disable SMBv1 and unneeded legacy services; apply CIS or DISA STIG baselines via Group
  Policy.

## Detection and response

- Forward endpoint and Sysmon logs to a SIEM; deploy EDR with behavioural detection.
- Segment administrative tiers to contain credential-theft lateral movement.
- Maintain a tested patch-management cadence through WSUS or a modern update service.

## Applicability note

These controls assume a general-purpose OS with a management agent, domain membership,
and an update infrastructure - none of which exist on embedded IoT cameras, doorbells,
thermostats, or webcams. For IoT botnet incidents, consult the IoT-specific containment
and hardening guidance instead.
