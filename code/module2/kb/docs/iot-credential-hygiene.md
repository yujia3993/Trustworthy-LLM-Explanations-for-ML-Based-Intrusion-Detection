---
doc_id: iot-credential-hygiene
title: "IoT Credential Hygiene: Defeating Default-Password Botnets"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: remediation
source: self_authored
is_distractor: false
---

# IoT Credential Hygiene: Defeating Default-Password Botnets

## Why credentials are the battleground

Mirai and Gafgyt do not exploit sophisticated vulnerabilities to spread - they log in.
Their scanners carry small dictionaries of factory-default username/password pairs
(root/xc3511, admin/admin, support/support and a few dozen more, copied from vendor
manuals into botnet source code). Every device still wearing factory credentials is not
"at risk" - it is pre-compromised, waiting to be found by the next scan sweep, which on
the public internet takes minutes.

## The rules

1. **Change every credential at deployment**, before the device first touches the
   network: web/admin login, Telnet/SSH if present, RTSP/streaming access, and the
   vendor cloud account. A device may carry several independent credentials; botnets
   only need one missed.
2. **Unique per device.** Shared passwords turn one compromise into a fleet compromise -
   and identical devices on one network are exactly the sweep pattern scan-class
   malware follows.
3. **Assume hidden accounts exist.** Many devices ship hard-coded service accounts that
   the admin UI never shows and cannot change. This is why credential hygiene must be
   paired with exposure removal (block Telnet, no WAN-reachable management) - you
   cannot rotate a password the vendor hard-coded.
4. **Rotate after every suspected compromise.** Memory-resident bots are cleared by a
   reboot, but any credential the device held must be treated as harvested.

## After an incident

Credential rotation belongs between the power-cycle and the reconnection - in that
order. Rebooting without rotating invites reinfection within minutes; rotating without
rebooting leaves the current bot process running with its existing C2 session.

## Programme-level practice

Keep a device inventory recording model, firmware version, credential-change date, and
whether the device has unchangeable factory accounts. Devices in that last category
should be flagged for network-level compensating controls and eventual replacement.
