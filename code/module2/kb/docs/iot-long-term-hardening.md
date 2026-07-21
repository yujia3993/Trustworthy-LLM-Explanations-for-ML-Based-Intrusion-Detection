---
doc_id: iot-long-term-hardening
title: "Long-Term Hardening Programme for IoT Deployments"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: remediation
source: self_authored
is_distractor: false
---

# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## 2. Remove internet exposure

No IoT management interface (Telnet, SSH, HTTP admin, RTSP) should be directly reachable
from the WAN. Disable UPnP on the router - devices silently punching their own holes is
how most "I never exposed it" compromises happen. Where remote access is genuinely
needed, use the vendor's cloud relay or a VPN into the local network instead of port
forwarding.

## 3. Segment the network

Place IoT devices on a dedicated VLAN/SSID with no route to workstations, phones, or
storage. Allow the segment outbound HTTPS/DNS/NTP to vendor clouds and block everything
else - especially outbound Telnet (23/2323), which benign IoT devices never need and
which is both the botnet's propagation channel and a common C2 giveaway. See the
network segmentation guide for a reference layout.

## 4. Patch on a schedule - and retire the unpatchable

Check for firmware updates on a recurring calendar (quarterly is realistic), not only
after incidents. Track each model's vendor support status: a camera or doorbell whose
vendor no longer ships security fixes cannot be secured by configuration and should be
scheduled for replacement.

## 5. Watch for behavioural anomalies

IoT devices have narrow, predictable traffic profiles (fixed endpoints, low or regular
volumes), which makes anomaly detection unusually effective. Even router-level
monitoring - unexpected destinations, sustained high outbound rates, Telnet attempts -
catches the loud attack classes documented in this knowledge base.

## Prioritisation note

If only one measure can be implemented, choose credential hygiene (1); if two, add
exposure removal (2). Segmentation (3) is what limits blast radius when the first two
eventually fail.
