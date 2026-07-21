---
doc_id: network-segmentation-iot
title: "Network Segmentation for IoT: Reference Design"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: remediation
source: self_authored
is_distractor: false
---

# Network Segmentation for IoT: Reference Design

Segmentation limits what a compromised IoT device can reach and makes its malicious
traffic easier to see and block. This guide gives a minimal reference design for home
and small-business networks.

## Reference layout

- **Trusted segment**: workstations, phones, NAS, printers.
- **IoT segment** (separate VLAN or at minimum a separate SSID with client isolation):
  cameras, doorbells, thermostats, monitors, plugs - everything embedded.
- Optional **guest segment** for visitor devices.

The IoT segment has **no route** to the trusted segment. If an app on a phone must reach
an IoT device directly (local streaming), allow that single flow trusted→IoT, never the
reverse.

## Egress policy for the IoT segment

Benign IoT traffic is almost exclusively outbound HTTPS, DNS, and NTP to vendor clouds.
A practical rule set:

- Allow outbound 443/tcp, 53/udp (to your resolver), 123/udp.
- **Deny outbound 23/tcp and 2323/tcp (Telnet) explicitly and log hits** - benign
  devices never need Telnet outbound, and hits on this rule are a near-certain botnet
  scanning indicator.
- Deny inbound from WAN entirely; no port forwarding into the IoT segment.
- Default-deny everything else, log, and add narrow exceptions only when a device
  demonstrably breaks.

## Why this matters for botnet incidents

Every attack class in this knowledge base is blunted by segmentation: scan-class traffic
cannot reach trusted hosts or (with the Telnet egress block) recruit outside victims;
flood traffic is confined to an segment you can rate-limit or kill without touching
trusted services; and quarantining a flagged device becomes a VLAN move instead of a
physical scramble.

## Operational notes

Client isolation within the IoT SSID also stops lateral infection between IoT devices -
relevant because scan-class malware probes neighbouring addresses first. Label switch
ports/SSIDs so responders can isolate a flagged device in seconds, and test the
quarantine procedure before you need it.
