---
doc_id: home-router-hardening
title: "Home Router Hardening Guide"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: remediation
source: public_analysis
is_distractor: true
---

# Home Router Hardening Guide

The home router is the gateway for every device on the network, including IoT endpoints.
Hardening it is worthwhile, but the router is a distinct asset class from the cameras,
doorbells, thermostats, and monitors this system classifies - a router is not among the
device categories in this dataset, and securing the router does not disinfect a
compromised endpoint behind it.

## Core measures

- Change the default administrator password and, if offered, the default admin username.
- Update firmware; enable automatic updates if the vendor supports them. Retire routers
  that no longer receive security updates.
- Disable remote (WAN-side) administration entirely.
- Disable UPnP unless a specific application requires it - UPnP lets internal devices
  open inbound ports automatically, a frequent path to IoT exposure.
- Disable WPS; use WPA3 (or WPA2-AES at minimum) with a strong passphrase.

## Network configuration

- Create a separate SSID/VLAN for IoT devices and enable client isolation.
- Use a reputable DNS resolver; consider DNS filtering of known-malicious domains.
- Turn off unused services (Telnet, legacy remote-management protocols).

## Monitoring

- Review the router's connected-device list periodically for unexpected clients.
- Where supported, enable logging of blocked outbound connection attempts.

## Applicability note

Router hardening reduces exposure and can enforce the segmentation and Telnet-egress
controls that contain IoT botnets, but it is a preventive/infrastructure measure. When an
endpoint device is already flagged as emitting botnet traffic, the endpoint itself must
be contained and cleared per the IoT-specific playbooks; hardening the router does not
remove malware from the camera or doorbell.
