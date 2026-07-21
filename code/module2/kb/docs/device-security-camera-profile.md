---
doc_id: device-security-camera-profile
title: "IP Security Camera: Device Profile and Security Guidance"
attack_family: generic
attack_types: []
device_categories: ["security_camera"]
doc_type: device_profile
source: self_authored
is_distractor: false
---

# IP Security Camera: Device Profile and Security Guidance

## Device characteristics

Consumer/SMB IP security cameras (e.g. Provision-ISR PT-737E/PT-838 and SimpleHome XCS7
class devices) stream continuous or motion-triggered video via RTSP/ONVIF or vendor
cloud relays. Benign traffic is a sustained media stream with characteristic regular
packet sizes, plus NTP, DNS, and telemetry to a small endpoint set. Cameras are the
canonical IoT botnet victim: embedded Linux, BusyBox userland, Telnet or web management
frequently enabled, factory-default credentials widespread, and firmware rarely updated.
The original Mirai botnet was built substantially from IP cameras and DVRs.

## Why cameras get conscripted into botnets

They combine every risk factor: always powered, always online, WAN-exposed for remote
viewing (often via UPnP or manual port forwards), default credentials, and useful uplink
bandwidth for flood attacks. Camera compromise also has a privacy dimension - the
attacker's access includes the video feed.

## Device-specific response actions

- **Immediate**: isolate the camera (unplug, disable its switch port, or quarantine its
  VLAN). Consider whether the physical area loses monitoring coverage and whether that
  is acceptable during response; for most home/SMB deployments it is.
- Power-cycle to clear memory-resident bot code; change web, RTSP/ONVIF, and any
  Telnet/SSH credentials before reconnecting.
- Check for firmware updates; for camera brands without an update channel, plan
  replacement.
- Audit router port-forwarding and UPnP mappings - remote-view exposure is the most
  common infection path.
- Where multiple cameras of the same model share the network, assume all are equally
  exposed: sweep and harden the whole fleet, not just the flagged unit.

## Longer-term hardening

Dedicated camera VLAN with no route to trusted hosts; NVR-mediated or VPN-based remote
viewing instead of direct WAN exposure; outbound Telnet blocked; unique per-device
credentials; scheduled firmware review.
