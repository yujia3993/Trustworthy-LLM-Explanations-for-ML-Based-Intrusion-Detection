---
doc_id: device-doorbell-profile
title: "Smart Doorbell: Device Profile and Security Guidance"
attack_family: generic
attack_types: []
device_categories: ["doorbell"]
doc_type: device_profile
source: self_authored
is_distractor: false
---

# Smart Doorbell: Device Profile and Security Guidance

## Device characteristics

Smart video doorbells (e.g. Danmini and Ennio class devices) combine a camera,
microphone, speaker, and a push-event radio or Wi-Fi link. Benign traffic is
event-driven and bursty: near-idle keepalive telemetry punctuated by video/audio
streaming bursts when the button is pressed or motion is detected. They typically speak
to a small, fixed set of vendor cloud endpoints, and many expose a local RTSP stream or
a web management interface. Budget models commonly ship with Telnet or web logins using
factory-default credentials - the exact attack surface Mirai- and Gafgyt-class botnets
brute-force.

## Why doorbells get conscripted into botnets

They are always powered, always online, rarely monitored, and almost never updated.
Users interact through a phone app and have no visibility into the device's network
behaviour, so an infection changes nothing the owner can see - the doorbell keeps
ringing normally while flooding a third party.

## Device-specific response actions

- **Immediate**: disconnect the doorbell from Wi-Fi or isolate its switch port / VLAN.
  Doorbells lose only convenience when offline - there is no safety impact, so
  aggressive isolation is low-cost.
- Power-cycle to clear memory-resident bot code, then change the web/app password and
  any Telnet/admin credential before allowing it back online.
- Check the vendor app for firmware updates; budget doorbell firmware is rarely
  auto-updated.
- Verify port-forwarding rules on the home router: doorbells are frequently exposed via
  UPnP mappings the owner never created deliberately.

## Longer-term hardening

Place the doorbell on an IoT-only network segment with no route to workstations or NAS
devices; block outbound Telnet (23/2323) from that segment; and disable UPnP on the
router. If the device cannot function without an exposed management port and receives no
vendor updates, treat it as end-of-life and replace it.
