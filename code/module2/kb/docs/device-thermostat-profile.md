---
doc_id: device-thermostat-profile
title: "Smart Thermostat: Device Profile and Security Guidance"
attack_family: generic
attack_types: []
device_categories: ["thermostat"]
doc_type: device_profile
source: self_authored
is_distractor: false
---

# Smart Thermostat: Device Profile and Security Guidance

## Device characteristics

Smart thermostats (e.g. Ecobee class devices) are low-bandwidth telemetry devices: they
report temperature/occupancy readings and fetch schedules and weather data from vendor
cloud endpoints at regular intervals. Benign traffic is small, periodic, and highly
predictable - a few kilobytes at a time to a handful of fixed destinations. There is no
media streaming. This makes flood or scan traffic from a thermostat exceptionally
anomalous: virtually any sustained high packet rate is orders of magnitude outside its
normal envelope.

## Why thermostats get conscripted into botnets

Like other embedded Linux devices, they are continuously powered and online, and older
or off-brand units may expose management services with weak credentials. Their
compromise value to a botnet is the network position and uplink, not the device's
function.

## Device-specific response actions

- **Immediate**: isolate the thermostat from the network. **Caution**: unlike a
  doorbell, a thermostat controls HVAC - most units continue their last programmed
  schedule offline, but in extreme-weather conditions confirm heating/cooling continues
  locally before leaving it disconnected for long periods.
- Power-cycle the unit, then rotate the associated account password and any local
  admin credential before reconnecting.
- Apply pending firmware updates through the vendor app; mainstream thermostat vendors
  do ship security updates, unlike much of the IoT space.
- Review the home router for unexpected port-forwarding entries pointing at the
  thermostat.

## Longer-term hardening

Keep the thermostat on an IoT-only VLAN with cloud-only egress (its legitimate traffic
needs nothing else); block outbound Telnet from that segment; prefer vendors with a
demonstrated update track record for any replacement.
