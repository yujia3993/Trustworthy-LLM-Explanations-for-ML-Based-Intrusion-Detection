---
doc_id: smart-tv-security
title: "Smart TV Security Considerations"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: device_profile
source: public_analysis
is_distractor: true
---

# Smart TV Security Considerations

Smart TVs are internet-connected embedded devices, but they are a different category from
the cameras, doorbells, thermostats, and monitors this system classifies, and they are
not represented in the dataset. This note covers their distinct security profile.

## Characteristics and risks

Smart TVs run full application platforms (Android TV, Tizen, webOS, Roku) with app
stores, microphones for voice control, and often cameras on older models. Their traffic
is dominated by high-bandwidth video streaming to content-delivery networks plus
substantial telemetry and advertising traffic - a very different baseline from the
low-rate, few-endpoint profile of sensor-class IoT devices.

## Primary threats

- **Privacy**: automatic content recognition and voice/telemetry collection, plus the
  historical risk of exposed cameras and microphones.
- **Malicious apps**: sideloaded or compromised apps on the TV's platform.
- **Platform vulnerabilities**: unpatched flaws in the TV's OS or media stack.

## Hardening

- Keep the platform and apps updated; disable app sideloading from unknown sources.
- Review privacy settings: disable automatic content recognition and unnecessary
  microphone/camera permissions; cover or disconnect built-in cameras when unused.
- Place the TV on the IoT/entertainment VLAN, isolated from trusted devices.
- Remove apps you do not use; audit their permissions.

## Applicability note

While a smart TV could in principle host malware, its rich-platform threat model
(privacy, malicious apps) differs from the credential-brute-forced, Telnet-exposed
sensor devices that Mirai/Gafgyt-class botnets recruit. Alerts in this system concern
the latter; this document does not correspond to any classifiable attack here.
