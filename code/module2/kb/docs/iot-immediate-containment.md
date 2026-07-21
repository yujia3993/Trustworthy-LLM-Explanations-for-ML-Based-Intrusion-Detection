---
doc_id: iot-immediate-containment
title: "Immediate Containment Playbook for a Compromised IoT Device"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: remediation
source: self_authored
is_distractor: false
---

# Immediate Containment Playbook for a Compromised IoT Device

Use this playbook when a device is flagged as actively emitting botnet traffic (flood or
scan). The goals, in order: stop outbound harm, clear the running malware, and close the
reinfection path before the device returns to the network.

## Step 1 - Isolate now

Disconnect the device from the network: unplug its Ethernet cable, disable its switch
port, block its MAC/IP at the router, or move it to a quarantine VLAN. For flood
traffic this is urgent twice over - the device is attacking a third party **and** may be
saturating your own uplink. Do not wait for further analysis; isolation is cheap and
reversible for every consumer IoT category (check device-specific guidance for the rare
exceptions such as HVAC controllers in extreme weather).

## Step 2 - Power-cycle

Mirai- and Gafgyt-class IoT bots are memory-resident: they run from RAM and do not
survive a reboot. Power the device off and on. This clears the running bot but does
NOT fix the vulnerability - a reachable device with unchanged credentials is typically
reinfected within minutes, so complete steps 3-4 before reconnecting.

## Step 3 - Rotate credentials

Change every credential the device carries: local web/admin login, Telnet/SSH password
if settable, RTSP/streaming credentials, and the vendor cloud account password. Assume
the factory defaults are public knowledge - they are literally embedded in botnet source
code.

## Step 4 - Close the exposure path

Before reconnecting: check the router for port-forwarding rules and UPnP mappings that
expose the device's Telnet (23/2323) or management ports to the internet, and remove
them; apply any pending firmware update; disable Telnet on the device if its interface
allows.

## Step 5 - Sweep the neighbourhood

Scanning-class infections actively probe adjacent LAN addresses. Check other IoT devices
on the same segment - same-model devices especially - for the same indicators, and apply
this playbook to each.

## What NOT to do

Do not merely block the current victim IP (the C2 will retarget), do not rely on the
reboot alone, and do not restore the device to a trusted network segment "temporarily" -
reinfection is faster than your next maintenance window.
