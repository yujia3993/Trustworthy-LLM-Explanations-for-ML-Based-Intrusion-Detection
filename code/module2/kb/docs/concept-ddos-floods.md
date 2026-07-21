---
doc_id: concept-ddos-floods
title: "DDoS Flood Attacks: TCP and UDP Mechanics"
attack_family: generic
attack_types: ["gafgyt_tcp", "gafgyt_udp", "mirai_ack", "mirai_syn", "mirai_udp", "mirai_udpplain"]
device_categories: ["generic"]
doc_type: concept
source: self_authored
is_distractor: false
---

# DDoS Flood Attacks: TCP and UDP Mechanics

A flood attack denies service by exhausting a finite resource - link bandwidth,
connection state, or processing capacity. Which resource depends on the packet type, and
this determines both the attack's statistical signature and the defender's options.

## UDP floods: volumetric

UDP is connectionless: the sender can transmit at line rate with no handshake or flow
control. UDP floods therefore target **bandwidth** - the victim's inbound link fills, and
legitimate traffic is crowded out regardless of what the victim's software does.
Secondary damage comes from the victim generating ICMP port-unreachable replies.
Statistically, UDP floods are the loudest class: maximum packet rate, template-built
packets with near-zero size variance, machine-regular timing.

## TCP SYN floods: state exhaustion at the edge

A SYN flood sends connection-request segments and never completes the handshake. Each
SYN occupies a half-open slot in the victim's backlog until timeout. The resource
attacked is **connection state**, so even modest bandwidth can take down an unprotected
service. Signature: minimal, payload-free packets (size distribution collapses to the
header minimum), high rate, no corresponding data transfer.

## TCP ACK floods: state lookups and filter evasion

ACK floods send mid-connection-looking segments that belong to no session. Stateful
devices must look up each one before discarding, burning CPU and state-table capacity.
Because they mimic established-session traffic, ACK floods pass filters designed only to
police connection-opening. Signature: high-rate, template-sized TCP packets - similar
regularity to SYN floods, distinguished by flags and slightly different size profile.

## Connection-oriented floods

Some attacks (e.g. Gafgyt's combo) complete real handshakes and push junk data through
established connections, attacking accept queues and application workers. These show
**bidirectional** traffic and mixed packet sizes - statistically distinct from the
one-way template floods above.

## The common statistical core

All flood classes share three traits against a benign IoT baseline: sustained packet
rates orders of magnitude above normal, abnormally tight (or in junk-payload cases,
abnormally shaped) packet-size distributions, and machine-regular inter-arrival times.
These are precisely the aggregate statistics that flow-level detectors key on.
