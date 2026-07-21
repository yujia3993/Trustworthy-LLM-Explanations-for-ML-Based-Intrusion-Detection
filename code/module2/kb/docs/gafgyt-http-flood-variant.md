---
doc_id: gafgyt-http-flood-variant
title: "Gafgyt HTTP Layer-7 Flood Variant"
attack_family: gafgyt
attack_types: []
device_categories: ["generic"]
doc_type: threat_intel
source: public_analysis
is_distractor: true
---

# Gafgyt HTTP Layer-7 Flood Variant

Some later Gafgyt (BASHLITE) forks added an application-layer HTTP flood capability
alongside the classic transport-layer TCP/UDP floods. This variant targets web
applications rather than raw bandwidth or connection tables, and it is distinct from the
tcp/udp/junk/combo/scan classes captured in the N-BaIoT dataset.

## Mechanism

An HTTP flood issues large volumes of syntactically valid HTTP requests - GET or POST -
against a target web server, often cycling through URL paths and rotating User-Agent
strings to blend in with legitimate traffic. Because each request is well-formed and
completes a TCP handshake and TLS negotiation, the attack consumes expensive
server-side resources: application worker threads, database queries, and backend API
calls. A relatively modest request rate can exhaust a dynamic web application that
serves each request with heavy computation.

## Why Layer-7 floods are harder to filter

Unlike volumetric floods, HTTP floods cannot be dropped purely on rate or packet-shape
heuristics without risking legitimate users, because individual requests look normal.
Mitigation typically requires application-aware defences: request fingerprinting,
challenge-response (CAPTCHA/JS challenges), rate limiting per client behaviour, and
web application firewalls tuned to the protected app.

## Relevance and scope note

This HTTP-flood capability is a genuine feature of some Gafgyt forks but is **not among
the attack classes in the N-BaIoT dataset**, whose Gafgyt labels cover only combo, junk,
scan, tcp, and udp. It is documented here for family completeness; alerts in this system
will not be labelled as an HTTP flood.
