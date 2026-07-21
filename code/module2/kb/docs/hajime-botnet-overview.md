---
doc_id: hajime-botnet-overview
title: "Hajime IoT Botnet Overview"
attack_family: other_botnet
attack_types: []
device_categories: ["generic"]
doc_type: threat_intel
source: public_analysis
is_distractor: true
---

# Hajime IoT Botnet Overview

Hajime is a peer-to-peer IoT botnet first identified in October 2016, shortly after
Mirai. It targets the same class of devices - internet-exposed embedded Linux systems
with default Telnet credentials - and spreads through the same brute-force mechanism, but
its architecture and apparent intent differ markedly.

## Distinguishing characteristics

Unlike Mirai's centralised command-and-control, Hajime uses a decentralised peer-to-peer
network built on the BitTorrent DHT protocol for coordination and uTP for transport, with
messages encrypted and signed. There is no hard-coded C2 server to seize, which makes the
botnet resilient to takedown. Hajime is also modular, fetching architecture-specific
payloads after initial infection.

## The "vigilante" behaviour

Hajime is notable for never having been observed launching a DDoS attack. Instead it
displays behaviour some researchers describe as vigilante: it blocks access to ports
commonly abused by Mirai (23, 7547, 5555, 5358) and periodically displays a signed
message from its author claiming to secure devices. Whether benign or simply
opportunistic infrastructure-building, its presence still represents an unauthorised
compromise, and the blocked ports revert the moment the memory-resident code is cleared
by a reboot.

## Relevance to defenders

Hajime demonstrates that default-credential Telnet exposure invites many actors, not just
Mirai and Gafgyt. The defensive posture is identical - eliminate default credentials,
remove Telnet exposure, segment IoT devices - regardless of an individual botnet's
stated intent. A device secure against Mirai is secure against Hajime by the same
measures.
