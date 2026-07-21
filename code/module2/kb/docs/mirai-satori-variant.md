---
doc_id: mirai-satori-variant
title: "Satori: A Mirai Variant Exploiting Router Vulnerabilities"
attack_family: mirai
attack_types: []
device_categories: ["generic"]
doc_type: threat_intel
source: public_analysis
is_distractor: true
---

# Satori: A Mirai Variant Exploiting Router Vulnerabilities

Satori (also called Okiru) is a Mirai-derived botnet that appeared in late 2017. It
inherits Mirai's leaked codebase but replaces the pure default-credential Telnet scanner
with remote-code-execution exploits, a shift that let it spread faster and to devices
that had changed their Telnet passwords.

## Exploit-driven propagation

Where classic Mirai only brute-forces credentials, Satori weaponised specific
vulnerabilities - notably a Huawei HG532 router flaw (CVE-2017-17215) and a Realtek SDK
UPnP SOAP flaw (CVE-2014-8361) - to achieve code execution without any login. Later
variants targeted specific cryptocurrency-mining rigs and additional router models. This
made Satori an early prominent example of Mirai forks moving beyond credential guessing
into exploit-based worming.

## Capabilities and impact

Satori retained Mirai's DDoS repertoire and reached hundreds of thousands of infected
devices within days of notable campaigns. Its rapid rise underscored how the public
Mirai source code lowered the barrier for building capable botnets: an attacker needed
only to bolt new exploits onto proven bot machinery.

## Relevance to defenders

Satori illustrates that credential rotation alone does not immunise a device whose
firmware carries an exploitable RCE bug. For the specific router models it targeted,
firmware patching was essential. The general IoT controls - remove WAN exposure of
management and UPnP services, segment devices, retire unpatchable hardware - blunt
exploit-driven variants as well as credential-driven ones.
