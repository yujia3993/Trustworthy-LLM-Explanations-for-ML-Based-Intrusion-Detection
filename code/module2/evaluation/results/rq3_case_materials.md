# RQ3 Case Grounding Materials

This is the grounding material the judge received for the selected RQ3 cases. It is provided so the human rater can apply the `supported` entailment criterion. It contains no judge answers.

## assertive_correct-125012

### ALERT DATA
ALERT DATA
- Device: Ennio_Doorbell
- Device category: doorbell
- Predicted class: gafgyt_scan (Gafgyt scan)
- p_top1: 1.0000
- Second class: benign (benign traffic)
- p_top2: 0.0000
- p_pair: 0.0000
- Margin: 1.0000
- Entropy: 0.0000

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) MI_dir_L0.01_mean = 76.47 - approximately at the device's benign median (82.2); within the benign 99th percentile (106.5). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) HH_L0.1_mean = 74 - approximately at the device's benign median (83.72); within the benign 99th percentile (202.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) HH_jit_L1_variance = 4.254e+15 - 559792941880069293342720.0x above the device's benign median (7.6e-09); within the benign 99th percentile (1.471e+16). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) HH_L0.1_magnitude = 74 - 0.7x below the device's benign median (106.9); within the benign 99th percentile (223). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (DISCRIMINATIVE) MI_dir_L0.1_weight = 1206 - 363.3x above the device's benign median (3.32); above the benign 99th percentile (12.5).

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt Combo Attack (Junk Payloads + Connection Opening)
# Gafgyt Combo Attack (Junk Payloads + Connection Opening)

## Threat assessment

The infected device is running Gafgyt's "combo" attack: it repeatedly opens TCP
connections to a victim IP and port while pushing junk payload data through them.
Severity is high - the device is under botnet control and attacking a third party with a
technique aimed at application/connection-handling resources rather than raw bandwidth.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Gafgyt Telnet Scanning / Propagation
# Gafgyt Telnet Scanning / Propagation

## Threat assessment

The infected device is scanning for new victims on behalf of a Gafgyt (BASHLITE)
botnet. This is propagation, not attack traffic: modest bandwidth, but the device is
confirmed compromised and actively recruiting new bots - including, potentially,
neighbouring devices on the same LAN.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt (BASHLITE) Botnet Family Overview
## Attack repertoire (classes present in this dataset)

- **gafgyt_scan** - scanning for new Telnet-exposed victims.
- **gafgyt_junk** - flood of junk/garbage payload data sent to the target.
- **gafgyt_combo** - combined attack: sends junk payloads while repeatedly opening
  connections to a target IP and port.
- **gafgyt_tcp** - TCP flood against a target.
- **gafgyt_udp** - UDP flood against a target.

### Observable Indicators
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C8] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C9] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C10] Smart Doorbell: Device Profile and Security Guidance
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
[C11] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## assertive_correct-145003

### ALERT DATA
ALERT DATA
- Device: Philips_B120N10_Baby_Monitor
- Device category: baby_monitor
- Predicted class: mirai_ack (Mirai ACK flood)
- p_top1: 1.0000
- Second class: benign (benign traffic)
- p_top2: 0.0000
- p_pair: 0.0000
- Margin: 1.0000
- Entropy: 0.0000

### EVIDENCE
EVIDENCE
[E1] (DISCRIMINATIVE) MI_dir_L0.01_mean = 390.8 - 5.5x above the device's benign median (71.11); above the benign 99th percentile (277.5).
[E2] (DISCRIMINATIVE) MI_dir_L5_weight = 166.1 - 120.3x above the device's benign median (1.381); above the benign 99th percentile (10.33).
[E3] (CONTEXTUAL) MI_dir_L3_variance = 6.165e+04 - 2894634.1x above the device's benign median (0.0213); within the benign 99th percentile (7.918e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) H_L0.01_variance = 5.795e+04 - 147.2x above the device's benign median (393.7); within the benign 99th percentile (1.84e+05). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) HpHp_L0.01_mean = 60 - approximately at the device's benign median (66.86); within the benign 99th percentile (170.5). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.
[C2] Mirai Telnet Scanning / Propagation
## Threat assessment

The infected device is scanning for new victims on behalf of the Mirai botnet. Unlike a
flood attack, scanning is the botnet's growth phase: every reachable device with default
Telnet credentials that this device finds may become a new bot. Severity is high even
though bandwidth use is modest, because the device is confirmed compromised and is
actively expanding the botnet - potentially into the local network.
[C3] Mirai UDP-Plain Flood Attack (High-PPS Variant)
# Mirai UDP-Plain Flood Attack (High-PPS Variant)

## Threat assessment

The infected device is running Mirai's optimised UDP flood. Severity is high and
equivalent to the generic UDP flood: the device is attacking a third party under botnet
control, at the maximum packet rate its hardware can produce.

### Attack Mechanism
[C4] Mirai Botnet Family Overview
## Attack repertoire (classes present in this dataset)

- **mirai_scan** - Telnet scanning/propagation traffic seeking new victims.
- **mirai_syn** - TCP SYN flood: connection-request exhaustion against a target.
- **mirai_ack** - TCP ACK flood: state-table exhaustion, also used to bypass naive SYN filters.
- **mirai_udp** - generic UDP flood with configurable payloads.
- **mirai_udpplain** - UDP flood with a stripped-down packet-building loop and fewer
  options, optimised for maximum packets-per-second.

## Analyst notes

Mirai attack traffic is machine-generated and highly regular: fixed or narrowly
distributed packet sizes, extreme packet rates, and near-constant inter-arrival times
that differ sharply from the bursty, low-volume traffic profile of a benign IoT device.
[C5] Mirai ACK Flood Attack
## Mechanism

An ACK flood sends TCP segments with the ACK flag set that belong to no established
connection. The victim (or an intermediate stateful firewall/load balancer) must look up
each segment in its connection table before discarding it, exhausting CPU and state-table
capacity. Because ACK segments look like the middle of legitimate sessions, they pass
filters that only guard against connection-opening (SYN) traffic. Mirai's ACK flood
builds packets in a tight loop with randomised source ports and sequence numbers and a
configurable payload size.
[C6] Mirai UDP Flood Attack
## Mechanism

A UDP flood overwhelms a target with connectionless datagrams. Because UDP requires no
handshake, the bot can transmit at line rate immediately; the damage is volumetric
(bandwidth exhaustion) and, secondarily, CPU load on the victim generating ICMP
port-unreachable responses. Mirai's generic UDP attack supports configurable payload
sizes, destination ports, and header options, letting operators tune packet size against
packet rate for the chosen target.

### Observable Indicators
[C7] Mirai UDP-Plain Flood Attack (High-PPS Variant)
## Observable indicators

- The most extreme outbound packet rates of any Mirai attack class on the same
  hardware - the defining signature of this variant.
- An essentially degenerate packet-size distribution: every packet is built from the
  same template, so outbound size variance collapses to near zero.
- Extremely regular inter-arrival times, tighter than the generic UDP flood because no
  per-packet option handling perturbs the send loop.
- Single fixed destination address and port for the duration of the attack command.

## Response priorities

Identical to the generic UDP flood: isolate immediately (the uplink is likely
saturated), power-cycle to clear the memory-resident bot, rotate credentials, and remove
Telnet exposure before reconnecting. See the immediate containment guide.

## Analyst note on classification

udpplain and udp differ in implementation efficiency, not in protocol semantics. The
statistical distinction visible to a traffic-feature classifier is the packet-rate and
timing profile, which is why the two remain separable classes in this dataset.
[C8] Gafgyt Combo Attack (Junk Payloads + Connection Opening)
## Observable indicators

- Elevated outbound packet rate - high, but typically below the raw flood classes,
  because handshake round-trips throttle the loop.
- A **mixed** outbound packet-size distribution: handshake-sized control segments
  interleaved with junk-payload data segments, giving higher size variance than
  template floods (which are near-degenerate).
- Bidirectional traffic with the victim: unlike stateless floods, combo completes
  handshakes, so inbound ACK traffic from the target accompanies the outbound stream.
- Repeated short-lived connections to a single destination address and port.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. See the immediate containment and long-term hardening
guides.

### Immediate Actions
[C9] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

### Longer Term Remediation
[C10] Networked Baby Monitor: Device Profile and Security Guidance
## Device-specific response actions

- **Immediate**: disconnect the monitor from the network. Fall back to local/direct
  monitoring if the household needs it; do not leave a compromised camera-microphone
  device online while investigating.
- Power-cycle, change every credential associated with the device (local admin, RTSP,
  vendor cloud account), and check for firmware updates before reconnecting.
- Inspect router port-forwarding/UPnP entries: internet-reachable baby monitors are a
  common misconfiguration and the main path to compromise.
- Given the privacy stakes, if the model has known unpatched vulnerabilities or no
  vendor updates, replace it rather than re-deploy.

## Longer-term hardening

IoT-only network segment, cloud-only egress, outbound Telnet blocked, UPnP disabled.
Prefer monitors that support authenticated, encrypted streaming and have an active
vendor update channel.

## assertive_correct-175000

### ALERT DATA
ALERT DATA
- Device: Philips_B120N10_Baby_Monitor
- Device category: baby_monitor
- Predicted class: gafgyt_junk (Gafgyt junk attack)
- p_top1: 1.0000
- Second class: benign (benign traffic)
- p_top2: 0.0000
- p_pair: 0.0000
- Margin: 1.0000
- Entropy: 0.0000

### EVIDENCE
EVIDENCE
[E1] (DISCRIMINATIVE) HH_L5_weight = 166.9 - 162.7x above the device's benign median (1.026); above the benign 99th percentile (9.486).
[E2] (DISCRIMINATIVE) MI_dir_L1_weight = 838.6 - 406.1x above the device's benign median (2.065); above the benign 99th percentile (22.83).
[E3] (CONTEXTUAL) HH_jit_L1_variance = 3.78e+13 - 20360829724458.4x above the device's benign median (1.856); within the benign 99th percentile (6.392e+13). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) HH_L0.1_magnitude = 95.26 - approximately at the device's benign median (117.6); within the benign 99th percentile (765.6). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_mean = 74.15 - approximately at the device's benign median (71.11); within the benign 99th percentile (277.5). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt Combo Attack (Junk Payloads + Connection Opening)
# Gafgyt Combo Attack (Junk Payloads + Connection Opening)

## Threat assessment

The infected device is running Gafgyt's "combo" attack: it repeatedly opens TCP
connections to a victim IP and port while pushing junk payload data through them.
Severity is high - the device is under botnet control and attacking a third party with a
technique aimed at application/connection-handling resources rather than raw bandwidth.
[C2] Gafgyt Junk Attack (Random Payload Flood)
# Gafgyt Junk Attack (Random Payload Flood)

## Threat assessment

The infected device is sending streams of random "junk" payload data at a victim as part
of a Gafgyt (BASHLITE) DDoS attack. Severity is high: the device is under external
command and control and consuming its uplink to attack a third party.
[C3] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.

### Attack Mechanism
[C4] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C5] Gafgyt Junk Attack (Random Payload Flood)
## Mechanism

The junk attack writes randomly generated byte sequences to the target. Its purpose is
twofold: volumetric load, and evasion - because payload contents are random rather than
a fixed template, simple signature- or content-based filters cannot match a repeating
pattern. Each transmission carries a randomly sized and randomly filled buffer, which
distinguishes junk statistically from Gafgyt's template-built tcp/udp floods.

### Observable Indicators
[C6] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.

### Immediate Actions
[C8] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
[C9] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C10] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Longer Term Remediation
[C11] Networked Baby Monitor: Device Profile and Security Guidance
## Device-specific response actions

- **Immediate**: disconnect the monitor from the network. Fall back to local/direct
  monitoring if the household needs it; do not leave a compromised camera-microphone
  device online while investigating.
- Power-cycle, change every credential associated with the device (local admin, RTSP,
  vendor cloud account), and check for firmware updates before reconnecting.
- Inspect router port-forwarding/UPnP entries: internet-reachable baby monitors are a
  common misconfiguration and the main path to compromise.
- Given the privacy stakes, if the model has known unpatched vulnerabilities or no
  vendor updates, replace it rather than re-deploy.

## Longer-term hardening

IoT-only network segment, cloud-only egress, outbound Telnet blocked, UPnP disabled.
Prefer monitors that support authenticated, encrypted streaming and have an active
vendor update channel.

### Confidence Notes
[C12] Pair-Level Assertion: How Reports Handle the Ambiguous Gafgyt Flood Pair
# Pair-Level Assertion: How Reports Handle the Ambiguous Gafgyt Flood Pair

## The rule

When the detector's evidence stops at the pair boundary, the report's language must stop
there too. For gafgyt_tcp/gafgyt_udp alerts, reports assert the **pair superclass** -
"a Gafgyt tcp-or-udp flood" - quantified by the pair probability
**p_pair = p(gafgyt_tcp) + p(gafgyt_udp)**, and explicitly decline to pick a member.

## assertive_correct-275000

### ALERT DATA
ALERT DATA
- Device: Provision_PT_838_Security_Camera
- Device category: security_camera
- Predicted class: mirai_udpplain (Mirai UDP plain flood)
- p_top1: 1.0000
- Second class: benign (benign traffic)
- p_top2: 0.0000
- p_pair: 0.0000
- Margin: 1.0000
- Entropy: 0.0000

### EVIDENCE
EVIDENCE
[E1] (DISCRIMINATIVE) H_L0.01_variance = 6.096e+04 - 3.5x above the device's benign median (1.766e+04); above the benign 99th percentile (4.95e+04).
[E2] (DISCRIMINATIVE) HpHp_L0.1_weight = 1562 - 807.9x above the device's benign median (1.933); above the benign 99th percentile (14.87).
[E3] (DISCRIMINATIVE) MI_dir_L0.01_mean = 302.5 - 2.9x above the device's benign median (103.7); above the benign 99th percentile (159.2).
[E4] (DISCRIMINATIVE) MI_dir_L0.01_variance = 6.096e+04 - 3.5x above the device's benign median (1.766e+04); above the benign 99th percentile (4.95e+04).
[E5] (DISCRIMINATIVE) MI_dir_L5_weight = 121.3 - 61.5x above the device's benign median (1.971); above the benign 99th percentile (54.39).

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.
[C2] Mirai UDP-Plain Flood Attack (High-PPS Variant)
# Mirai UDP-Plain Flood Attack (High-PPS Variant)

## Threat assessment

The infected device is running Mirai's optimised UDP flood. Severity is high and
equivalent to the generic UDP flood: the device is attacking a third party under botnet
control, at the maximum packet rate its hardware can produce.
[C3] Mirai SYN Flood Attack
# Mirai SYN Flood Attack

## Threat assessment

The infected device is emitting a TCP SYN flood as part of a coordinated DDoS attack.
Severity is high: the device is under botnet command and control and actively attacking a
third party.

### Attack Mechanism
[C4] Mirai UDP Flood Attack
## Mechanism

A UDP flood overwhelms a target with connectionless datagrams. Because UDP requires no
handshake, the bot can transmit at line rate immediately; the damage is volumetric
(bandwidth exhaustion) and, secondarily, CPU load on the victim generating ICMP
port-unreachable responses. Mirai's generic UDP attack supports configurable payload
sizes, destination ports, and header options, letting operators tune packet size against
packet rate for the chosen target.
[C5] Mirai UDP-Plain Flood Attack (High-PPS Variant)
## Mechanism

"UDP plain" is Mirai's stripped-down UDP attack. Where the generic UDP flood rebuilds
configurable header options for every packet, udpplain removes most options and reuses a
single pre-built packet template, spending CPU only on the send loop. On weak embedded
processors this raises achievable packets-per-second substantially - the attack is
optimised for PPS rather than per-packet flexibility. It is the variant of choice when
the operator wants raw packet rate against a single target port.
[C6] Mirai Botnet Family Overview
## Attack repertoire (classes present in this dataset)

- **mirai_scan** - Telnet scanning/propagation traffic seeking new victims.
- **mirai_syn** - TCP SYN flood: connection-request exhaustion against a target.
- **mirai_ack** - TCP ACK flood: state-table exhaustion, also used to bypass naive SYN filters.
- **mirai_udp** - generic UDP flood with configurable payloads.
- **mirai_udpplain** - UDP flood with a stripped-down packet-building loop and fewer
  options, optimised for maximum packets-per-second.

## Analyst notes

Mirai attack traffic is machine-generated and highly regular: fixed or narrowly
distributed packet sizes, extreme packet rates, and near-constant inter-arrival times
that differ sharply from the bursty, low-volume traffic profile of a benign IoT device.

### Observable Indicators
[C7] Mirai UDP-Plain Flood Attack (High-PPS Variant)
## Observable indicators

- The most extreme outbound packet rates of any Mirai attack class on the same
  hardware - the defining signature of this variant.
- An essentially degenerate packet-size distribution: every packet is built from the
  same template, so outbound size variance collapses to near zero.
- Extremely regular inter-arrival times, tighter than the generic UDP flood because no
  per-packet option handling perturbs the send loop.
- Single fixed destination address and port for the duration of the attack command.

## Response priorities

Identical to the generic UDP flood: isolate immediately (the uplink is likely
saturated), power-cycle to clear the memory-resident bot, rotate credentials, and remove
Telnet exposure before reconnecting. See the immediate containment guide.

## Analyst note on classification

udpplain and udp differ in implementation efficiency, not in protocol semantics. The
statistical distinction visible to a traffic-feature classifier is the packet-rate and
timing profile, which is why the two remain separable classes in this dataset.
[C8] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C9] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
[C10] Immediate Containment Playbook for a Compromised IoT Device
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

## assertive_correct-285001

### ALERT DATA
ALERT DATA
- Device: Provision_PT_838_Security_Camera
- Device category: security_camera
- Predicted class: gafgyt_junk (Gafgyt junk attack)
- p_top1: 1.0000
- Second class: benign (benign traffic)
- p_top2: 0.0000
- p_pair: 0.0000
- Margin: 1.0000
- Entropy: 0.0000

### EVIDENCE
EVIDENCE
[E1] (DISCRIMINATIVE) HH_L0.1_weight = 7282 - 2384.9x above the device's benign median (3.054); above the benign 99th percentile (115.5).
[E2] (DISCRIMINATIVE) MI_dir_L0.1_weight = 7309 - 838.0x above the device's benign median (8.723); above the benign 99th percentile (123.3).
[E3] (CONTEXTUAL) HH_L0.1_magnitude = 95.27 - approximately at the device's benign median (114); within the benign 99th percentile (522.2). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) HH_jit_L1_variance = 1.37 - 1.8x above the device's benign median (0.7571); within the benign 99th percentile (1.042e+05). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_mean = 74.53 - 0.7x below the device's benign median (103.7); within the benign 99th percentile (159.2). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt Combo Attack (Junk Payloads + Connection Opening)
# Gafgyt Combo Attack (Junk Payloads + Connection Opening)

## Threat assessment

The infected device is running Gafgyt's "combo" attack: it repeatedly opens TCP
connections to a victim IP and port while pushing junk payload data through them.
Severity is high - the device is under botnet control and attacking a third party with a
technique aimed at application/connection-handling resources rather than raw bandwidth.
[C2] Gafgyt Junk Attack (Random Payload Flood)
# Gafgyt Junk Attack (Random Payload Flood)

## Threat assessment

The infected device is sending streams of random "junk" payload data at a victim as part
of a Gafgyt (BASHLITE) DDoS attack. Severity is high: the device is under external
command and control and consuming its uplink to attack a third party.
[C3] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.

### Attack Mechanism
[C4] Gafgyt Junk Attack (Random Payload Flood)
## Mechanism

The junk attack writes randomly generated byte sequences to the target. Its purpose is
twofold: volumetric load, and evasion - because payload contents are random rather than
a fixed template, simple signature- or content-based filters cannot match a repeating
pattern. Each transmission carries a randomly sized and randomly filled buffer, which
distinguishes junk statistically from Gafgyt's template-built tcp/udp floods.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.

### Observable Indicators
[C6] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.

### Immediate Actions
[C8] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
[C9] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C10] Consumer Webcam: Device Profile and Security Guidance
## Device-specific response actions

- **Immediate**: disconnect the webcam from the network. Webcams have no
  safety-critical function; isolation is always the right first move. As with any
  camera device, treat compromise as a potential privacy breach too.
- Power-cycle, then change local admin and vendor-cloud credentials before considering
  reconnection.
- Check for firmware updates. For discontinued models with known unpatched
  vulnerabilities, **replacement is the remediation** - no configuration fully secures
  an unpatchable camera.
- Remove router port-forwarding/UPnP entries exposing the webcam.

## Longer-term hardening

If the device stays in service: IoT-only VLAN, cloud-only egress, outbound Telnet
blocked, unique credentials, and periodic checks that the vendor relay still receives
security maintenance. Prefer retiring end-of-life camera hardware over compensating
controls.

### Longer Term Remediation
[C11] Networked Baby Monitor: Device Profile and Security Guidance
## Device-specific response actions

- **Immediate**: disconnect the monitor from the network. Fall back to local/direct
  monitoring if the household needs it; do not leave a compromised camera-microphone
  device online while investigating.
- Power-cycle, change every credential associated with the device (local admin, RTSP,
  vendor cloud account), and check for firmware updates before reconnecting.
- Inspect router port-forwarding/UPnP entries: internet-reachable baby monitors are a
  common misconfiguration and the main path to compromise.
- Given the privacy stakes, if the model has known unpatched vulnerabilities or no
  vendor updates, replace it rather than re-deploy.

## Longer-term hardening

IoT-only network segment, cloud-only egress, outbound Telnet blocked, UPnP disabled.
Prefer monitors that support authenticated, encrypted streaming and have an active
vendor update channel.

### Confidence Notes
[C12] Pair-Level Assertion: How Reports Handle the Ambiguous Gafgyt Flood Pair
# Pair-Level Assertion: How Reports Handle the Ambiguous Gafgyt Flood Pair

## The rule

When the detector's evidence stops at the pair boundary, the report's language must stop
there too. For gafgyt_tcp/gafgyt_udp alerts, reports assert the **pair superclass** -
"a Gafgyt tcp-or-udp flood" - quantified by the pair probability
**p_pair = p(gafgyt_tcp) + p(gafgyt_udp)**, and explicitly decline to pick a member.

## assertive_correct-90002

### ALERT DATA
ALERT DATA
- Device: Ecobee_Thermostat
- Device category: thermostat
- Predicted class: gafgyt_junk (Gafgyt junk attack)
- p_top1: 1.0000
- Second class: benign (benign traffic)
- p_top2: 0.0000
- p_pair: 0.0000
- Margin: 1.0000
- Entropy: 0.0000

### EVIDENCE
EVIDENCE
[E1] (DISCRIMINATIVE) HH_L0.1_weight = 7008 - 4599.3x above the device's benign median (1.524); above the benign 99th percentile (5.344).
[E2] (DISCRIMINATIVE) MI_dir_L0.1_weight = 7033 - 2898.6x above the device's benign median (2.426); above the benign 99th percentile (6.257).
[E3] (CONTEXTUAL) HH_jit_L1_variance = 24.28 - 687755.4x above the device's benign median (3.53e-05); within the benign 99th percentile (880.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) HH_L0.1_magnitude = 95.27 - 0.2x below the device's benign median (382.6); within the benign 99th percentile (765.5). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_mean = 74.35 - 0.4x below the device's benign median (200.9); within the benign 99th percentile (261.4). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt Combo Attack (Junk Payloads + Connection Opening)
# Gafgyt Combo Attack (Junk Payloads + Connection Opening)

## Threat assessment

The infected device is running Gafgyt's "combo" attack: it repeatedly opens TCP
connections to a victim IP and port while pushing junk payload data through them.
Severity is high - the device is under botnet control and attacking a third party with a
technique aimed at application/connection-handling resources rather than raw bandwidth.
[C2] Gafgyt Junk Attack (Random Payload Flood)
# Gafgyt Junk Attack (Random Payload Flood)

## Threat assessment

The infected device is sending streams of random "junk" payload data at a victim as part
of a Gafgyt (BASHLITE) DDoS attack. Severity is high: the device is under external
command and control and consuming its uplink to attack a third party.
[C3] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.

### Attack Mechanism
[C4] Gafgyt Junk Attack (Random Payload Flood)
## Mechanism

The junk attack writes randomly generated byte sequences to the target. Its purpose is
twofold: volumetric load, and evasion - because payload contents are random rather than
a fixed template, simple signature- or content-based filters cannot match a repeating
pattern. Each transmission carries a randomly sized and randomly filled buffer, which
distinguishes junk statistically from Gafgyt's template-built tcp/udp floods.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.

### Observable Indicators
[C7] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.
[C8] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C9] Mirai UDP-Plain Flood Attack (High-PPS Variant)
## Observable indicators

- The most extreme outbound packet rates of any Mirai attack class on the same
  hardware - the defining signature of this variant.
- An essentially degenerate packet-size distribution: every packet is built from the
  same template, so outbound size variance collapses to near zero.
- Extremely regular inter-arrival times, tighter than the generic UDP flood because no
  per-packet option handling perturbs the send loop.
- Single fixed destination address and port for the duration of the attack command.

## Response priorities

Identical to the generic UDP flood: isolate immediately (the uplink is likely
saturated), power-cycle to clear the memory-resident bot, rotate credentials, and remove
Telnet exposure before reconnecting. See the immediate containment guide.

## Analyst note on classification

udpplain and udp differ in implementation efficiency, not in protocol semantics. The
statistical distinction visible to a traffic-feature classifier is the packet-rate and
timing profile, which is why the two remain separable classes in this dataset.

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
[C12] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

## assertive_error-317103

### ALERT DATA
ALERT DATA
- Device: Samsung_SNH_1011_N_Webcam
- Device category: webcam
- Predicted class: gafgyt_combo (Gafgyt combo attack)
- p_top1: 0.9992
- Second class: benign (benign traffic)
- p_top2: 0.0008
- p_pair: 0.0000
- Margin: 0.9983
- Entropy: 0.0067

### EVIDENCE
EVIDENCE
[E1] (DISCRIMINATIVE) MI_dir_L0.1_weight = 7485 - 1974.8x above the device's benign median (3.79); above the benign 99th percentile (52.97).
[E2] (CONTEXTUAL) HH_L0.1_magnitude = 137.5 - 0.4x below the device's benign median (381.8); within the benign 99th percentile (591.8). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) HH_jit_L3_variance = 9.366e-07 - 0.0x below the device's benign median (0.003906); within the benign 99th percentile (631.5). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) HH_L0.1_covariance = 26.78 - far above the device's benign median (0); within the benign 99th percentile (2864). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) HH_L0.01_radius = 38.88 - 0.1x below the device's benign median (397.1); within the benign 99th percentile (1.974e+05). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt Combo Attack (Junk Payloads + Connection Opening)
# Gafgyt Combo Attack (Junk Payloads + Connection Opening)

## Threat assessment

The infected device is running Gafgyt's "combo" attack: it repeatedly opens TCP
connections to a victim IP and port while pushing junk payload data through them.
Severity is high - the device is under botnet control and attacking a third party with a
technique aimed at application/connection-handling resources rather than raw bandwidth.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.

### Attack Mechanism
[C4] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C5] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.

### Observable Indicators
[C6] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C7] DDoS Flood Attacks: TCP and UDP Mechanics
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
[C8] Mirai UDP-Plain Flood Attack (High-PPS Variant)
## Observable indicators

- The most extreme outbound packet rates of any Mirai attack class on the same
  hardware - the defining signature of this variant.
- An essentially degenerate packet-size distribution: every packet is built from the
  same template, so outbound size variance collapses to near zero.
- Extremely regular inter-arrival times, tighter than the generic UDP flood because no
  per-packet option handling perturbs the send loop.
- Single fixed destination address and port for the duration of the attack command.

## Response priorities

Identical to the generic UDP flood: isolate immediately (the uplink is likely
saturated), power-cycle to clear the memory-resident bot, rotate credentials, and remove
Telnet exposure before reconnecting. See the immediate containment guide.

## Analyst note on classification

udpplain and udp differ in implementation efficiency, not in protocol semantics. The
statistical distinction visible to a traffic-feature classifier is the packet-rate and
timing profile, which is why the two remain separable classes in this dataset.

### Immediate Actions
[C9] Consumer Webcam: Device Profile and Security Guidance
## Device-specific response actions

- **Immediate**: disconnect the webcam from the network. Webcams have no
  safety-critical function; isolation is always the right first move. As with any
  camera device, treat compromise as a potential privacy breach too.
- Power-cycle, then change local admin and vendor-cloud credentials before considering
  reconnection.
- Check for firmware updates. For discontinued models with known unpatched
  vulnerabilities, **replacement is the remediation** - no configuration fully secures
  an unpatchable camera.
- Remove router port-forwarding/UPnP entries exposing the webcam.

## Longer-term hardening

If the device stays in service: IoT-only VLAN, cloud-only egress, outbound Telnet
blocked, unique credentials, and periodic checks that the vendor relay still receives
security maintenance. Prefer retiring end-of-life camera hardware over compensating
controls.
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

### Longer Term Remediation
[C12] Networked Baby Monitor: Device Profile and Security Guidance
## Device-specific response actions

- **Immediate**: disconnect the monitor from the network. Fall back to local/direct
  monitoring if the household needs it; do not leave a compromised camera-microphone
  device online while investigating.
- Power-cycle, change every credential associated with the device (local admin, RTSP,
  vendor cloud account), and check for firmware updates before reconnecting.
- Inspect router port-forwarding/UPnP entries: internet-reachable baby monitors are a
  common misconfiguration and the main path to compromise.
- Given the privacy stakes, if the model has known unpatched vulnerabilities or no
  vendor updates, replace it rather than re-deploy.

## Longer-term hardening

IoT-only network segment, cloud-only egress, outbound Telnet blocked, UPnP disabled.
Prefer monitors that support authenticated, encrypted streaming and have an active
vendor update channel.

## assertive_error-91545

### ALERT DATA
ALERT DATA
- Device: Ecobee_Thermostat
- Device category: thermostat
- Predicted class: gafgyt_combo (Gafgyt combo attack)
- p_top1: 0.9992
- Second class: benign (benign traffic)
- p_top2: 0.0008
- p_pair: 0.0000
- Margin: 0.9983
- Entropy: 0.0067

### EVIDENCE
EVIDENCE
[E1] (DISCRIMINATIVE) MI_dir_L0.1_weight = 7485 - 3084.8x above the device's benign median (2.426); above the benign 99th percentile (6.257).
[E2] (CONTEXTUAL) HH_L0.1_magnitude = 137.5 - 0.4x below the device's benign median (382.6); within the benign 99th percentile (765.5). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) HH_jit_L3_variance = 9.366e-07 - far above the device's benign median (0); within the benign 99th percentile (835.7). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) HH_L0.1_covariance = 26.78 - -75.6x below the device's benign median (-0.3542); within the benign 99th percentile (1317). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) HH_L0.01_radius = 38.88 - 0.0x below the device's benign median (3.454e+04); within the benign 99th percentile (1.119e+05). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt Combo Attack (Junk Payloads + Connection Opening)
# Gafgyt Combo Attack (Junk Payloads + Connection Opening)

## Threat assessment

The infected device is running Gafgyt's "combo" attack: it repeatedly opens TCP
connections to a victim IP and port while pushing junk payload data through them.
Severity is high - the device is under botnet control and attacking a third party with a
technique aimed at application/connection-handling resources rather than raw bandwidth.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.

### Attack Mechanism
[C4] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C5] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.

### Observable Indicators
[C6] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C7] Mirai UDP-Plain Flood Attack (High-PPS Variant)
## Observable indicators

- The most extreme outbound packet rates of any Mirai attack class on the same
  hardware - the defining signature of this variant.
- An essentially degenerate packet-size distribution: every packet is built from the
  same template, so outbound size variance collapses to near zero.
- Extremely regular inter-arrival times, tighter than the generic UDP flood because no
  per-packet option handling perturbs the send loop.
- Single fixed destination address and port for the duration of the attack command.

## Response priorities

Identical to the generic UDP flood: isolate immediately (the uplink is likely
saturated), power-cycle to clear the memory-resident bot, rotate credentials, and remove
Telnet exposure before reconnecting. See the immediate containment guide.

## Analyst note on classification

udpplain and udp differ in implementation efficiency, not in protocol semantics. The
statistical distinction visible to a traffic-feature classifier is the packet-rate and
timing profile, which is why the two remain separable classes in this dataset.
[C8] Gafgyt Combo Attack (Junk Payloads + Connection Opening)
## Observable indicators

- Elevated outbound packet rate - high, but typically below the raw flood classes,
  because handshake round-trips throttle the loop.
- A **mixed** outbound packet-size distribution: handshake-sized control segments
  interleaved with junk-payload data segments, giving higher size variance than
  template floods (which are near-degenerate).
- Bidirectional traffic with the victim: unlike stateless floods, combo completes
  handshakes, so inbound ACK traffic from the target accompanies the outbound stream.
- Repeated short-lived connections to a single destination address and port.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. See the immediate containment and long-term hardening
guides.

### Immediate Actions
[C9] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C10] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
[C11] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Longer Term Remediation
[C12] Smart Thermostat: Device Profile and Security Guidance
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

## hedged_pair-100010

### ALERT DATA
ALERT DATA
- Device: Ecobee_Thermostat
- Device category: thermostat
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.4998
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4993
- p_pair: 0.9992
- Margin: 0.0005
- Entropy: 0.6993

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.1x below the device's benign median (12.62); within the benign 99th percentile (18.37). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (2.483e+04); within the benign 99th percentile (5.149e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.3x below the device's benign median (222.8); within the benign 99th percentile (414.8). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.1x below the device's benign median (12.62); within the benign 99th percentile (18.37). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (2.483e+04); within the benign 99th percentile (5.149e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.

### Observable Indicators
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C8] Mirai ACK Flood Attack
## Observable indicators

- Sustained outbound TCP packet rate orders of magnitude above the device's benign
  baseline (thousands of packets per second from a device that normally emits a few).
- Very low variance in packet size: flood packets are built from one template, so the
  outbound packet-size distribution collapses to a near-constant value.
- Near-constant inter-arrival times - the regular cadence of a packet-generation loop
  rather than the bursty request/response pattern of benign device traffic.
- Traffic concentrated on one or a few destination hosts, unrelated to the device's
  normal cloud endpoints.

## Response priorities

Isolate the device from the network to stop the outbound flood, then follow standard IoT
containment: power-cycle to clear the memory-resident bot, change default credentials,
and block WAN-side Telnet before reconnecting. See the immediate containment and
long-term hardening guides.

### Immediate Actions
[C9] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C10] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Longer Term Remediation
[C11] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
[C12] Smart Thermostat: Device Profile and Security Guidance
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

## hedged_pair-105000

### ALERT DATA
ALERT DATA
- Device: Ecobee_Thermostat
- Device category: thermostat
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.4998
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4993
- p_pair: 0.9992
- Margin: 0.0005
- Entropy: 0.6993

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.1x below the device's benign median (12.62); within the benign 99th percentile (18.37). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (2.483e+04); within the benign 99th percentile (5.149e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.3x below the device's benign median (222.8); within the benign 99th percentile (414.8). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.1x below the device's benign median (12.62); within the benign 99th percentile (18.37). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (2.483e+04); within the benign 99th percentile (5.149e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.

### Observable Indicators
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C8] Mirai ACK Flood Attack
## Observable indicators

- Sustained outbound TCP packet rate orders of magnitude above the device's benign
  baseline (thousands of packets per second from a device that normally emits a few).
- Very low variance in packet size: flood packets are built from one template, so the
  outbound packet-size distribution collapses to a near-constant value.
- Near-constant inter-arrival times - the regular cadence of a packet-generation loop
  rather than the bursty request/response pattern of benign device traffic.
- Traffic concentrated on one or a few destination hosts, unrelated to the device's
  normal cloud endpoints.

## Response priorities

Isolate the device from the network to stop the outbound flood, then follow standard IoT
containment: power-cycle to clear the memory-resident bot, change default credentials,
and block WAN-side Telnet before reconnecting. See the immediate containment and
long-term hardening guides.

### Immediate Actions
[C9] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C10] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Longer Term Remediation
[C11] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
[C12] Smart Thermostat: Device Profile and Security Guidance
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

## hedged_pair-105004

### ALERT DATA
ALERT DATA
- Device: Ecobee_Thermostat
- Device category: thermostat
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.4998
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4993
- p_pair: 0.9992
- Margin: 0.0005
- Entropy: 0.6993

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.1x below the device's benign median (12.62); within the benign 99th percentile (18.37). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (2.483e+04); within the benign 99th percentile (5.149e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.3x below the device's benign median (222.8); within the benign 99th percentile (414.8). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.1x below the device's benign median (12.62); within the benign 99th percentile (18.37). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (2.483e+04); within the benign 99th percentile (5.149e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.

### Observable Indicators
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C8] Mirai ACK Flood Attack
## Observable indicators

- Sustained outbound TCP packet rate orders of magnitude above the device's benign
  baseline (thousands of packets per second from a device that normally emits a few).
- Very low variance in packet size: flood packets are built from one template, so the
  outbound packet-size distribution collapses to a near-constant value.
- Near-constant inter-arrival times - the regular cadence of a packet-generation loop
  rather than the bursty request/response pattern of benign device traffic.
- Traffic concentrated on one or a few destination hosts, unrelated to the device's
  normal cloud endpoints.

## Response priorities

Isolate the device from the network to stop the outbound flood, then follow standard IoT
containment: power-cycle to clear the memory-resident bot, change default credentials,
and block WAN-side Telnet before reconnecting. See the immediate containment and
long-term hardening guides.

### Immediate Actions
[C9] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C10] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Longer Term Remediation
[C11] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
[C12] Smart Thermostat: Device Profile and Security Guidance
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

## hedged_pair-130000

### ALERT DATA
ALERT DATA
- Device: Ennio_Doorbell
- Device category: doorbell
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (20.36); within the benign 99th percentile (41.32). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (199.6); within the benign 99th percentile (8923). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.7x below the device's benign median (87.61); within the benign 99th percentile (129.7). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (20.36); within the benign 99th percentile (41.32). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (199.6); within the benign 99th percentile (8922). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C8] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C9] DDoS Flood Attacks: TCP and UDP Mechanics
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

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## hedged_pair-135001

### ALERT DATA
ALERT DATA
- Device: Ennio_Doorbell
- Device category: doorbell
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (20.36); within the benign 99th percentile (41.32). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (199.6); within the benign 99th percentile (8923). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.7x below the device's benign median (87.61); within the benign 99th percentile (129.7). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (20.36); within the benign 99th percentile (41.32). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (199.6); within the benign 99th percentile (8922). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C8] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C9] DDoS Flood Attacks: TCP and UDP Mechanics
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

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## hedged_pair-240001

### ALERT DATA
ALERT DATA
- Device: Provision_PT_737E_Security_Camera
- Device category: security_camera
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (31.5); within the benign 99th percentile (131.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (3430); within the benign 99th percentile (4.384e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.8x below the device's benign median (79.26); within the benign 99th percentile (171.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (31.5); within the benign 99th percentile (131.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (3419); within the benign 99th percentile (4.384e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C8] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C9] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## hedged_pair-245001

### ALERT DATA
ALERT DATA
- Device: Provision_PT_737E_Security_Camera
- Device category: security_camera
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (31.5); within the benign 99th percentile (131.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (3430); within the benign 99th percentile (4.384e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.8x below the device's benign median (79.26); within the benign 99th percentile (171.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (31.5); within the benign 99th percentile (131.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (3419); within the benign 99th percentile (4.384e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C8] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C9] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## hedged_pair-245009

### ALERT DATA
ALERT DATA
- Device: Provision_PT_737E_Security_Camera
- Device category: security_camera
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (31.5); within the benign 99th percentile (131.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (3430); within the benign 99th percentile (4.384e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.8x below the device's benign median (79.26); within the benign 99th percentile (171.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (31.5); within the benign 99th percentile (131.1). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (3419); within the benign 99th percentile (4.384e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C8] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C9] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## hedged_pair-295024

### ALERT DATA
ALERT DATA
- Device: Provision_PT_838_Security_Camera
- Device category: security_camera
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (59.29); within the benign 99th percentile (254.2). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (1.766e+04); within the benign 99th percentile (4.95e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.7x below the device's benign median (89.05); within the benign 99th percentile (171.3). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (59.29); within the benign 99th percentile (254.2). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (1.766e+04); within the benign 99th percentile (4.95e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C8] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C9] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## hedged_pair-300009

### ALERT DATA
ALERT DATA
- Device: Provision_PT_838_Security_Camera
- Device category: security_camera
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (59.29); within the benign 99th percentile (254.2). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (1.766e+04); within the benign 99th percentile (4.95e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.7x below the device's benign median (89.05); within the benign 99th percentile (171.3). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (59.29); within the benign 99th percentile (254.2). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (1.766e+04); within the benign 99th percentile (4.95e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C8] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C9] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## hedged_pair-325011

### ALERT DATA
ALERT DATA
- Device: Samsung_SNH_1011_N_Webcam
- Device category: webcam
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (29.18); within the benign 99th percentile (410.7). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (3.164e+04); within the benign 99th percentile (7.688e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.2x below the device's benign median (288.3); within the benign 99th percentile (413.2). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (29.18); within the benign 99th percentile (410.7). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (3.164e+04); within the benign 99th percentile (7.688e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C8] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C9] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.

## hedged_pair-330023

### ALERT DATA
ALERT DATA
- Device: Samsung_SNH_1011_N_Webcam
- Device category: webcam
- Predicted class: gafgyt_tcp (Gafgyt TCP flood)
- p_top1: 0.5002
- Second class: gafgyt_udp (Gafgyt UDP flood)
- p_top2: 0.4998
- p_pair: 1.0000
- Margin: 0.0005
- Entropy: 0.6931

### EVIDENCE
EVIDENCE
[E1] (CONTEXTUAL) H_L0.01_weight = 1 - 0.0x below the device's benign median (29.18); within the benign 99th percentile (410.7). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E2] (CONTEXTUAL) H_L0.01_variance = 0 - 0.0x below the device's benign median (3.164e+04); within the benign 99th percentile (7.688e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E3] (CONTEXTUAL) MI_dir_L0.1_mean = 60 - 0.2x below the device's benign median (288.3); within the benign 99th percentile (413.2). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E4] (CONTEXTUAL) MI_dir_L0.01_weight = 1 - 0.0x below the device's benign median (29.18); within the benign 99th percentile (410.7). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.
[E5] (CONTEXTUAL) MI_dir_L0.01_variance = 0 - 0.0x below the device's benign median (3.164e+04); within the benign 99th percentile (7.688e+04). Contextual only: describe as anomalous relative to baseline; do not tie to a specific attack type.

### CONTEXT
CONTEXT

### Threat Assessment
[C1] Gafgyt TCP Flood Attack
# Gafgyt TCP Flood Attack

## Threat assessment

The infected device is emitting a high-rate TCP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device is under external command and control
and is consuming its uplink to attack a third party.
[C2] Gafgyt UDP Flood Attack
# Gafgyt UDP Flood Attack

## Threat assessment

The infected device is emitting a high-volume UDP flood as part of a Gafgyt (BASHLITE)
botnet DDoS attack. Severity is high: the device's uplink is being used to saturate a
victim's bandwidth under external command and control.
[C3] Mirai ACK Flood Attack
# Mirai ACK Flood Attack

## Threat assessment

The infected device is actively participating in a distributed denial-of-service attack,
emitting a high-rate stream of TCP ACK packets toward a victim chosen by the botnet
operator. Severity is high: the device is under external control, consuming upstream
bandwidth, and contributing to third-party harm.

### Attack Mechanism
[C4] Gafgyt TCP Flood Attack
## Mechanism

Gafgyt's TCP flood sends a continuous stream of TCP segments at a target IP and port.
Depending on the variant and command parameters, segments may carry SYN, ACK, or other
flag combinations with randomised source ports and sequence numbers. The goal is a
mixture of state exhaustion (connection tables on the victim or its middleboxes) and raw
volumetric load. The packet-building loop is simple C code; on embedded hardware it
produces a sustained, extremely regular stream.
[C5] Gafgyt UDP Flood Attack
## Mechanism

Gafgyt's UDP flood transmits connectionless datagrams at a target IP and port as fast as
the device can generate them. With no handshake or congestion control, the attack is
purely volumetric: it exhausts the victim's inbound bandwidth and burdens it with ICMP
port-unreachable generation. Payload contents are typically random or repeated filler
bytes of a fixed configured size; the send loop reuses one packet template.
[C6] Gafgyt UDP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's UDP and TCP floods are
**indistinguishable**: the features do not record the transport protocol, and both
attacks produce template-built maximum-rate streams with near-identical statistics.
Reports must therefore assert at the pair level ("Gafgyt tcp-or-udp flood"), present
both candidates symmetrically, and point the analyst to the packet-capture
disambiguation procedure - a single packet's IP protocol field settles it.

## Response priorities

Isolate the device (its flood may be saturating the local uplink), power-cycle, rotate
credentials, and eliminate WAN-exposed Telnet before reconnecting. Containment is
identical for both members of the tcp/udp pair, so response should never wait on
protocol disambiguation.

### Observable Indicators
[C7] Gafgyt (BASHLITE) Botnet Family Overview
## Analyst notes

Gafgyt flood traffic shows the same machine-generated regularity as other IoT DDoS
malware: sustained extreme packet rates and tight packet-size and timing distributions.
Note for this dataset: gafgyt_tcp and gafgyt_udp floods are statistically
indistinguishable in the N-BaIoT feature space because the features do not record the
transport protocol; see the pair-level assertion guidance for how reports must handle
this pair.
[C8] Gafgyt TCP Flood Attack
## Important caveat for this dataset

In the N-BaIoT statistical feature space, Gafgyt's TCP and UDP floods are
**indistinguishable**: the features aggregate packet counts, sizes, and timing but do not
record the transport protocol, and both floods are template-built maximum-rate streams
with near-identical statistics. A detector on these features can assert "Gafgyt tcp-or-udp
flood" with high confidence but cannot tell which member of the pair it is. Reports must
assert at the pair level and direct the analyst to the packet-capture disambiguation
procedure (one packet's IP protocol field resolves it).

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate credentials,
and remove Telnet exposure. Response is identical for the TCP and UDP flood variants, so
the pair ambiguity does not delay containment.
[C9] Gafgyt Junk Attack (Random Payload Flood)
## Observable indicators

- Sustained outbound packet rate well above the device's benign baseline.
- **Higher packet-size variance than template floods**: random payload lengths spread
  the outbound size distribution, where tcp/udp flood packets collapse to a single
  size. This spread is the junk attack's most useful statistical fingerprint.
- Machine-regular sending cadence despite randomised contents - inter-arrival timing
  still reflects a generation loop, not human-driven or event-driven device activity.
- A single victim destination unrelated to the device's normal endpoints.

## Response priorities

Isolate the device, power-cycle to clear the memory-resident bot, rotate default
credentials, and block WAN-side Telnet before reconnecting. See the immediate
containment and long-term hardening guides.

### Immediate Actions
[C10] Why Gafgyt TCP and UDP Floods Are Indistinguishable in This Feature Space
## Implications for reports on this pair

- Assert at the **pair level**: "Gafgyt tcp-or-udp flood", with the pair probability
  p_pair = p(gafgyt_tcp) + p(gafgyt_udp).
- Present both candidates **symmetrically**; any ordering language would dress a
  capture artefact as evidence.
- State the indistinguishability and its structural cause explicitly.
- Give the analyst the resolution path: a single packet from the raw capture settles
  the protocol (see the packet-capture disambiguation procedure).

## Why this does not delay response

Containment for the two attacks is identical (isolate, power-cycle, rotate credentials,
close Telnet exposure), so the protocol ambiguity has no operational cost at the
containment stage.
[C11] Immediate Containment Playbook for a Compromised IoT Device
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

### Longer Term Remediation
[C12] Long-Term Hardening Programme for IoT Deployments
# Long-Term Hardening Programme for IoT Deployments

Immediate containment stops one incident; these measures stop the class of incident.
They are ordered by protection-per-effort for home and small-business networks.

## 1. Eliminate default and shared credentials

Every IoT device gets a unique, non-default password at deployment. Mirai/Gafgyt-class
botnets are, at core, default-credential exploitation at scale - this single control
breaks their primary propagation path. Keep an inventory of devices and their credential
status; a spreadsheet is enough at small scale.
