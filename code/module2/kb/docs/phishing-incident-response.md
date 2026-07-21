---
doc_id: phishing-incident-response
title: "Phishing Incident Response Playbook"
attack_family: generic
attack_types: []
device_categories: ["generic"]
doc_type: remediation
source: public_analysis
is_distractor: true
---

# Phishing Incident Response Playbook

This playbook covers response to a phishing attack against an organisation's users - a
social-engineering and credential-theft threat unrelated to IoT botnet traffic. It is
included as an example of a plausible-but-off-target response procedure.

## Triage

- Preserve the reported email with full headers; identify sender infrastructure, embedded
  URLs, and any attachments.
- Determine scope: how many recipients, how many clicked, how many submitted credentials
  or opened attachments.

## Containment

- Pull the malicious message from all mailboxes via the mail platform's search-and-purge
  capability.
- Block sender domains, URLs, and file hashes at the mail gateway and web proxy.
- Force password resets and revoke active sessions for any user who entered credentials;
  re-enrol MFA where account takeover is suspected.

## Eradication and recovery

- Scan endpoints of users who opened attachments for malware; reimage if compromised.
- Review mailbox rules and OAuth grants for attacker-created persistence.
- Restore affected accounts and confirm no fraudulent transactions or data access
  occurred.

## Prevention

- User awareness training and simulated phishing.
- Enforce MFA everywhere; deploy DMARC/DKIM/SPF and anti-spoofing controls.
- Tune mail-filtering and URL-rewriting defences.

## Applicability note

Phishing response centres on email, user accounts, and credential theft. It shares
vocabulary with security incidents generally ("containment", "credential reset") but has
no bearing on a compromised camera or doorbell emitting DDoS traffic; use the IoT
containment guidance for those.
