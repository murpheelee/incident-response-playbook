<p align="center">
  <img src="https://img.shields.io/badge/Framework-NIST%20SP%20800--61-002868?style=for-the-badge" alt="NIST IR"/>
  <img src="https://img.shields.io/badge/Standard-SANS%20IR-E21E26?style=for-the-badge" alt="SANS"/>
  <img src="https://img.shields.io/badge/Focus-Incident%20Response-FF6600?style=for-the-badge" alt="IR"/>
</p>

# Incident Response Playbook

> **Structured incident response procedures** aligned with NIST SP 800-61 Rev 2 and the SANS Incident Response framework — providing actionable, step-by-step playbooks for common security incidents with escalation paths, containment strategies, and recovery procedures.

## Objective

Develop a comprehensive, enterprise-ready incident response playbook that security teams can use during active incidents. Each playbook follows a standardized structure, maps to MITRE ATT&CK techniques, and includes decision trees, containment options, and communication templates — demonstrating IR program development skills critical for security leadership.

## IR Lifecycle (NIST SP 800-61)

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│1. Preparation│──▶│2. Detection &│──▶│3. Containment│──▶│4. Post-      │
│              │   │   Analysis   │   │  Eradication │   │   Incident   │
│              │   │              │   │  & Recovery  │   │   Activity   │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

## Playbook Index

| # | Playbook | Severity | MITRE ATT&CK | Status |
|---|----------|----------|--------------|--------|
| 1 | [Malware Infection](#playbook-1-malware-infection) | High | T1059, T1055, T1071 | Complete |
| 2 | [Phishing Attack](#playbook-2-phishing-attack) | Medium-High | T1566, T1534, T1078 | Complete |
| 3 | [Brute Force / Credential Stuffing](#playbook-3-brute-force--credential-stuffing) | High | T1110, T1078 | Complete |
| 4 | [Ransomware](#playbook-4-ransomware) | Critical | T1486, T1490, T1027 | Complete |
| 5 | [Insider Threat](#playbook-5-insider-threat) | High | T1078, T1567, T1048 | Complete |
| 6 | [Unauthorized Access](#playbook-6-unauthorized-access) | High | T1078, T1021 | Complete |

---

## Playbook 1: Malware Infection

### Detection Indicators
- EDR/AV alerts for known malware signatures or suspicious behavior
- Unusual outbound network connections (C2 beaconing)
- Unexpected process execution or file modifications
- User reports of slow system performance or pop-ups

### Severity Classification

| Indicator | Low | Medium | High | Critical |
|-----------|-----|--------|------|----------|
| Single endpoint, known malware, auto-quarantined | X | | | |
| Multiple endpoints, unknown variant | | | X | |
| Lateral movement observed | | | | X |
| Data exfiltration confirmed | | | | X |

### Response Procedures

**Containment (Immediate — within 15 minutes)**
1. Isolate affected endpoint(s) from the network (disable NIC or EDR network isolation)
2. Preserve volatile memory (RAM dump) before any remediation
3. Block identified malicious IPs/domains at the firewall/proxy
4. Disable compromised user account(s) if credential theft suspected

**Eradication**
1. Run full EDR scan on isolated endpoint
2. Remove malicious files, registry keys, scheduled tasks
3. Identify and remove persistence mechanisms
4. Check for lateral movement artifacts on adjacent systems

**Recovery**
1. Re-image endpoint if rootkit or extensive compromise detected
2. Restore from last known clean backup if data integrity is questionable
3. Re-enable network access with enhanced monitoring
4. Reset credentials for any accounts that accessed the compromised system

**Post-Incident**
1. Document timeline, IOCs, and actions taken
2. Update detection rules based on observed TTPs
3. Conduct lessons learned meeting within 5 business days
4. Update this playbook with any procedural improvements

---

## Playbook 2: Phishing Attack

### Detection Indicators
- User reports suspicious email
- Email security gateway flags malicious attachment/link
- Multiple users receive same suspicious email
- Unusual sign-in activity following email interaction

### Response Procedures

**Containment (Immediate)**
1. Pull the phishing email from all mailboxes (admin purge)
2. Block the sender domain/IP at the email gateway
3. Block any malicious URLs at the web proxy
4. If credentials entered: immediately reset the user's password and revoke active sessions

**Analysis**
1. Extract and detonate attachments in sandbox
2. Analyze email headers for true source
3. Check if any users clicked the link (proxy logs, email tracking pixel)
4. Identify the scope: how many users received the email?

**Communication**
1. If < 10 users affected: direct notification
2. If organization-wide: issue security advisory to all staff
3. If customer data at risk: engage legal and communications team

---

## Playbook 3: Brute Force / Credential Stuffing

### Detection Indicators
- 10+ failed authentication attempts from a single source within 15 minutes
- Failed attempts followed by a successful logon
- Login attempts against multiple accounts from same IP
- Attempts from geographically anomalous locations

### KQL Detection Query

```kql
// Detect brute force: 10+ failures followed by success
let threshold = 10;
let timeframe = 15m;
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4625, 4624)
| summarize
    FailedAttempts = countif(EventID == 4625),
    SuccessfulAttempts = countif(EventID == 4624),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated)
    by IpAddress, Account
| where FailedAttempts >= threshold
| where SuccessfulAttempts > 0
| where (LastEvent - FirstEvent) <= timeframe
| project Account, IpAddress, FailedAttempts, SuccessfulAttempts, FirstEvent, LastEvent
```

### Response Procedures

**Containment**
1. Block the source IP at the firewall (temporary 24h block)
2. If successful login detected: disable the compromised account immediately
3. Force password reset for the targeted account(s)
4. Enable or verify MFA is enforced

**Investigation**
1. Check if credentials were used to access any resources post-compromise
2. Review what data/systems the account has access to
3. Check for credential dumps on dark web (Have I Been Pwned, threat intelligence feeds)

---

## Playbook 4: Ransomware

### Detection Indicators
- Mass file encryption or renaming (`.encrypted`, `.locked` extensions)
- Ransom note files appearing on endpoints or file shares
- Volume Shadow Copy deletion alerts
- Known ransomware process execution

### Response Procedures

**CRITICAL: DO NOT**
- Do NOT shut down affected systems (preserves memory forensics)
- Do NOT pay the ransom without executive/legal authorization
- Do NOT attempt decryption without verified tools
- Do NOT connect backup media to infected systems

**Containment (Immediate — within 5 minutes)**
1. Disconnect affected systems from the network (pull cable, disable WiFi)
2. Isolate affected network segments at the switch/firewall level
3. Disable shared drives and network shares to prevent spread
4. Preserve a forensic image of at least one affected system

**Escalation**
1. Notify CISO/Security Director immediately
2. Engage incident response retainer (if applicable)
3. Notify legal counsel — potential regulatory notification requirements
4. Notify cyber insurance carrier within policy-required timeframe

**Recovery**
1. Identify ransomware variant (ID Ransomware, vendor threat intelligence)
2. Check for available decryption tools (No More Ransom project)
3. Restore from offline/immutable backups (verify integrity first)
4. Rebuild from gold images if backups are compromised

---

## Playbook 5: Insider Threat

### Detection Indicators
- Large volume data downloads or transfers to external storage
- Access to resources outside normal job function
- After-hours access to sensitive systems
- Employee on termination or PIP notice accessing sensitive data
- DLP alerts triggered by outbound email attachments

### Response Procedures

**Containment (Coordinate with HR and Legal FIRST)**
1. Do NOT alert the individual before consulting HR/Legal
2. Increase monitoring on the user's account and endpoint
3. Preserve all evidence (email, file access logs, DLP logs)
4. If imminent data loss: disable account access

**Investigation**
1. Review file access patterns for the past 30-90 days
2. Check USB/removable media usage logs
3. Review email and cloud sharing activity (OneDrive, SharePoint, personal email)
4. Interview manager regarding employee behavior changes

---

## Playbook 6: Unauthorized Access

### Detection Indicators
- Login from unexpected geographic location
- Impossible travel alerts (two logins far apart in short time)
- Access to high-value resources by non-privileged account
- After-hours VPN connection from unusual source

### Response Procedures

**Containment**
1. Disable the compromised account immediately
2. Terminate all active sessions (revoke tokens)
3. Block the source IP at the perimeter
4. Check for any persistence mechanisms (new accounts, scheduled tasks, SSH keys)

**Investigation**
1. Determine initial access vector (phishing, credential reuse, exploited vulnerability)
2. Map all resources accessed during the unauthorized session
3. Check for data exfiltration indicators
4. Determine if lateral movement occurred

---

## Communication Templates

### Initial Notification (to Management)

```
Subject: [SEVERITY] Security Incident - [Type] - [Date/Time]

An active security incident has been identified requiring immediate attention.

Incident Type: [Malware/Phishing/Ransomware/etc.]
Severity: [Critical/High/Medium/Low]
Systems Affected: [Count and description]
Current Status: [Containment in progress / Under investigation]
Business Impact: [Known or estimated impact]

Next update will be provided in [timeframe].

Incident Commander: [Name]
Contact: [Phone/Email]
```

### All-Hands Security Advisory

```
Subject: Security Advisory - [Brief Description]

The security team has identified [brief description of threat].

Required Action:
- [Specific action employees should take]
- [What to report and to whom]
- [What NOT to do]

If you believe you are affected, contact the security team immediately at [contact].
```

## Escalation Matrix

| Severity | Response Time | Escalation Path | Communication |
|----------|--------------|-----------------|---------------|
| Critical | 15 minutes | SOC → IR Lead → CISO → CTO/CEO | Executive briefing within 1 hour |
| High | 30 minutes | SOC → IR Lead → Security Manager | Management notification within 2 hours |
| Medium | 2 hours | SOC → IR Lead | Team lead notification within 4 hours |
| Low | 8 hours | SOC Analyst | Documented in ticketing system |

## Key Skills Demonstrated

- NIST SP 800-61 incident response lifecycle implementation
- SANS incident handling methodology
- MITRE ATT&CK technique mapping for detection and response
- KQL detection query authoring
- Incident escalation and communication procedures
- Cross-functional coordination (Legal, HR, Executive Leadership)
- IR program development and documentation

## References

- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [No More Ransom Project](https://www.nomoreransom.org/)
