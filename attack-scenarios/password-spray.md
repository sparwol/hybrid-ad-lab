# Attack Scenario: Password Spray in Hybrid AD / Entra ID

This scenario simulates a low-noise password spray attack against a hybrid environment with both on-prem Active Directory and cloud Entra ID accounts. The goal is to demonstrate how attackers discover valid credentials without triggering account lockouts, and how defenders can detect this behavior using KQL and EDR logs.

---

## Overview

**Tactic:** Initial Access (TA0001)  
**Technique:** Valid Accounts - T1078  
**Target Services:** Entra ID (Azure AD) + On-Prem Exchange OWA / LDAP  
**Tool Used:** `o365spray` (for Entra ID) + `crackmapexec` (on-prem AD)

---

## Setup

- **Domain Controller (DC01)** – Windows Server 2025
- **Workstation (WKS01)** – Windows 11, hybrid-joined
- **Azure AD Connect** syncing identities to Entra ID
- **Test Users:**
  - `alton.buckley`, `kate.morrison`, `eric.glass`, `nadine.munoz`, `sheila.liu` with weak passwords in `testusers.txt`

---

## Objective

- Identify valid usernames via error response timing
- Use a list of 50–100 common passwords
- Avoid account lockout thresholds
- Capture logs via:
  - Defender for Identity
  - Sentinel Sign-In logs
  - ADFS / IIS / LDAP logs (optional)

---

## Execution

### 1. Spray Entra ID

```o365spray --userlist testusers.txt --password 'Summer2025!' --verbose```

Focuses on /common/oauth2/token or legacy auth endpoints

May result in:

AADSTS50126: Invalid username or password
AADSTS50034: User not found

### 2. Spray On-Prem

```netexec smb 192.168.88.10 -u testusers.txt -p 'Summer2025!' --no-bruteforce```

Tests for SMB logon using known weak creds

## Detection Guidance
KQL Sample – Sentinel Sign-In Logs

```SigninLogs
| where ResultType == 50034 or ResultType == 50126
| summarize Attempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 15m)
| where Attempts > 5
```
Key Indicators:

- Many failed sign-ins from same IP
- Targeting multiple users with the same password
- Legacy authentication usage

## Defender Visibility
Source	Signal
Defender for Identity	NTLM Auth Failures, LDAP Spray
Microsoft Sentinel	SigninLogs anomalies
Entra Sign-In Risk	Multiple failed sign-ins, spray risk
IIS Logs (Optional)	Repeated /owa/auth.owa requests

## Screenshots (Insert Here)
o365spray terminal output

Sentinel SignInLogs query results

Entra ID Risk log (if available)

## Detection Validation
- Trigger spray from Kali box or VM
- Verify logs populate in Sentinel & Defender
- Tune detection queries
- Optional: Create an alert rule or Logic App for email/Slack alerting

## Obfuscation Variant
To evade basic detection signatures:

```o365spray --userlist testusers.txt --password 'Summer2025!' --user-agent 'Mozilla/5.0' --sleep 2```

## Navigation
← [Back to Lab Index](../README.md)
→ [Next: ](./kerberos/kerberoasting.md)