# Lab Setup Instructions
This lab simulates a hybrid Active Directory and Azure environment for offensive security testing, focused on:

- **On-prem Active Directory attacks (Kerberos, DCSync, delegation, relay)**
- **Entra ID (Azure AD) abuse (token replay, Conditional Access, MFA bypass)**
- **Hybrid identity paths (Azure AD Connect, sync attacks, pivot techniques)**

NOTE: This environment is for educational and authorized testing use only.

## Lab Overview
Topology

[Attacker VM] <---> [Internal Network]
                          |
        +-----------------+------------------+
        |                                    |
  [Windows Server 2019 DC]           [Azure AD + M365 Tenant]
        |                                    |
   AD DS, DNS, DHCP                     Synced with AAD Connect
        |
  [Workstation VM(s)]

## Components
Role	Hostname	Notes
Domain Controller	dc01	AD DS, DNS, optional Certificate Svc
Workstation	ws01, ws02	Windows 10/11 joined to AD
AAD Connect	aadconnect01	Syncs to Entra ID
Attacker VM (Kali)	attacker	For relays, phishing, token abuse
Azure/M365 Tenant	n/a	Cloud-based Entra ID tenant

## Requirements
Hypervisor: VMware Workstation, VirtualBox, Hyper-V, or Proxmox
Azure subscription (Pay-As-You-Go or sponsored/free trial)
Domain: internal.lab
Optional: Use Packer or Terraform for automation (coming soon)

## On-Prem Setup
### 1. Create Internal Network (host-only or NAT)
- Ensure the attacker and Windows boxes can all communicate privately.

### 2. Deploy DC (dc01)
- Windows Server 2019/2022/2025
- Promote to domain controller:
- Domain: internal.lab
- Install AD DS, DNS, DHCP (optional)
- Create OU structure, test users:
    - admin.internal.lab
    - svc-repl
    - helpdesk01
    - printer01

### 3. Workstations (ws01, ws02)
- Windows 10 or 11
- Join domain: internal.lab
- Test login with low-priv and admin users

### 4. Azure AD Connect Host (aadconnect01)
- Windows Server 2019
- Install Azure AD Connect:
    - Enable Password Hash Sync
    - Optionally enable Seamless SSO
    - Use a user-synced account with hybrid identity

## Azure Setup
### 1. Create Entra ID Tenant
- Go to: https://portal.azure.com
- Create new tenant or use free trial

### 2. Add Domain and Sync
- Add internal.lab or use .onmicrosoft.com
- Install AAD Connect on aadconnect01
- Sync selected OUs and users

### 3. Add Licenses (M365 E5 or Azure AD P2)
- Enable:
    - MFA
    - Conditional Access
    - Identity Protection (optional)
    - Logging (Log Analytics workspace + Defender for Cloud Apps)

## Attacker VM Setup
Use Kali Linux or Parrot OS:

### Install Common Tools

```
sudo apt update && sudo apt install -y \
  bloodhound \
  neo4j \
  evil-winrm \
  responder \
  ntlmrelayx \
  impacket-scripts \
  mitmproxy \
  python3-pip

pip3 install roadrecon aadinternals token-tactics```
### Optional tools:

- mimikatz (on Windows)
- Evilginx2 (for token theft/MFA bypass)


## Sample Attack Paths
- Kerberoasting → TGT replay → Admin access
- AAD Connect → MSOL extraction → Cloud pivot
- Token theft → Azure CLI → Graph abuse
- PetitPotam → NTLM Relay → LDAP privilege escalation
- MFA Fatigue → OAuth Consent Grant → Token Replay

## To Do / Coming Soon
- Terraform module for Azure baseline
- PowerShell DSC config for AD users/groups
- Sigma detection rules and KQL dashboards
- Local DNS poisoning scenarios
- Intune policy bypass lab

Navigation
[Back to Lab Index:](README.md)
[Jump to:](./attack-scenarios/)