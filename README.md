# Hybrid AD + Entra ID Lab

This lab simulates real-world initial access and privilege escalation attacks in hybrid Active Directory / Entra ID environments, focused on regulated sectors like healthcare and critical infrastructure.

## Focus Areas
- Password spraying and account discovery
- Kerberoasting and delegation abuse
- DC Sync attacks with overprivileged users
- Entra ID MFA bypass & Conditional Access abuse
- Purple team detection with KQL and Sigma

## MITRE Coverage
- TA0001: Initial Access
- TA0003: Persistence
- TA0006: Credential Access
- TA0008: Lateral Movement

## Lab Setup
The environment includes:
- 1 Domain Controller (Windows Server 2025)
- 1 Entra ID-joined Windows 11 workstation
- 1 Hybrid Azure AD connector (Azure AD Connect)
- Defender for Identity + Sentinel (Optional)

[Lab Setup Instructions →](lab-setup/)

## Attack Scenarios
- [Password Spray](attack-scenarios/password-spray/)
- [Kerberoasting](attack-scenarios/kerberos-delegation/)
- [DC Sync Misuse](attack-scenarios/dcsync/)
- [Entra MFA Bypass](attack-scenarios/azure-mfa-bypass/)

## Detection Logic
- KQL queries (Sentinel / Defender)
- Sigma rules for EDR/SIEM platforms
- Visibility gaps and tuning notes

[Detection Coverage →](detection/)

---

> 💡 This project is intended for educational and research purposes only. All simulated attacks are executed in isolated lab environments.

## Contributions Welcome
Suggestions, improvements, or PRs are appreciated!
