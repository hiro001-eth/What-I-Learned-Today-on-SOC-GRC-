# SOC Phishing and Email Header Analysis

Personal research notes and technical reference covering email protocols, header analysis, SPF/DKIM/DMARC authentication, SOC triage playbooks, gateway bypass techniques, threat actor TTPs, and incident response automation.

---

## Table of Contents

1. [Threat Landscape and Attack Vectors](#1-threat-landscape-and-attack-vectors)
   - [1.1 Why Phishing Dominates Initial Access](#11-why-phishing-dominates-initial-access)
   - [1.2 Threat Actor Categorization](#12-threat-actor-categorization)
2. [Email Protocol Fundamentals and Header Structure](#2-email-protocol-fundamentals-and-header-structure)
   - [2.1 SMTP Transaction Flow](#21-smtp-transaction-flow)
   - [2.2 Email Header Breakdown](#22-email-header-breakdown)
3. [Email Authentication (SPF, DKIM, DMARC)](#3-email-authentication-spf-dkim-dmarc)
   - [3.1 Sender Policy Framework (SPF)](#31-sender-policy-framework-spf)
   - [3.2 DomainKeys Identified Mail (DKIM)](#32-domainkeys-identified-mail-dkim)
   - [3.3 DMARC](#33-dmarc)
4. [Tier-by-Tier SOC Workflows (L1, L2, L3)](#4-tier-by-tier-soc-workflows-l1-l2-l3)
   - [4.1 Tier 1 Analyst: Initial Triage Playbook](#41-tier-1-analyst-initial-triage-playbook)
   - [4.2 Tier 2 Analyst: Incident Response and Investigation](#42-tier-2-analyst-incident-response-and-investigation)
   - [4.3 Tier 3 Analyst: Detection Engineering and Campaign Analysis](#43-tier-3-analyst-detection-engineering-and-campaign-analysis)
5. [Enterprise Log Analysis (KQL and SPL)](#5-enterprise-log-analysis-kql-and-spl)
   - [5.1 KQL Queries (Microsoft Sentinel / Defender XDR)](#51-kql-queries-microsoft-sentinel--defender-xdr)
   - [5.2 SPL Queries (Splunk Enterprise)](#52-spl-queries-splunk-enterprise)
6. [Threat Intelligence Integration and IOC Pivoting](#6-threat-intelligence-integration-and-ioc-pivoting)
   - [6.1 IOC Extraction Matrix](#61-ioc-extraction-matrix)
   - [6.2 IOC Pivoting Methodology](#62-ioc-pivoting-methodology)
7. [Gateway Bypass Techniques](#7-gateway-bypass-techniques)
   - [7.1 HTML Smuggling](#71-html-smuggling)
   - [7.2 Container Format Evasion (ISO, VHD, Password-Protected ZIP)](#72-container-format-evasion-iso-vhd-password-protected-zip)
8. [URL Redirect Chains and Quishing Analysis](#8-url-redirect-chains-and-quishing-analysis)
   - [8.1 URL Redirect Chain Inspection](#81-url-redirect-chain-inspection)
   - [8.2 QR Code Phishing (Quishing) Triage](#82-qr-code-phishing-quishing-triage)
9. [OAuth and Consent Phishing Defense](#9-oauth-and-consent-phishing-defense)
   - [9.1 Attack Mechanism](#91-attack-mechanism)
   - [9.2 Incident Remediation Workflow (PowerShell)](#92-incident-remediation-workflow-powershell)
10. [Threat Actor TTP Matrix](#10-threat-actor-ttp-matrix)
11. [Email Body Deobfuscation Pipeline](#11-email-body-deobfuscation-pipeline)
    - [11.1 Deobfuscation Script](#111-deobfuscation-script)
12. [Evidence Preservation and SOAR Logic](#12-evidence-preservation-and-soar-logic)
    - [12.1 Evidence Preservation Protocol](#121-evidence-preservation-protocol)
    - [12.2 SOAR Playbook Logic Flow](#122-soar-playbook-logic-flow)
13. [Tools and Reference Commands](#13-tools-and-reference-commands)
    - [13.1 Tool Reference Table](#131-tool-reference-table)
    - [13.2 Terminal Commands for Email Analysis](#132-terminal-commands-for-email-analysis)

---

## 1. Threat Landscape and Attack Vectors

### 1.1 Why Phishing Dominates Initial Access

Phishing is the primary initial access vector in enterprise environments due to several factors:

- **Targeting Users:** Bypasses perimeter network security by targeting end users directly.
- **Abuse of Trusted Services:** Uses trusted platforms like Microsoft 365, Google Workspace, DocuSign, and SharePoint to trick recipients.
- **Phishing-as-a-Service (PaaS):** PaaS kits make setting up phishing infrastructure simple for attackers.
- **Email Auth Misconfigurations:** Weak or missing SPF, DKIM, and DMARC records allow spoofing.
- **AiTM Proxies:** Adversary-in-the-Middle reverse proxy toolkits bypass standard multi-factor authentication (MFA).

Note: User interaction remains central to credential theft and malware delivery in breach incidents.

### 1.2 Threat Actor Categorization

| Category | Technical Sophistication | Infrastructure | Typical Profiles |
| :--- | :--- | :--- | :--- |
| **Opportunistic** | Low | Free webmail, open SMTP relays | Script kiddies, basic spam botnets |
| **Cybercrime** | Medium to High | Bulletproof hosting, compromised SMTP servers, AiTM proxies | FIN7, TA505, Scattered Spider |
| **Nation-State (APT)** | Advanced | Custom redirect networks, compromised cloud tenants, zero-day lures | APT29, Lazarus Group, APT28 |

---

## 2. Email Protocol Fundamentals and Header Structure

### 2.1 SMTP Transaction Flow

Email is delivered via Simple Mail Transfer Protocol (SMTP). Header analysis requires understanding SMTP session commands.

```smtp
EHLO mail.attacker-domain.com
MAIL FROM: <bounce-handler@attacker-domain.com>
RCPT TO: <target-user@company.com>
DATA
From: "IT Support" <support@company.com>
To: <target-user@company.com>
Subject: Action Required: Password Reset
[Body Content]
.
QUIT
```

#### Envelope Sender vs Header From

- **Envelope Sender (`MAIL FROM` / Return-Path):** Used by mail transfer agents (MTAs) for bounce handling and routing errors. SPF validates the IP address against this domain.
- **Header From (`From:` header):** Shown directly to the user in mail clients (Outlook, Gmail). DMARC checks if this domain matches the SPF or DKIM domain.

Note: Misalignment between Envelope Sender (`MAIL FROM`) and Header From (`From:`) is the core mechanism used in email domain spoofing.

### 2.2 Email Header Breakdown

Annotated sample of an unparsed raw email header:

```http
Received: from mail.company.com (mail.company.com [192.0.2.10])
        by mx.company.com (Postfix) with ESMTPS id 4VxxxxxxZz
        for <target-user@company.com>; Mon, 18 Aug 2026 10:15:33 +0000
Received: from mail.evil-attacker.com (mail.evil-attacker.com [203.0.113.50])
        by mail.company.com (Inbound Gateway) with ESMTP id 3XyyyyyyAa
        for <target-user@company.com>; Mon, 18 Aug 2026 10:15:30 +0000
Authentication-Results: mx.company.com;
       dkim=fail (signature verification failed) header.i=@evil-attacker.com;
       spf=pass (sender IP 203.0.113.50 is authorized) smtp.mailfrom=evil-attacker.com;
       dmarc=fail (p=reject) header.from=company.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=evil-attacker.com; s=s1;
        h=From:To:Subject:Date:Message-ID; bh=d3b07384...; b=Kj9x...
Return-Path: <bounce-handler@evil-attacker.com>
From: "IT Service Desk" <support@company.com>
To: <target-user@company.com>
Reply-To: <phish-collector@external-domain.net>
Subject: Action Required: Password Reset
Date: Mon, 18 Aug 2026 10:15:28 +0000
Message-ID: <20260818101528.12345@mail.evil-attacker.com>
X-Originating-IP: [198.51.100.77]
X-Mailer: Custom-Phish-Framework-v2.1
```

#### Key Field Reference

- **`Received:`** Added sequentially by each MTA processing the message. Read bottom-to-top to trace the path from source to target. The bottom `Received:` header is the originating relay.
- **`Authentication-Results:`** Summary generated by the receiving gateway for SPF, DKIM, and DMARC checks.
- **`Return-Path:`** Address for non-delivery reports (NDRs). Matches the SMTP `MAIL FROM` address.
- **`Reply-To:`** Address for recipient replies. If different from `From:`, replies will be sent to this external mailbox.
- **`Message-ID:`** Unique identifier assigned by the sending mail server. Check if the domain matches the sending server or `From:` address.
- **`X-Originating-IP:`** Client IP address that sent the message to the first outbound SMTP relay. Useful when the sender uses webmail.

---

## 3. Email Authentication (SPF, DKIM, DMARC)

### 3.1 Sender Policy Framework (SPF)

SPF (RFC 7208) lets a domain owner publish a list of IP addresses and subnets permitted to send mail for their envelope sender domain (`MAIL FROM`).

#### Example SPF Record Syntax
```dns
v=spf1 ip4:192.0.2.0/24 include:_spf.google.com include:sendgrid.net -all
```

#### SPF Mechanisms and Qualifiers
- `ip4` / `ip6`: Authorized IP ranges.
- `include`: References another domain's SPF record.
- `a` / `mx`: Authorizes IPs resolved from A or MX records.
- `-all` (Fail): Hard fail. Rejects mail from unlisted IPs.
- `~all` (Softfail): Soft fail. Accepts mail but flags as untrusted.
- `?all` (Neutral): Neutral policy recommendation.

Note: SPF evaluations allow a maximum of 10 DNS lookups (`include`, `a`, `mx`, `ptr`, `exists`). Exceeding this limit causes an SPF `PermError`, failing the check.

### 3.2 DomainKeys Identified Mail (DKIM)

DKIM (RFC 6376) uses public-key cryptography to verify that mail was sent by the domain owner and wasn't altered in transit.

#### DKIM Verification Process
1. Sender hashes selected headers (`From`, `To`, `Subject`, `Date`) and the message body (`bh`).
2. Sender encrypts the hash with their private key and attaches the `DKIM-Signature` header.
3. Recipient retrieves the public key from DNS at `[selector]._domainkey.[domain]` to verify the signature.

```text
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  d=company.com; s=s2026;
  h=from:to:subject:date:message-id;
  bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
  b=dB/0P9...
```

- `d=`: Signing domain.
- `s=`: Selector name used for DNS lookup.
- `bh=`: Base64 body hash.
- `b=`: Digital signature covering headers and body hash.

### 3.3 DMARC

DMARC (RFC 7489) ties SPF and DKIM verification to the visible `From:` header domain.

#### DMARC Alignment Principles
- **SPF Alignment:** The `From:` header domain must match (or share a parent domain with) the `MAIL FROM` (Return-Path) address.
- **DKIM Alignment:** The `From:` header domain must match the `d=` domain in a valid DKIM signature.

DMARC passes if either SPF alignment or DKIM alignment passes.

#### DMARC Policy Directives (`p=`)
- `p=none`: Monitor only. Reports are collected; messages are delivered normally.
- `p=quarantine`: Delivers failed messages to Spam/Junk.
- `p=reject`: Rejects non-compliant messages during SMTP transaction.

```dns
v=DMARC1; p=reject; rua=mailto:dmarc-reports@company.com; ruf=mailto:dmarc-forensics@company.com; pct=100; adkim=r; aspf=r
```

#### Authentication Matrix

| Header From (`From:`) | Envelope Sender (`Return-Path`) | SPF Result | DKIM Result (`d=`) | DMARC Result | Action Under `p=reject` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `user@company.com` | `bounce@company.com` | PASS (Aligned) | PASS (`d=company.com`) | **PASS** | Inbox |
| `user@company.com` | `bounce@evil.com` | PASS (Unaligned) | PASS (`d=company.com`) | **PASS** (via DKIM) | Inbox |
| `user@company.com` | `bounce@evil.com` | PASS (Unaligned) | FAIL (`d=evil.com`) | **FAIL** | Reject / Quarantine |
| `user@company.com` | `bounce@company.com` | PASS (Aligned) | FAIL (No Sign) | **PASS** (via SPF) | Inbox |

---

## 4. Tier-by-Tier SOC Workflows (L1, L2, L3)

### 4.1 Tier 1 Analyst: Initial Triage Playbook

#### Objective
Categorize suspicious emails, perform initial IOC enrichment, and determine disposition (False Positive, Spam, Phishing).

#### Triage Steps
1. **Extract Headers and Payload:** Retrieve raw `.eml` or `.msg` file. Avoid rendering HTML inline without blocking external images.
2. **Check Authentication:**
   - Verify SPF, DKIM, and DMARC in `Authentication-Results`.
   - Compare `From:` vs `Return-Path:` domains.
   - Compare `From:` vs `Reply-To:` fields.
3. **Check Sender Infrastructure:**
   - Extract originating IP from the bottom `Received:` hop.
   - Look up IP reputation on AbuseIPDB and VirusTotal.
   - Check if IP maps to cloud providers, VPNs, residential proxies, or Tor exit nodes.
4. **Inspect Links and Attachments:**
   - Extract embedded URLs and defang them (`hxxps://`, `domain[.]com`).
   - Run links through URLscan.io and VirusTotal to check redirect chains and page snapshots.
   - Hash attachments (SHA256) before sandbox analysis. Query hashes in SIEM and VirusTotal.
5. **Scope Impact:**
   - Search mail gateway or SIEM for other mailboxes receiving messages with the same Subject, Sender domain, or Attachment hash in the last 7 days.

### 4.2 Tier 2 Analyst: Incident Response and Investigation

#### Objective
Investigate root cause, analyze payload behavior, verify potential compromise, and execute containment across endpoints and mailboxes.

#### Investigation and Containment Steps
1. **Payload Analysis:**
   - Check attachments for password protection, HTML smuggling, script obfuscation, or macros.
   - Run suspicious files in an isolated sandbox (ANY.run, Hybrid Analysis). Track process trees (e.g., `cmd.exe` calling `powershell.exe` or `mshta.exe`).
2. **Account Compromise Verification:**
   - Check identity logs (Entra ID, Okta) for users who interacted with phishing links.
   - Filter sign-in events by timestamp, location, risk level, client app, or impossible travel triggers.
3. **Tenant Purge:**
   - Remove matching phishing emails from all mailboxes across the organization.
4. **Account Remediation:**
   - Reset passwords and revoke active user sessions.
   - Revoke unauthorized OAuth application tokens and review MFA methods.
   - Check for malicious inbox rules (e.g., rules auto-deleting or auto-forwarding emails containing keywords like `invoice` or `wire`).

### 4.3 Tier 3 Analyst: Detection Engineering and Campaign Analysis

#### Objective
Analyze complex attack vectors, map attacker infrastructure, create custom SIEM/EDR detection rules, and hunt for active campaigns.

#### Advanced Tasks
1. **Phishing Kit Analysis:**
   - Deobfuscate client-side JavaScript on phishing landing pages to locate exfiltration webhooks, Telegram bot tokens, or C2 backends.
   - Trace reverse proxy setups (e.g., Evilginx2 setups matched by SSL certificates, JARM fingerprints, or custom HTTP headers).
2. **Detection Engineering:**
   - Write Yara rules for file attachment scanning.
   - Build KQL (Sentinel/Defender) and SPL (Splunk) queries for suspicious mail flow and credential access patterns.
3. **Threat Hunting:**
   - Monitor passive DNS for typosquatted domain registrations.
   - Hunt for unusual OAuth application consent patterns in cloud audit logs.

---

## 5. Enterprise Log Analysis (KQL and SPL)

### 5.1 KQL Queries (Microsoft Sentinel / Defender XDR)

#### Query 1: Detect Inbound Emails with DMARC Failures
```kql
EmailEvents
| where Timestamp > ago(24h)
| where LatestDeliveryLocation == "Inbox" or LatestDeliveryLocation == "JunkFolder"
| where AuthenticationDetails has "dmarc=fail"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, LatestDeliveryLocation
| sort by Timestamp desc
```

#### Query 2: Identify Users Clicking Links in Malicious Emails
```kql
EmailUrlInfo
| where Timestamp > ago(7d)
| join kind=inner (
    EmailEvents
    | where ThreatTypes has "Phish" or ThreatTypes has "Malware"
) on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | where ActionType == "ClickAllowed" or ActionType == "UserNavigated"
) on Url, NetworkMessageId
| project Timestamp, AccountUpn, Url, Subject, SenderFromAddress, IPAddress, ActionType
```

#### Query 3: Search for Inbox Rules Hiding Phishing or Exfiltration
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RuleName = tostring(RawEventData.Parameters[0].Value)
| extend RuleConditions = tostring(RawEventData.Parameters)
| where RuleConditions has_any ("DeleteMessage", "MoveToDeletedItems", "MarkAsRead", "RSS Subscriptions", "Junk Email")
| project Timestamp, AccountUpn, IPAddress, RuleName, RuleConditions
```

### 5.2 SPL Queries (Splunk Enterprise)

#### Query 1: Detect Sender Domain vs Display Name Misalignment
```spl
index=email_logs sourcetype="cisco:esa" OR sourcetype="proofpoint:pps"
| eval display_name_domain=mvindex(split(from_header, "@"), 1)
| eval envelope_domain=mvindex(split(return_path, "@"), 1)
| where display_name_domain != envelope_domain AND isnotnull(display_name_domain)
| stats count by src_ip, from_header, return_path, recipient, subject
| sort - count
```

#### Query 2: Aggregate Inbound Volume by Sender IP to Spot Anomalies
```spl
index=email_logs sourcetype="email:gateway"
| stats count as total_messages, 
        sum(eval(action="blocked")) as blocked_count, 
        sum(eval(action="delivered")) as delivered_count 
        by src_ip, sender_domain
| where total_messages > 50 AND delivered_count > 0
| eval block_ratio=(blocked_count/total_messages)*100
| where block_ratio < 20
| sort - total_messages
```

---

## 6. Threat Intelligence Integration and IOC Pivoting

### 6.1 IOC Extraction Matrix

A single phishing message provides multiple pivot points for analysis:

```text
EMAIL HEADER ARTIFACTS
├── Sender IP (X-Originating-IP / Bottom Received Hop)
├── Envelope Sender Domain (Return-Path)
├── Header From Domain
├── DKIM Selector and Signing Domain
├── Message-ID Format and Domain
└── X-Mailer / User-Agent Header

EMAIL BODY ARTIFACTS
├── Landing Page URLs
├── Intermediate Redirect Domains
├── Attachment SHA256 / MD5 Hashes
├── QR Code Decoded Content
└── Encoded Scripts (Base64 / Hex)

ATTACHMENT METADATA
├── Author / Org Name in Office Properties
├── Embedded VBA Macro / XLM Code
├── LNK File Arguments and Paths
└── C2 Domains / IPs in Dropper Payloads
```

### 6.2 IOC Pivoting Methodology

1. **Pivot on Sender IP:**
   - Query WHOIS and ASN data for hosting provider type (cloud host, residential ISP, dedicated server).
   - Query Passive DNS (SecurityTrails, VirusTotal) for co-hosted domains.
   - Query Shodan / Censys for open ports, SSL certificates, and JARM fingerprints.
2. **Pivot on Domain Name:**
   - Check domain creation date via WHOIS (domains under 14 days old carry higher risk).
   - Search Certificate Transparency logs (`crt.sh`) for subdomains.
3. **Pivot on Attachment Hash:**
   - Query VirusTotal and Hybrid Analysis for network callbacks and dropped files.

---

## 7. Gateway Bypass Techniques

### 7.1 HTML Smuggling

HTML smuggling encodes malicious payloads inside an HTML attachment or HTML email body using Base64 encoding and JavaScript Blob objects. The payload is assembled locally inside the recipient's browser, bypassing static gateway inspection.

#### Example Execution
```html
<!DOCTYPE html>
<html>
<body>
<script>
  // Base64 payload (ISO, ZIP, or Executable)
  var base64Payload = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAA...=";
  
  function base64ToArrayBuffer(base64) {
    var binaryString = window.atob(base64);
    var len = binaryString.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  var fileBuffer = base64ToArrayBuffer(base64Payload);
  var blob = new Blob([fileBuffer], {type: "application/octet-stream"});
  var fileName = "Invoice_Document.iso";

  var a = document.createElement("a");
  a.href = window.URL.createObjectURL(blob);
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
</script>
</body>
</html>
```

#### Detection Strategy
- Check HTML attachments for `<script>` blocks using `window.URL.createObjectURL`, `msSaveOrOpenBlob`, or large Base64 strings.
- Monitor endpoint activity for browser processes (`chrome.exe`, `msedge.exe`) writing disk image formats (`.iso`, `.vhd`, `.img`) directly to local Download folders.

### 7.2 Container Format Evasion (ISO, VHD, Password-Protected ZIP)

Attackers package malicious scripts or executables inside disk images (`.iso`, `.vhd`) or encrypted archives to avoid static file inspection and bypass Mark-of-the-Web (MOTW) checks.

#### Container Structure
```text
Invoice_Pack.iso
├── Invoice.lnk (Shortcut file disguised as PDF, points to hidden payload)
├── .hidden_folder/
│   ├── main_payload.exe (Renamed executable or DLL)
│   └── script.bat (Secondary loader)
```

#### Analysis Steps
- Mount ISO or VHD images in Linux (`mount -o loop file.iso /mnt/analysis`).
- Check hidden directories using `ls -la` or `dir /a`.
- Verify file types using the Linux `file` utility rather than trusting extensions.

---

## 8. URL Redirect Chains and Quishing Analysis

### 8.1 URL Redirect Chain Inspection

Phishing emails often use multi-hop redirect chains, open redirectors on trusted sites, or CDNs to obscure the final landing page.

#### Python Script for Unrolling Redirects

```python
#!/usr/bin/env python3
import requests
import sys

def trace_redirects(initial_url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    try:
        response = requests.get(initial_url, headers=headers, allow_redirects=True, timeout=10)
        print(f"[+] Initial Target: {initial_url}\n")
        
        for i, resp in enumerate(response.history, 1):
            print(f"Hop {i}: HTTP {resp.status_code} -> {resp.url}")
            if 'Location' in resp.headers:
                print(f"       Location Header: {resp.headers['Location']}")
                
        print(f"\n[+] Final Destination: HTTP {response.status_code} -> {response.url}")
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        trace_redirects(sys.argv[1])
    else:
        print("Usage: python3 trace_url.py <url>")
```

### 8.2 QR Code Phishing (Quishing) Triage

Quishing uses QR codes inside email bodies or PDF attachments instead of plain text URLs to bypass email gateway text scanners.

#### Decoding QR Codes
Extract and decode QR payloads from image files using command line utilities:

```bash
# Install QR decoding tool
sudo apt-get install zbar-tools

# Extract URL from image
zbarimg -raw suspicious_qr_code.png
```

---

## 9. OAuth and Consent Phishing Defense

### 9.1 Attack Mechanism

OAuth consent phishing tricks users into authorizing a malicious third-party app registered in cloud environments (such as Entra ID).

Instead of stealing passwords, the attacker obtains delegated OAuth tokens (`refresh_token`, `access_token`), granting persistent API access to the user's mailbox and cloud files without prompting for passwords or MFA.

```text
Attacker creates Azure App Registration
        │
        ▼
Generates consent URL with high-risk scopes:
(Mail.ReadWrite, Files.ReadWrite.All, Offline_access)
        │
        ▼
Sends target email with legitimate Microsoft login consent link
        │
        ▼
User logs into legitimate Microsoft page and clicks "Accept"
        │
        ▼
Attacker app receives Authorization Code -> Exchanges for Access/Refresh Tokens
        │
        ▼
Attacker accesses mailbox remotely via Microsoft Graph API
```

### 9.2 Incident Remediation Workflow (PowerShell)

Revoke compromised OAuth permissions using Microsoft Graph PowerShell:

```powershell
# Connect to Microsoft Graph with Directory Admin permissions
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

# 1. List delegated permission grants for target user
$UserId = "target-user@company.com"
Get-MgUserOAuth2PermissionGrant -UserId $UserId | Format-Table Id, ClientId, ConsentType, Scope

# 2. Revoke specific malicious OAuth2 permission grant by ID
$GrantId = "MaliciousGrantIDString"
Remove-MgOAuth2PermissionGrant -OAuth2PermissionGrantId $GrantId

# 3. Revoke active user sign-in sessions and refresh tokens
Revoke-MgUserSignInSession -UserId $UserId
```

---

## 10. Threat Actor TTP Matrix

Comparison of email delivery techniques used by active threat actor groups:

| Threat Actor Group | Target Sectors | Primary Lures | Delivery Method | Key Evasion Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **APT29** (Cozy Bear) | Defense, Government, NATO, Think Tanks | Diplomatic invites, policy updates | Shared links hosting HTML droppers (ENVYSCOUT), OAuth consent phish | Exploiting legitimate cloud services (OneDrive, Notion, Dropbox) |
| **FIN7** | Retail, Hospitality, Financial Services | Supplier complaints, fake resumes, SEC filings | Password-protected ISO/ZIP files containing LNK shortcuts | Double extensions, legitimate admin binaries (PSExec, WMI) |
| **Scattered Spider** | Telecom, BPO, Technology, Retail | Helpdesk notifications, MFA alerts, SSO portals | AiTM proxy portals (Evilginx2), vishing with SMS/email links | Stealing session cookies to bypass MFA |
| **Lazarus Group** | Cryptocurrency, Defense, Fintech | High-paying job offers, technical assignments | PDF attachments with embedded links, malicious Word macros | Target research via LinkedIn, custom DLL sideloading |
| **TA505** | Financial Services, Healthcare, Enterprise | Urgent invoice notifications, remittance notices | Excel files with XLM (Excel 4.0) macros, HTML smuggling | Obfuscated macro code downloading secondary payloads |

---

## 11. Email Body Deobfuscation Pipeline

### 11.1 Deobfuscation Script

Python script to parse raw `.eml` files, extract headers, decode Base64/Quoted-Printable content, strip hidden CSS spans, and output defanged URLs.

```python
#!/usr/bin/env python3
import email
from email import policy
import re
from bs4 import BeautifulSoup
import sys

def parse_and_deobfuscate(eml_path):
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    print("=" * 60)
    print("EMAIL HEADER SUMMARY")
    print("=" * 60)
    print(f"From: {msg.get('From')}")
    print(f"To: {msg.get('To')}")
    print(f"Subject: {msg.get('Subject')}")
    print(f"Date: {msg.get('Date')}")
    print(f"Return-Path: {msg.get('Return-Path')}")
    print(f"Authentication-Results: {msg.get('Authentication-Results')}\n")

    body_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/html", "text/plain"]:
                payload = part.get_payload(decode=True)
                if payload:
                    body_content += payload.decode('utf-8', errors='ignore')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_content = payload.decode('utf-8', errors='ignore')

    # Parse HTML structure and strip hidden elements
    soup = BeautifulSoup(body_content, 'html.parser')
    
    # Remove CSS hidden elements designed to confuse text scanners
    for hidden in soup.find_all(style=re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden', re.IGNORECASE)):
        hidden.decompose()

    clean_text = soup.get_text(separator=' ')
    
    # Extract URLs
    raw_urls = re.findall(r'https?://[^\s<>"]+', body_content)
    unique_urls = set(raw_urls)

    print("=" * 60)
    print("EXTRACTED AND DEFANGED URLS")
    print("=" * 60)
    for url in unique_urls:
        defanged = url.replace('http', 'hxxp').replace('.', '[.]')
        print(f"[+] {defanged}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_and_deobfuscate(sys.argv[1])
    else:
        print("Usage: python3 deobfuscate_email.py <file.eml>")
```

---

## 12. Evidence Preservation and SOAR Logic

### 12.1 Evidence Preservation Protocol

To preserve evidence integrity for legal or regulatory reporting during phishing investigations:

1. **Export Raw Message:** Save original message as `.eml` or `.msg` format without modifying header properties.
2. **Generate Cryptographic Hashes:**
   ```bash
   sha256sum incident_sample.eml > hashes.txt
   md5sum incident_sample.eml >> hashes.txt
   ```
3. **Chain of Custody Record:** Log the following details in incident tracking:
   - Source mailbox address and timestamp.
   - Username of analyst performing extraction.
   - Restricted storage path.
   - Hash verification log.

### 12.2 SOAR Playbook Logic Flow

Overview of automated email incident response workflow in SOAR systems:

```text
[TRIGGER: User Suspicious Email Report / SEG Alert]
                    │
                    ▼
[PHASE 1: AUTOMATED DATA EXTRACTION & ENRICHMENT]
├── Parse EML -> Extract Sender IP, Sender Domain, URLs, Attachment Hashes
├── Check Gateway Logs -> Count total internal mailboxes receiving same message
├── Query VirusTotal / AbuseIPDB for IP & Domain Reputation Score
└── Query URLscan API -> Retrieve screenshot & rendered DOM links
                    │
                    ▼
[PHASE 2: DECISION GATE & VERDICT RATING]
├── IF Auth (DMARC) == FAIL AND VT IP Score > 10 AND URL Score == Malicious:
│   └── VERDICT = HIGH CONFIDENCE PHISHING
├── ELSE IF VT Score == 0 AND Auth == PASS AND Internal Sender:
│   └── VERDICT = BENIGN / FALSE POSITIVE
└── ELSE:
    └── VERDICT = SUSPICIOUS (Escalate to Tier 2 Human Review)
                    │
                    ▼
[PHASE 3: AUTOMATED REMEDIATION ACTIONS (If Malicious)]
├── Hard delete email instance from all target mailboxes via API
├── Block Sender Domain & Originating IP at Email Gateway
├── Block URL destinations at Proxy / Web Security Gateway
├── Force password reset & revoke sessions if user clicked link
└── Update ticket status & notify reporting user via email
```

---

## 13. Tools and Reference Commands

### 13.1 Tool Reference Table

| Tool Category | Tool Name | Purpose |
| :--- | :--- | :--- |
| **Header Analysis** | Google Admin Toolbox | Email header hop parser |
| **Header Analysis** | MXToolbox Header Analyzer | Breakdown of SPF/DKIM/DMARC headers |
| **Reputation Check** | VirusTotal | File, hash, IP, and domain scanner |
| **Reputation Check** | AbuseIPDB | IP abuse and spam reports |
| **Sandbox Analysis** | ANY.run | Interactive malware sandbox |
| **Sandbox Analysis** | Hybrid Analysis | Automated malware sandbox |
| **Command Utilities** | `zbar-tools` | Command line QR code decoder (`zbarimg`) |
| **Command Utilities** | `oletools` | MS Office macro parser (`olevba`) |

### 13.2 Terminal Commands for Email Analysis

#### Extract All Headers from EML File
```bash
python3 -c "import email, sys; msg=email.message_from_file(open(sys.argv[1])); print('\n'.join([f'{k}: {v}' for k,v in msg.items()]))" sample.eml
```

#### Extract VBA Macros from Office Document
```bash
olevba -code-extract suspicious_doc.docm
```

#### Query SPF TXT Record via Dig
```bash
dig +short TXT company.com | grep "v=spf1"
```

#### Query DMARC TXT Record via Dig
```bash
dig +short TXT _dmarc.company.com
```

#### Query DKIM Selector Record via Dig
```bash
dig +short TXT s2026._domainkey.company.com
```
