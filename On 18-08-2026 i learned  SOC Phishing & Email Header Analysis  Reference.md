# SOC Phishing & Email Header Analysis: Complete Field Guide

> *A Practical Reference for Email Protocol Fundamentals, Header Parsing, Authentication (SPF/DKIM/DMARC), SOC Tier Playbooks, Gateway Evading Attacks, Threat Actor TTPs, and Incident Automation.*

---

##  Table of Contents

1. [Threat Landscape & Attack Vectors](#1-threat-landscape--attack-vectors)
   - [1.1 Why Phishing Dominates Initial Access](#11-why-phishing-dominates-initial-access)
   - [1.2 Threat Actor Categorization](#12-threat-actor-categorization)
2. [Email Protocol Fundamentals & Header Anatomy](#2-email-protocol-fundamentals--header-anatomy)
   - [2.1 SMTP Transaction Anatomy](#21-smtp-transaction-anatomy)
   - [2.2 Complete Email Header Breakdown](#22-complete-email-header-breakdown)
3. [Email Authentication Deep Dive (SPF, DKIM, DMARC)](#3-email-authentication-deep-dive-spf-dkim-dmarc)
   - [3.1 Sender Policy Framework (SPF)](#31-sender-policy-framework-spf)
   - [3.2 DomainKeys Identified Mail (DKIM)](#32-domainkeys-identified-mail-dkim)
   - [3.3 DMARC](#33-dmarc-domain-based-message-authentication-reporting-and-conformance)
4. [Tier-by-Tier SOC Workflows (L1, L2, L3)](#4-tier-by-tier-soc-workflows-l1-l2-l3)
   - [4.1 Tier 1 Analyst: Initial Triage Playbook](#41-tier-1-analyst-initial-triage-playbook)
   - [4.2 Tier 2 Analyst: Incident Response & Investigation Playbook](#42-tier-2-analyst-incident-response--investigation-playbook)
   - [4.3 Tier 3 Analyst: Detection Engineering & Campaign Analysis](#43-tier-3-analyst-detection-engineering--campaign-analysis)
5. [Enterprise SOC Operations & Log Analysis (KQL & SPL)](#5-enterprise-soc-operations--log-analysis-kql--spl)
   - [5.1 KQL Queries (Microsoft Sentinel / Defender XDR)](#51-kql-queries-microsoft-sentinel--defender-xdr)
   - [5.2 SPL Queries (Splunk Enterprise / ES)](#52-spl-queries-splunk-enterprise--es)
6. [Threat Intelligence Integration & IOC Pivoting](#6-threat-intelligence-integration--ioc-pivoting)
   - [6.1 IOC Extraction Matrix](#61-ioc-extraction-matrix)
   - [6.2 IOC Pivoting Methodology](#62-ioc-pivoting-methodology)
7. [Advanced Gateway Bypass Techniques](#7-advanced-gateway-bypass-techniques)
   - [7.1 HTML Smuggling](#71-html-smuggling)
   - [7.2 Container Format Evasion (ISO, VHD, Password-Protected ZIP)](#72-container-format-evadence-iso-vhd-password-protected-zip)
8. [URL Redirect Chains & Quishing Analysis](#8-url-redirect-chains--quishing-analysis)
   - [8.1 URL Redirect Chain Inspection](#81-url-redirect-chain-inspection)
   - [8.2 QR Code Phishing (Quishing) Triage](#82-qr-code-phishing-quishing-triage)
9. [OAuth and Consent Phishing Defense](#9-oauth-and-consent-phishing-defense)
   - [9.1 Attack Mechanism](#91-attack-mechanism)
   - [9.2 Incident Remediation Workflow (PowerShell)](#92-incident-remediation-workflow-powershell)
10. [Threat Actor TTP Matrix (APT29, FIN7, Scattered Spider, Lazarus, TA505)](#10-threat-actor-ttp-matrix)
11. [Email Body Deobfuscation Pipeline & Python Scripts](#11-email-body-deobfuscation-pipeline--python-scripts)
    - [11.1 Deobfuscation Script Toolkit](#111-deobfuscation-script-toolkit)
12. [Evidence Preservation, Legal Chain of Custody & SOAR Logic](#12-evidence-preservation-legal-chain-of-custody--soar-logic)
    - [12.1 Evidence Preservation Protocol](#121-evidence-preservation-protocol)
    - [12.2 SOAR Playbook Logic Flow](#122-soar-playbook-logic-flow)
13. [Tools & Reference Commands](#13-tools--reference-commands)
    - [13.1 Quick Tool Reference Table](#131-quick-tool-reference-table)
    - [13.2 Essential Terminal Commands for Email Analysis](#132-essential-terminal-commands-for-email-analysis)

---

## 1. Threat Landscape & Attack Vectors

### 1.1 Why Phishing Dominates Initial Access

Phishing remains the primary vector for initial access across enterprise environments for key reasons:

- **Human Layer Vulnerability:** Targets the human layer, bypassing perimeter network security controls.
- **Trusted Service Abuse:** Leverages user trust in recognized services (Microsoft 365, Google Workspace, DocuSign, SharePoint).
- **Phishing-as-a-Service (PaaS):** PaaS platforms democratize custom infrastructure deployment.
- **Authentication Gaps:** Widespread misconfigurations in email authentication (SPF, DKIM, DMARC).
- **AiTM Proxy Frameworks:** Adversary-in-the-Middle (AiTM) proxy frameworks effectively bypass standard Multi-Factor Authentication (MFA).

> [!IMPORTANT]
> Human involvement remains a factor in the majority of security breaches, with credential theft and malicious attachment delivery acting as primary objectives.

### 1.2 Threat Actor Categorization

| Category | Technical Sophistication | Infrastructure | Typical Groups / Profiles |
| :--- | :--- | :--- | :--- |
| **Commodity / Opportunistic** | Low | Free webmail, open SMTP relays | Script kiddies, basic spam botnets |
| **Cybercrime (Organized)** | Medium to High | Bulletproof hosting, compromised SMTP servers, AiTM proxies | FIN7, TA505, Scattered Spider |
| **Nation-State (APT)** | Advanced | Custom redirect networks, compromised cloud tenants, zero-day lures | APT29, Lazarus Group, APT28 |

---

## 2. Email Protocol Fundamentals & Header Anatomy

### 2.1 SMTP Transaction Anatomy

Every email is delivered via Simple Mail Transfer Protocol (SMTP). Analyzing header data requires understanding the distinct stages of an SMTP session.

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

#### Envelope Sender vs. Header From

- **Envelope Sender (`MAIL FROM` / Return-Path):** Used by mail transfer agents (MTAs) for bounce handling and routing error notifications. SPF validates the IP address sending on behalf of this domain.
- **Header From (`From:` header):** Displayed directly to the end-user inside mail clients (Outlook, Gmail). DMARC evaluates whether this domain matches the validated SPF or DKIM domain (alignment).

> [!WARNING]
> The discrepancy between the **Envelope Sender** and the **Header From** domain is the central vulnerability exploited in email spoofing.

### 2.2 Complete Email Header Breakdown

Below is an annotated sample of an unparsed raw email header:

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

- **`Received:`** Added sequentially by each MTA handling the message. Read bottom to top to trace the hop path from origin to destination. The bottom-most `Received:` header represents the original sending relay.
- **`Authentication-Results:`** Summary generated by the recipient's mail gateway evaluating SPF, DKIM, and DMARC checks.
- **`Return-Path:`** Address where non-delivery reports (NDRs) are directed. Matches the SMTP `MAIL FROM` envelope address.
- **`Reply-To:`** Address specified for user replies. If set differently than `From:`, responses will route to this external destination.
- **`Message-ID:`** Unique message identifier generated by the originating mail system. Check if the domain portion matches the sending server or `From:` address.
- **`X-Originating-IP:`** Client IP address submitting the email to the first outbound SMTP relay. Useful when the sender uses webmail or compromised relays.

---

## 3. Email Authentication Deep Dive (SPF, DKIM, DMARC)

### 3.1 Sender Policy Framework (SPF)

SPF (RFC 7208) allows a domain owner to declare which IP addresses and subnets are authorized to send email on behalf of their domain envelope sender (`MAIL FROM`).

#### Example SPF Record Syntax
```dns
v=spf1 ip4:192.0.2.0/24 include:_spf.google.com include:sendgrid.net -all
```

#### SPF Mechanisms and Qualifiers
- `ip4` / `ip6`: Explicit IP ranges authorized to send.
- `include`: Delegates authorization to another domain's SPF record.
- `a` / `mx`: Authorizes the IPs resolved by the domain's A or MX records.
- `-all` (Fail): Explicit hard fail. Reject mail from IPs not matched in the record.
- `~all` (Softfail): Accept mail but flag as suspicious/non-compliant.
- `?all` (Neutral): No explicit policy recommendation.

> [!NOTE]
> **The 10-DNS Lookup Limit:** SPF evaluations enforce a maximum limit of 10 recursive DNS lookups (`include`, `a`, `mx`, `ptr`, `exists`) to prevent Denial of Service (DoS) conditions on mail receivers. Exceeding 10 lookups triggers an SPF `PermError`, causing SPF evaluation to fail. Attackers sometimes leverage complex nested includes to force PermError conditions on legacy receivers.

### 3.2 DomainKeys Identified Mail (DKIM)

DKIM (RFC 6376) provides cryptographic proof that an email was authorized by the domain owner and that the header/body contents were not modified during transit.

#### How DKIM Signature Function Works
1. The sender calculates a cryptographic hash over selected headers (e.g., `From`, `To`, `Subject`, `Date`) and the message body hash (`bh`).
2. The sender encrypts this hash using their private key and attaches the result in the `DKIM-Signature` header field.
3. The recipient fetches the public key from DNS at `[selector]._domainkey.[domain]` and decrypts the signature to verify hash integrity.

```text
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  d=company.com; s=s2026;
  h=from:to:subject:date:message-id;
  bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
  b=dB/0P9...
```

- `d=`: Signing domain.
- `s=`: Selector name used to locate the DNS TXT record.
- `bh=`: Base64 hash of the canonicalized message body.
- `b=`: The digital signature covering both headers and body hash.

### 3.3 DMARC (Domain-based Message Authentication, Reporting, and Conformance)

DMARC (RFC 7489) ties SPF and DKIM checks directly to the visible `From:` header domain.

#### DMARC Alignment Principles
- **SPF Alignment:** The domain in the `From:` header must match (or be a subdomain of, under relaxed policy) the domain in the `MAIL FROM` (Return-Path) address.
- **DKIM Alignment:** The domain in the `From:` header must match the domain specified in the `d=` parameter of a valid DKIM signature.

> [!TIP]
> DMARC passes if **either** SPF alignment or DKIM alignment passes.

#### DMARC Policy Directives (`p=`)
- `p=none`: Monitoring mode. Reports are generated, but non-aligned messages are delivered normally.
- `p=quarantine`: Delivers non-aligned messages to the user's Spam/Junk folder.
- `p=reject`: Instructs the recipient MTA to reject non-aligned messages during the SMTP transaction.

```dns
v=DMARC1; p=reject; rua=mailto:dmarc-reports@company.com; ruf=mailto:dmarc-forensics@company.com; pct=100; adkim=r; aspf=r
```

#### Authentication Verification Matrix

| Sender Header (`From:`) | Envelope Sender (`Return-Path`) | SPF Result | DKIM Result (`d=`) | DMARC Evaluation | Action Under `p=reject` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `user@company.com` | `bounce@company.com` | PASS (Aligned) | PASS (`d=company.com`) | **PASS** | Deliver to Inbox |
| `user@company.com` | `bounce@evil.com` | PASS (Unaligned) | PASS (`d=company.com`) | **PASS** (via DKIM) | Deliver to Inbox |
| `user@company.com` | `bounce@evil.com` | PASS (Unaligned) | FAIL (`d=evil.com`) | **FAIL** | Reject / Quarantine |
| `user@company.com` | `bounce@company.com` | PASS (Aligned) | FAIL (No Sign) | **PASS** (via SPF) | Deliver to Inbox |

---

## 4. Tier-by-Tier SOC Workflows (L1, L2, L3)

### 4.1 Tier 1 Analyst: Initial Triage Playbook

#### Goal
Rapidly categorize suspicious emails, execute preliminary IOC enrichment, and determine initial disposition (False Positive, Benign Spam, Malicious Phishing).

#### Step-by-Step Execution Path
1. **Extract Headers and Payload:** Retrieve raw `.eml` or `.msg` file. Do not double-click or view HTML inline without disabling external image auto-loading.
2. **Evaluate Header Authentication:**
   - Verify SPF, DKIM, and DMARC status in `Authentication-Results`.
   - Check for `From:` vs. `Return-Path:` domain mismatches.
   - Compare `From:` vs. `Reply-To:` entries.
3. **Analyze Originating IP Infrastructure:**
   - Extract bottom `Received:` hop IP.
   - Query IP against reputation databases (AbuseIPDB, VirusTotal).
   - Verify if sender IP belongs to a known public cloud, VPN, residential proxy, or Tor exit node.
4. **Inspect Body Links and Attachments:**
   - Extract all embedded URLs using script/parsing tool. Defang links (`hxxps://`, `domain[.]com`).
   - Submit links to URL scanning engines (URLscan.io, VirusTotal). Inspect final rendered screenshots and DOM redirects.
   - For attachments, calculate SHA256 hash prior to sandbox execution. Check hashes against VirusTotal or internal SIEM data.
5. **Scope Verification:**
   - Query mail gateway or SIEM: Identify total internal mailboxes receiving emails with the same Subject line, Sender domain, or Attachment hash over the past 7 days.

### 4.2 Tier 2 Analyst: Incident Response & Investigation Playbook

#### Goal
Perform root-cause analysis, analyze payload mechanics, determine compromise status, and execute remediation across affected endpoints and mailboxes.

#### Investigation and Containment Workflow
1. **Analyze Advanced Evasion Mechanics:**
   - Inspect attachments for password protection, HTML smuggling, script obfuscation, or macro execution triggers.
   - Run suspicious binaries/scripts in an isolated sandbox (ANY.run, Hybrid Analysis). Track process trees (`cmd.exe` launching `powershell.exe`, wscript launching `mshta.exe`).
2. **Evaluate Potential Account Compromise:**
   - Check identity logs (Azure AD / Entra ID, Okta) for users who clicked phishing links or submitted credentials.
   - Filter sign-ins by timestamp, unusual location, risk score, client app, or impossible travel triggers.
3. **Execute Mail Gateway Purge:**
   - Initiate automated or administrative purge of all matching phishing instances across the tenant (e.g., via Microsoft Defender Hard Delete / Soft Delete).
4. **Remediate Compromised Accounts:**
   - Force password reset and terminate active user sessions.
   - Revoke existing OAuth app tokens and review recently added MFA authentication methods.
   - Search for newly created inbox rules (e.g., rules moving incoming messages to "RSS Feeds" or "Deleted Items" with keywords like `invoice`, `wire`, `phish`).

### 4.3 Tier 3 Analyst: Detection Engineering & Campaign Analysis

#### Goal
Reverse engineer complex attack vectors, analyze adversary infrastructure patterns, write custom SIEM/EDR detection rules, and hunt across enterprise logs.

#### Advanced Technical Tasks
1. **Phishing Kit & Infrastructure Deconstruction:**
   - Deobfuscate client-side JavaScript from phishing landing pages. Identify exfiltration webhooks, Telegram bot tokens, or C2 server backends.
   - Trace backend reverse proxy setups (e.g., Evilginx2 setups matching specific SSL certificates, JARM fingerprints, or custom HTTP headers).
2. **Detection Rule Development:**
   - Author Yara rules for malicious attachment detection.
   - Deploy KQL (Sentinel / Defender) and SPL (Splunk) queries targeting suspicious mail flow, anomalous sign-ins, and post-exploitation activity.
3. **Proactive Threat Hunting:**
   - Search for lookalike / typosquatted domain registrations using passive DNS data.
   - Monitor for unauthorized OAuth app authorizations matching permission scope abuse patterns across cloud environments.

---

## 5. Enterprise SOC Operations & Log Analysis (KQL & SPL)

### 5.1 KQL Queries (Microsoft Sentinel / Defender XDR)

#### Query 1: Detect Inbound Emails with DMARC Failures Targeting Internal Users
```kql
EmailEvents
| where Timestamp > ago(24h)
| where LatestDeliveryLocation == "Inbox" or LatestDeliveryLocation == "JunkFolder"
| where AuthenticationDetails has "dmarc=fail"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, LatestDeliveryLocation
| sort by Timestamp desc
```

#### Query 2: Identify Users Clicking Links in Flagged Malicious Emails
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

#### Query 3: Search for Inbox Rules Designed to Hide Exfiltration or Phishing Activity
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| extend RuleName = tostring(RawEventData.Parameters[0].Value)
| extend RuleConditions = tostring(RawEventData.Parameters)
| where RuleConditions has_any ("DeleteMessage", "MoveToDeletedItems", "MarkAsRead", "RSS Subscriptions", "Junk Email")
| project Timestamp, AccountUpn, IPAddress, RuleName, RuleConditions
```

### 5.2 SPL Queries (Splunk Enterprise / ES)

#### Query 1: Detect Sender Domain and Display Name Misalignment (Display Name Spoofing)
```spl
index=email_logs sourcetype="cisco:esa" OR sourcetype="proofpoint:pps"
| eval display_name_domain=mvindex(split(from_header, "@"), 1)
| eval envelope_domain=mvindex(split(return_path, "@"), 1)
| where display_name_domain != envelope_domain AND isnotnull(display_name_domain)
| stats count by src_ip, from_header, return_path, recipient, subject
| sort - count
```

#### Query 2: Aggregate Inbound Mail Volume by Sender IP to Spot High-Volume Outliers
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

## 6. Threat Intelligence Integration & IOC Pivoting

### 6.1 IOC Extraction Matrix

A single phishing message provides multiple pivot points for threat intelligence enrichment:

```text
EMAIL HEADER ARTIFACTS
├── Sender Originating IP (X-Originating-IP / Bottom Received Hop)
├── Envelope Sender Domain (Return-Path)
├── Header From Domain
├── DKIM Selector & Signing Domain
├── Message-ID Format & Domain
└── X-Mailer / User-Agent Header

EMAIL BODY & CONTENT ARTIFACTS
├── Raw & Unrolled Landing Page URLs
├── Intermediate Redirect Domains
├── Attachment SHA256 / MD5 Hashes
├── Embedded QR Code Decoded Payload
└── Embedded Base64 / Hex Encoded Scripts

ATTACHMENT METADATA ARTIFACTS
├── Author / Organization Name in Office Properties
├── Embedded VBA Macro / XLM Code Fingerprints
├── LNK File Arguments & Binary Paths
└── C2 Domains / IPs inside Dropper Payloads
```

### 6.2 IOC Pivoting Methodology

When an IOC is extracted, pivot across threat intelligence sources to unveil adversary infrastructure:

1. **Pivot on Sender IP:**
   - Query WHOIS and ASN data to determine host type (e.g., DigitalOcean vs. unknown residential ISP).
   - Query Passive DNS (SecurityTrails, VirusTotal) to find co-hosted domains on the same IP address.
   - Query Shodan / Censys for open ports, SSL certificate hashes, and JARM signatures matching known phishing kits.
2. **Pivot on Domain Name:**
   - Inspect domain registration date (WHOIS). Domains registered under 14 days ago represent higher risk.
   - Search Certificate Transparency logs (`crt.sh`) for recent SSL certificates issued for subdomains.
3. **Pivot on Attachment Hash:**
   - Query VirusTotal and Hybrid Analysis for execution reports, dropped files, and network communication indicators.

---

## 7. Advanced Gateway Bypass Techniques

### 7.1 HTML Smuggling

HTML smuggling embeds malicious payloads directly within an HTML attachment or HTML email body using Base64 encoding and JavaScript Blob objects. The payload is reconstructed locally inside the user's browser, bypassing standard network perimeter scanners and email gateway attachment filters.

#### How HTML Smuggling Executes
```html
<!DOCTYPE html>
<html>
<body>
<script>
  // Base64 encoded payload (e.g., ISO, ZIP, or Executable)
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
- Inspect email attachments for `<script>` tags containing `window.URL.createObjectURL`, `msSaveOrOpenBlob`, or large Base64 strings.
- Monitor endpoint activity for browser processes (`chrome.exe`, `msedge.exe`) writing disk image formats (`.iso`, `.vhd`, `.img`) or archive files directly to user Downloads folders.

### 7.2 Container Format Evasion (ISO, VHD, Password-Protected ZIP)

Adversaries wrap malicious scripts or executables inside disk images (`.iso`, `.vhd`) or encrypted archives to prevent email gateway static file inspection and bypass Mark-of-the-Web (MOTW) propagation.

#### Common Container Layout
```text
Invoice_Pack.iso
├── Invoice.lnk (Shortcut file disguised as PDF, points to hidden payload)
├── .hidden_folder/
│   ├── main_payload.exe (Renamed executable or DLL)
│   └── script.bat (Secondary loader)
```

#### Analysis Steps
- Mount ISO or VHD images inside a controlled Linux environment (`mount -o loop file.iso /mnt/analysis`).
- Inspect hidden directory contents using `ls -la` or `dir /a`.
- Verify file signatures using `file` command rather than relying on file extension names.

---

## 8. URL Redirect Chains & Quishing Analysis

### 8.1 URL Redirect Chain Inspection

Phishing links often utilize multi-hop redirect chains, open redirectors on trusted domains, or CDN platforms to conceal the final credential harvesting page.

#### Python Script for Unrolling URL Redirect Chains

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

Quishing replaces standard text URLs with embedded QR code images inside email bodies or PDF attachments. This evades text-based URL extractors in email gateways.

#### Command-Line Parsing Methodology
Extract and decode QR code payloads directly from saved image files using Linux command line tools:

```bash
# Install QR decoding utility
sudo apt-get install zbar-tools

# Extract decoded target URL from image
zbarimg -raw suspicious_qr_code.png
```

---

## 9. OAuth and Consent Phishing Defense

### 9.1 Attack Mechanism

OAuth consent phishing tricks users into granting permissions to a malicious third-party app registered in multi-tenant environments (e.g., Azure AD / Entra ID).

Rather than stealing password credentials, the adversary acquires delegated OAuth tokens (`refresh_token`, `access_token`), securing persistent API access to the victim's mailbox and cloud storage without triggering MFA prompts or password resets.

```text
Adversary creates Azure App Registration
        │
        ▼
Generates Authorization URL requesting high-risk scope permissions:
(Mail.ReadWrite, Files.ReadWrite.All, Offline_access)
        │
        ▼
Sends target user email with legitimate Microsoft login consent URL
        │
        ▼
User clicks, authenticates to legitimate Microsoft endpoint, and clicks "Accept"
        │
        ▼
Adversary application receives Authorization Code -> Exchanges for Access/Refresh Tokens
        │
        ▼
Adversary accesses victim mailbox data remotely via Microsoft Graph API
```

### 9.2 Incident Remediation Workflow (PowerShell)

Execute the following actions using Microsoft Graph PowerShell to revoke compromised OAuth permissions:

```powershell
# Connect to Microsoft Graph with Directory Administrator permissions
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All"

# 1. Identify and list delegated permissions granted for target user
$UserId = "target-user@company.com"
Get-MgUserOAuth2PermissionGrant -UserId $UserId | Format-Table Id, ClientId, ConsentType, Scope

# 2. Revoke specific malicious OAuth2 permission grant by ID
$GrantId = "MaliciousGrantIDString"
Remove-MgOAuth2PermissionGrant -OAuth2PermissionGrantId $GrantId

# 3. Revoke all active user sign-in sessions and refresh tokens
Revoke-MgUserSignInSession -UserId $UserId
```

---

## 10. Threat Actor TTP Matrix

Below is a technical comparison of email delivery techniques observed across major threat actor groups:

| Threat Actor Group | Target Sectors | Primary Lure Topics | Preferred Delivery Payload / Technique | Key Evasion Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **APT29** (Cozy Bear) | Defense, Government, NATO, Think Tanks | Diplomatic invites, policy updates, administrative notices | Shared links hosting HTML droppers (ENVYSCOUT), OAuth consent phish | Exploiting legitimate cloud services (OneDrive, Notion, Dropbox) |
| **FIN7** | Retail, Hospitality, Financial Services | Supplier complaints, fake resume submissions, SEC filings | Password-protected ISO/ZIP containers containing LNK files | Double extensions, heavy use of legitimate admin tools (PSExec, WMI) |
| **Scattered Spider** | Telecom, BPO, Technology, Retail | IT Helpdesk notifications, MFA reset alerts, SSO portals | AiTM proxy portals (Evilginx2), vishing combined with SMS/email links | Stealing active session cookies to bypass FIDO2 / Push MFA |
| **Lazarus Group** | Cryptocurrency, Defense, Fintech | High-paying job offers, technical interview assignments | PDF attachments with embedded links, malicious Word macros | Target tailoring via LinkedIn before sending email, custom DLL sideloading |
| **TA505** | Financial Services, Healthcare, Enterprise | Urgent invoice notifications, remittance advices | Excel attachments containing XLM (Excel 4.0) macros, HTML smuggling | Obfuscated macro code triggering secondary payload downloads |

---

## 11. Email Body Deobfuscation Pipeline & Python Scripts

### 11.1 Deobfuscation Script Toolkit

The following Python script accepts a raw `.eml` file, extracts header fields, decodes Base64/Quoted-Printable content, strips hidden CSS spans, and extracts defanged URLs.

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

## 12. Evidence Preservation, Legal Chain of Custody & SOAR Logic

### 12.1 Evidence Preservation Protocol

During phishing investigations, maintaining strict evidentiary integrity is mandatory for potential legal proceedings or regulatory reporting.

1. **Export Original Raw Message:** Save message in raw `.eml` or `.msg` format without altering header attributes.
2. **Generate Cryptographic Hashes Immediately:**
   ```bash
   sha256sum incident_sample.eml > hashes.txt
   md5sum incident_sample.eml >> hashes.txt
   ```
3. **Chain of Custody Documentation:** Record the following details in incident tracking records:
   - Source mailbox address and reporting time.
   - Analyst username performing extraction.
   - Storage location path (write-protected directory with restricted permissions).
   - Exact hash verification logs.

### 12.2 SOAR Playbook Logic Flow

Below is a structured representation of an automated email response playbook implemented in SOAR systems (e.g., Cortex XSOAR, Splunk SOAR, Sentinel Logic Apps):

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

## 13. Tools & Reference Commands

### 13.1 Quick Tool Reference Table

| Tool Category | Tool Name | Primary Purpose / Feature |
| :--- | :--- | :--- |
| **Header Analysis** | Google Admin Toolbox | Interactive visual email header hop parser |
| **Header Analysis** | MXToolbox Header Analyzer | Quick visual breakdown of SPF/DKIM/DMARC headers |
| **Reputation Check** | VirusTotal | Multi-engine file, hash, IP, and domain inspection |
| **Reputation Check** | AbuseIPDB | Community-driven IP abuse and spam reports |
| **Sandbox & Payload** | ANY.run | Interactive Windows malware execution environment |
| **Sandbox & Payload** | Hybrid Analysis | Free automated sandbox analysis powered by Falcon Sandbox |
| **Command Utilities** | `zbar-tools` | Command line QR code reading tool (`zbarimg`) |
| **Command Utilities** | `oletools` | Python suite for parsing MS Office files and macros (`olevba`) |

### 13.2 Essential Terminal Commands for Email Analysis

#### Extract All Headers from EML File (Python One-Liner)
```bash
python3 -c "import email, sys; msg=email.message_from_file(open(sys.argv[1])); print('\n'.join([f'{k}: {v}' for k,v in msg.items()]))" sample.eml
```

#### Extract VBA Macros from Suspicious Office Document
```bash
olevba -code-extract suspicious_doc.docm
```

#### Query SPF TXT Record for Domain via Dig
```bash
dig +short TXT company.com | grep "v=spf1"
```

#### Query DMARC TXT Record for Domain via Dig
```bash
dig +short TXT _dmarc.company.com
```

#### Query DKIM Selector Record via Dig
```bash
dig +short TXT s2026._domainkey.company.com
```
