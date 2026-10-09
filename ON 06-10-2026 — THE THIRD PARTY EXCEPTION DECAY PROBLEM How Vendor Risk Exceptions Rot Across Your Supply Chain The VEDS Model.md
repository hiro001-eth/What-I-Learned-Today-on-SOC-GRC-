================================================================================
ON 06-10-2026 — THE THIRD-PARTY EXCEPTION DECAY PROBLEM
How Vendor Risk Exceptions Rot Across Your Supply Chain — The VEDS Model

Author  : hiro001-eth (Manjil Katuwal)
Series  : What-I-Learned-Today-on-SOC-GRC
Version : 1.0 (Research Paper)
Paper   : 14 of the series
Prereqs : Papers 8 (Backdoors), 9 (ELDM), 10 (IR-GRC Loop), 12 (UPE), 13 (SAVS)
Date    : 2026-10-06
================================================================================

--------------------------------------------------------------------------------
ABSTRACT
--------------------------------------------------------------------------------
Every paper in this series has examined exception decay inside one boundary:
the organization's own governance perimeter. The risk register held the
exception. The SOC held the detection gap. The GRC officer held the audit
evidence. The decay happened inside the house.

This paper crosses the boundary.

When your organization accepts a vendor's security posture — their SOC 2 Type II
certification, their ISO 27001 certificate, their penetration test results, their
contractual security commitments — you are not receiving security. You are
receiving an assertion about security at a point in time from an entity whose
internal decay you cannot observe. That assertion expires. The contract drifts
from the threat landscape. The certification ages from the controls it certified.
The telemetry gap widens because you cannot instrument what you do not own.

You are accepting a vendor's exceptions on faith — and those exceptions decay
by the same four mechanisms the ELDM identified, accelerated by the additional
variable that you cannot see the decay happening.

We introduce the Vendor Exception Decay Score (VEDS) — an extension of EDS
(Paper 9) across the third-party boundary. VEDS has five components where EDS
had four, because vendor exceptions introduce a fifth decay mechanism that does
not exist for internal exceptions: Trust Opacity, the systematic inability of
the accepting organization to observe the vendor's actual security posture.

We derive the Vendor Exception Tree (VET) — the attack path model that shows
how an attacker chains through a vendor's decayed exception into the accepting
organization, through multiple tiers of the supply chain if the vendor has its
own vendors. We demonstrate that every EDS = 0 exception in a vendor's estate
is a potential EDS = 0 exception in your estate, propagated through the trust
relationship the contract created.

We map VEDS to the three regulatory frameworks that now make vendor decay a
board-level event: DORA's third-party ICT risk management requirements, NIS2's
supply chain security obligations, and ISO 27001:2022's substantially expanded
controls 5.19 through 5.22. We provide the contract language, the audit
procedure, the SIEM detection queries, and the closed-loop update to the
IR-GRC channels from Paper 10.

The central claim: your vendor's ELDM score is your risk. You just cannot
measure it because you are on the wrong side of the boundary. VEDS is the
formula that makes the invisible decay measurable from the outside.

CENTRAL FORMULA:
  VEDS(v,t) = CD(v,t) × AD(v,t) × TD(v,t) × OR(v,t) × TO(v,t)

Where VEDS = 1.0 means all five decay mechanisms are healthy for this vendor
relationship and VEDS = 0.0 means the vendor relationship has decayed to the
point where it constitutes an active attack surface in the accepting organization's
supply chain.

Keywords: third-party risk, vendor risk, supply chain security, VEDS, DORA,
NIS2, ISO 27001:2022, SOC 2, exception decay, attack tree, telemetry gap,
attestation drift, contract drift, TPRM, vendor exception, fourth-party risk,
vendor incident, closed loop, IR-GRC, trust opacity

--------------------------------------------------------------------------------
SECTION 1 — WHY THE BOUNDARY MATTERS AND WHY IT MAKES EVERYTHING WORSE
--------------------------------------------------------------------------------

1.1 THE ASSUMPTION EVERY PREVIOUS PAPER MADE

Papers 8 through 13 of this series examined security exception decay with one
implicit assumption: that the organization can, in principle, observe the decay.

The ELDM (Paper 9) described four drift mechanisms. Every one of them produces
artifacts that are observable if the organization looks:
  Scope drift   → phantom assets appear in the asset inventory
  Temporal drift → expiry dates are readable in the exception register
  Ownership drift → HR directory shows the custodian has departed
  Detection drift → SIEM shows the compensation rule has gone silent

These artifacts require the organization to look in the right places at the
right time. They are not automatically surfaced. But they are in principle
observable — the data exists in systems the organization owns and operates.

Vendor exceptions do not have this property.

When your organization enters a contractual relationship with a vendor who
processes your data, accesses your systems, or provides services that sit
in your security chain, you become dependent on that vendor's security posture.
But the vendor's security posture is not in any system you own. It is in:
  The vendor's internal exception register (which you cannot read)
  The vendor's SIEM (which you cannot query)
  The vendor's asset inventory (which you cannot audit)
  The vendor's HR directory (which you cannot check for custodian departures)
  The vendor's GRC platform (which you cannot access)

You receive periodic assertions about this posture: a SOC 2 report once or twice
a year, an ISO 27001 certificate that is valid for three years, a security
questionnaire response that reflects the vendor's state of mind on the day it
was completed, a penetration test report that describes the environment as it
existed when the tester was in it.

Between those assertions, the vendor's environment continues to operate. Their
exceptions continue to decay. Their EDS scores continue to fall. And you cannot
see any of it.

1.2 THE STRUCTURAL ADVANTAGE THIS GIVES AN ATTACKER

An attacker targeting your organization evaluates the attack surface holistically.
Your own perimeter has defenses you have invested in. Your SIEM watches your
assets. Your EDR covers your endpoints. Your GRC exceptions are at least in a
register that could be reviewed.

Your vendors have perimeters they have invested in — but typically less than
yours, because vendor security investment scales with vendor size and revenue,
and most of your vendors are smaller than you. Their SIEM may watch fewer assets.
Their EDR may have lower coverage. Their GRC exceptions may be less rigorously
managed.

And you have given those vendors something extraordinarily valuable: a trust
relationship into your environment. A valid VPN credential. An API key with
scope into your customer data. An identity in your Azure AD tenant. A service
account with access to your file servers. An SFTP credential to your payment
processing pipeline.

The attacker's decision: attack you directly (defended environment, high cost)
or attack your vendor (less defended, lower cost) and then walk the trust
relationship into you (already established, zero additional authentication
required).

This is not a theoretical attack pattern. It is the documented pattern of every
major supply chain breach in the last decade:

  SolarWinds (2020): Compromise of SolarWinds build pipeline → malicious update
    distributed to 18,000+ customers → attackers walked into customer environments
    using the legitimate SolarWinds Orion trust relationship.

  Kaseya VSA (2021): Compromise of Kaseya's MSP platform → REvil ransomware
    deployed to 60+ MSPs → ransomware propagated to MSP customers through the
    management trust relationship.

  Okta (2022): Compromise of Okta's support system → access to customer tenants
    through the support trust relationship → Twilio, Cloudflare, and 300+ customers
    affected.

  3CX (2023): Compromise of 3CX's software supply chain → malicious update to
    3CX desktop client → deployed in customer environments through the update trust
    relationship.

  MOVEit (2023): Zero-day in MOVEit file transfer software → Cl0p ransomware group
    compromised MOVEit installations at 2,500+ organizations → data exfiltrated
    through the file transfer trust relationship.

In each case: the attacker did not break through the victim organization's
defenses. They walked through a door the organization had opened and handed
a key to a vendor they trusted.

1.3 THE SPECIFIC DECAY PROBLEM FOR VENDOR RELATIONSHIPS

Vendor relationships age in a way that internal security configurations also age,
but with an additional dimension. An internal configuration that was correct when
deployed can become incorrect as the threat landscape changes. A vendor relationship
that was appropriate when contracted can become inappropriate as:

  THE VENDOR'S SECURITY POSTURE DECAYS:
    Their exceptions accumulate. Their certifications age past the last audit.
    Their security team churns. Their controls drift from their documentation.
    This is the ELDM happening inside the vendor — but you cannot observe it.

  THE TRUST SCOPE EXPANDS WITHOUT RE-ASSESSMENT:
    The vendor was initially contracted for one function with one access path.
    Over time, additional functions were added, additional access was granted,
    the vendor became embedded deeper in your operations — but each addition
    was a routine operational decision, not a security re-assessment. The access
    the vendor has in 2026 was never collectively assessed against your current
    risk appetite.

  THE THREAT LANDSCAPE CHANGES AROUND THE RELATIONSHIP:
    The vendor's access was assessed as low-risk in 2021 because the techniques
    that could exploit it were not yet in common use. By 2026, those techniques
    are documented, tooled, and actively deployed by multiple threat actor groups.
    The relationship has the same access profile. The risk has multiplied.

  THE REGULATORY ENVIRONMENT CHANGES AROUND THE RELATIONSHIP:
    DORA, NIS2, and AI Act impose new requirements on vendor relationships that
    did not exist when the contract was signed. The contract does not contain
    the right provisions. The audit rights do not cover the right scope. The
    notification requirements are not defined. The relationship is non-compliant
    with frameworks that did not exist when it was established.

All four of these decay mechanisms are external to the vendor — they are about
the relationship between the accepting organization and the vendor, not about
the vendor's internal controls. They operate in addition to the vendor's own
internal ELDM decay. The total decay is compounded.

--------------------------------------------------------------------------------
SECTION 2 — THE FIVE DECAY MECHANISMS OF VENDOR EXCEPTIONS
--------------------------------------------------------------------------------

The ELDM identified four internal decay mechanisms: Scope, Temporal, Ownership,
and Detection. Vendor exceptions exhibit all four — but operating through the
contract and the certification rather than through internal governance documents
— plus a fifth mechanism that has no internal equivalent.

--------------------------------------------------------------------------------
2.1 CONTRACT DRIFT (CD) — The Scope Mechanism for Vendor Relationships
--------------------------------------------------------------------------------

DEFINITION:
Contract Drift measures the degree to which the access, processing scope,
and security obligations documented in the current contract match the actual
operational relationship between the organization and the vendor.

THE MECHANISM:
When a vendor contract is signed, it describes:
  - What data the vendor can access
  - What systems the vendor can reach
  - What security standards the vendor must maintain
  - What the vendor can and cannot do with the data
  - What happens when the vendor has a security incident

Between contract signing and the present, the actual relationship has evolved:
  New use cases emerged that required new data access → granted operationally,
    not contractually. The contract says the vendor accesses customer name and
    email. The current reality: they also access transaction history and device
    fingerprints, added 18 months ago when a new integration was built.
    
  Old use cases were terminated but access was not revoked → the vendor's
    technical access includes credentials and API keys for functions they no
    longer perform. The credentials remain active. The contract does not describe
    them because they predate the current contract version.
    
  The security standards clause references a specific framework version that
    has since been superseded → the contract requires "NIST CSF compliance"
    which has been updated (CSF 2.0, released 2024) adding the GOVERN function.
    The vendor's SOC 2 report assesses against NIST CSF 1.1. The contract
    technically requires something different from what the certification covers.
    
  The incident notification clause specifies a timeframe that predates DORA
    and NIS2 → the contract requires notification "within a reasonable time"
    (pre-DORA boilerplate). DORA Art. 19 requires ICT incident notification
    within 4 hours for major incidents. "Reasonable time" is not 4 hours.
    The contract creates a compliance gap the moment DORA applies.

CONTRACT DRIFT FORMULA:
  CD(v,t) = (aligned_contract_terms / total_operational_terms) ×
             (1 - (days_since_contract_review / review_SLA_days))

Where:
  aligned_contract_terms = number of operational realities correctly described
                            in the current contract
  total_operational_terms = total number of material operational facts
                             (access paths, data categories, security obligations)
  days_since_contract_review = elapsed since last formal contract security review
  review_SLA_days = required review cadence (recommended: 365 days)

CONTRACT DRIFT AUDIT PROCEDURE:

  STEP 1 — OPERATIONAL REALITY MAP (2 hours per vendor):
    Pull all current technical access:
      Active credentials (API keys, service accounts, VPN accounts)
      OAuth grants held by vendor applications (Paper 11 territory)
      Network firewall rules with vendor IP ranges as source
      Cloud IAM role assignments with vendor principal ARNs
    
    Pull all current data flows:
      Data shared with vendor (from data flow maps or DLP logs)
      Data processed by vendor on organization's behalf
      Data the vendor creates that flows back into the organization
    
    This is the ACTUAL scope of the relationship.

  STEP 2 — CONTRACT MAPPING:
    For each item in the operational reality map: is it explicitly described
    in the current contract (or DPA, or MSA, or SOW)?
    
    Aligned: operational reality matches contract description
    Underdescribed: operational reality broader than contract description
    Overdescribed: contract describes something that no longer happens
    Conflicting: contract description inconsistent with operational reality

  STEP 3 — GAP QUANTIFICATION:
    Compute CD(v,t) from the aligned/total ratio and the time since last review.
    
    Findings:
    CD < 0.5: Contract Drift finding — requires contract remediation before
              next renewal AND immediate access review for underdescribed items
    CD < 0.3: Critical finding — the contract no longer accurately describes
              the relationship. Regulatory exposure for undescribed processing
              (GDPR Art. 28 applies to all processing, not just contracted processing)

QUERY — VENDOR ACCESS NOT IN CONTRACT REGISTRY (SQL):

  SELECT
      a.credential_id,
      a.vendor_name,
      a.credential_type,
      a.access_scope,
      a.created_date,
      DATEDIFF(day, a.created_date, GETDATE()) AS days_active,
      c.contract_id,
      c.documented_access_scope,
      c.contract_expiry
  FROM vendor_credentials a
  LEFT JOIN vendor_contracts c
      ON a.vendor_name = c.vendor_name
      AND a.access_scope LIKE CONCAT('%', c.documented_access_scope, '%')
  WHERE
      c.contract_id IS NULL                               -- no matching contract
      OR c.contract_expiry < GETDATE()                    -- expired contract
      OR DATEDIFF(day, c.last_reviewed, GETDATE()) > 365  -- stale review
  ORDER BY days_active DESC

OUTPUT: Every vendor credential that is either undocumented in any contract,
covered by an expired contract, or covered by a contract not reviewed in a year.
Each row is a Contract Drift finding requiring immediate attention.

--------------------------------------------------------------------------------
2.2 ATTESTATION DRIFT (AD) — The Temporal Mechanism for Vendor Relationships
--------------------------------------------------------------------------------

DEFINITION:
Attestation Drift measures how much of the vendor's security posture is covered
by current, scope-accurate, recently validated security attestations — and how
much has aged beyond the point where the attestation provides meaningful assurance.

This is the vendor equivalent of the ELDM's AL_n (Authorization Lag, normalized)
component. For internal exceptions, authorization lag measures how long the
exception has operated beyond its expiry date. For vendor relationships,
attestation drift measures how far the security certification has aged from
the audit period that produced it.

THE THREE ATTESTATION TYPES AND THEIR DECAY RATES:

TYPE 1 — SOC 2 TYPE II REPORT:
  Issued: covers a specific audit period (typically 6-12 months)
  Frequency: typically annual (one report per year)
  Validity period: typically 12 months from report date
  
  Decay profile:
    Month 0:   Report issued. Covers audit period that ended ~2 months prior.
               Actual coverage lag at issuance: ~2 months.
    Month 6:   Report is 6 months old. Controls it assessed are 8 months old.
               Organizational changes in that 8 months are not reflected.
    Month 12:  Report is 12 months old. Controls it assessed are 14 months old.
               Typical renewal point. Many organizations accept reports up to
               18 months old — at which point the assessed controls may be
               2 years old.
    Month 18+: Standard "stale SOC 2" situation. The report is still presented
               as evidence. It describes a 2-year-old snapshot of controls.

  THE CRITICAL LIMITATION OF SOC 2 TYPE II THAT NOBODY EXPLAINS CLEARLY:
  
  A SOC 2 Type II report says: during the audit period, the described controls
  were in place and operating effectively, as tested by the auditor's sampling.
  
  It does NOT say:
    - That every control the vendor has was tested (auditors test a sample)
    - That the controls remain in place after the audit period ended
    - That the controls are effective against current threats (not just against
      the threats that defined the control criteria when the trust service
      criteria were written)
    - That controls outside the defined trust service categories are adequate
    - That the vendor's controls cover your specific data or processing activity
      (the report covers the vendor's general environment, not your specific tenant)
  
  In ELDM terms: a SOC 2 Type II report has CC at the audit completion date.
  After that date, CC decays. The report does not decay — the report is a fixed
  document — but the controls the report describes have been continuing to operate
  in an environment that continues to change. The report's accuracy as a
  description of the current state degrades every day after the audit period ends.
  
  AD(SOC2, t) = 1/(1 + days_since_audit_end/180)
  
  At audit_end + 0 days:  AD = 1.0
  At audit_end + 180 days: AD = 0.5
  At audit_end + 365 days: AD = 0.36 (most stale reports accepted as current)
  At audit_end + 730 days: AD = 0.20 (common if vendor renews late)

TYPE 2 — ISO 27001 CERTIFICATE:
  Issued: covers a point-in-time certification audit
  Validity: 3 years with annual surveillance audits
  
  The 3-year validity period is the most dangerous attestation decay pattern
  in common use. An ISO 27001 certificate that is 2 years and 11 months old
  was issued based on an audit of the organization's ISMS as it existed nearly
  three years ago. The annual surveillance audits confirm that the ISMS "continues
  to meet requirements" — but surveillance audits are not full re-certifications.
  They cover approximately 30-40% of the control set.
  
  Between a full certification audit (year 0) and re-certification (year 3),
  the vendor's environment has undergone three years of change that the
  certificate does not reflect. New technologies deployed. New threat vectors.
  New staff. New systems. Old exceptions accumulated.
  
  AD(ISO27001, t):
    Year 0 (certification):    AD = 1.0
    Year 1 (surveillance 1):   AD = 0.7 (surveillance covers ~35% of controls)
    Year 2 (surveillance 2):   AD = 0.5
    Year 3 (re-certification): AD = 0.35 (just before re-cert, most stale point)
    After re-certification:    AD = 1.0 (reset)

TYPE 3 — PENETRATION TEST REPORT:
  Issued: point-in-time assessment of the environment as it existed during testing
  Standard frequency: annual (best practice) or as required by contract/regulation
  
  The penetration test report is the most rapidly decaying attestation because:
    1. It covers only the scope the tester was given (typically not the vendor's
       entire environment — just the portion relevant to your relationship)
    2. The environment changes faster than any other factor (new vulnerabilities,
       new deployments, new configurations)
    3. Every day after the test is conducted, new CVEs are disclosed that the
       test did not assess because they did not exist
  
  A penetration test from 12 months ago is not evidence of current security.
  It is evidence that 12 months ago, in the tested scope, the tester found
  the vulnerabilities they found. Everything that has changed since is uncovered.
  
  AD(PENTEST, t) = 1/(1 + days_since_test/90)
  
  At test+0:   AD = 1.0
  At test+90:  AD = 0.5
  At test+180: AD = 0.33
  At test+365: AD = 0.21

COMBINED ATTESTATION DRIFT SCORE:
  AD(v,t) = harmonic_mean(AD_SOC2, AD_ISO27001, AD_PENTEST)
  
  Using harmonic mean rather than arithmetic mean — same defense as ELDM's
  product form — prevents a strong attestation in one category from masking
  a completely stale attestation in another. A vendor with a fresh SOC 2 but
  a 2-year-old penetration test has a mixed posture that arithmetic averaging
  would overstate.

QUERY — VENDOR ATTESTATIONS PAST DECAY THRESHOLD (SQL):

  SELECT
      v.vendor_name,
      v.vendor_tier,
      v.data_categories_processed,
      s.report_date AS soc2_date,
      DATEDIFF(day, s.audit_period_end, GETDATE()) AS soc2_age_days,
      1.0 / (1.0 + DATEDIFF(day, s.audit_period_end, GETDATE()) / 180.0) AS ad_soc2,
      i.certificate_date AS iso_cert_date,
      DATEDIFF(day, i.certificate_date, GETDATE()) AS iso_age_days,
      p.test_date AS pentest_date,
      DATEDIFF(day, p.test_date, GETDATE()) AS pentest_age_days,
      1.0 / (1.0 + DATEDIFF(day, p.test_date, GETDATE()) / 90.0) AS ad_pentest
  FROM vendor_registry v
  LEFT JOIN vendor_soc2_reports s ON v.vendor_id = s.vendor_id
      AND s.report_date = (SELECT MAX(report_date) FROM vendor_soc2_reports
                           WHERE vendor_id = v.vendor_id)
  LEFT JOIN vendor_iso27001_certs i ON v.vendor_id = i.vendor_id
      AND i.is_current = 1
  LEFT JOIN vendor_pentests p ON v.vendor_id = p.vendor_id
      AND p.test_date = (SELECT MAX(test_date) FROM vendor_pentests
                         WHERE vendor_id = v.vendor_id)
  WHERE
      v.vendor_tier IN ('Critical', 'High')
      AND (
          DATEDIFF(day, s.audit_period_end, GETDATE()) > 365
          OR DATEDIFF(day, p.test_date, GETDATE()) > 365
          OR s.report_date IS NULL
          OR p.test_date IS NULL
      )
  ORDER BY soc2_age_days DESC, pentest_age_days DESC

OUTPUT: Critical and high-tier vendors whose primary attestations have exceeded
decay thresholds. Each row is an Attestation Drift finding requiring either
vendor engagement to obtain fresh attestation or a risk register entry documenting
the gap and the accepted exposure.

--------------------------------------------------------------------------------
2.3 TELEMETRY DRIFT (TD) — The Detection Mechanism for Vendor Relationships
--------------------------------------------------------------------------------

DEFINITION:
Telemetry Drift measures the degree to which the accepting organization retains
real-time visibility into the vendor's activities that affect the organization's
security posture — and how that visibility degrades over time as the vendor's
integration deepens and the telemetry architecture lags behind it.

This is the vendor equivalent of the ELDM's CL (Compensation Liveness) component.
For internal exceptions, CL measures whether the compensating detection rule is
still receiving data and still firing correctly. For vendor relationships, TD
measures whether the organization can observe what the vendor is doing in its
environment — and whether that visibility is still accurate.

THE TELEMETRY GAP STRUCTURE:

Most accepting organizations have some vendor activity logging. What they have
is almost never complete. The telemetry gap has four layers:

  LAYER 1 — ACCESS EVENT LOGGING (usually present):
    VPN authentication events for vendor accounts
    API authentication events for vendor API keys
    Firewall logs for traffic from vendor IP ranges
    Azure AD sign-in logs for vendor service principals
    
    This layer tells you WHEN the vendor connected and from WHERE.
    Most organizations have this. Most organizations do not alert on it
    meaningfully (the vendor connects every day — when does the alert fire?
    When they connect from a new IP? When they connect outside business hours?
    Are those thresholds defined, documented, and tested?)

  LAYER 2 — ACTION LOGGING WITHIN VENDOR SESSION (partially present):
    What did the vendor API key query after authenticating?
    What records did the vendor access in your Salesforce tenant?
    What files did the vendor touch in your SharePoint?
    What changes did the vendor's service account make in your AD?
    
    Most organizations have the raw log data for this. Most organizations
    have no alert rules on it. A vendor that accesses 10,000 customer records
    during normal support operations and 10,000 customer records during
    an active exfiltration event generates identical log entries.
    Without a baseline for vendor action volume and type, no anomaly fires.

  LAYER 3 — VENDOR-SIDE LOGGING (almost never present):
    What is happening in the vendor's environment that affects your security?
    Has the vendor experienced a security incident that may affect your data?
    Has the vendor made changes to the systems that access your environment?
    Has the vendor's staff who have access to your account changed?
    
    This is invisible. You cannot instrument the vendor's environment.
    You receive this information through disclosure — the vendor tells you —
    which is mediated by the vendor's incident response program, their legal
    review of notification obligations, and their assessment of what you
    need to know.
    
    The Okta breach (2022) was a case study in Layer 3 telemetry failure:
    Okta had a breach. Customers had no Layer 3 telemetry. Customers discovered
    they were affected when Lapsus$ published screenshots — not through Okta's
    disclosure, which came later and incompletely. The customer's Layer 1 and 2
    telemetry continued to show normal Okta activity throughout, because the
    breach was in Okta's internal environment (Layer 3), not in the authentication
    flows the customer could observe.

  LAYER 4 — FOURTH-PARTY VISIBILITY (essentially never present):
    Your vendor has vendors. Those vendors have access to your vendor's environment
    which has access to yours. Fourth-party risk is the recognition that your
    vendor's supply chain is also your supply chain — at one remove.
    
    The SolarWinds breach was technically a fifth-party event for some victims:
    the attacker compromised SolarWinds (the third party) which distributed
    updates to SolarWinds customers (fourth-party event) which used SolarWinds
    to manage customer networks (fifth-party event for those customers' customers).
    
    Almost no organization has any telemetry for fourth-party activity.

TELEMETRY DRIFT CALCULATION:
  TD(v,t) = (layers_with_meaningful_coverage / 4) ×
             (1 - integration_depth_delta × coverage_lag_rate)

Where:
  layers_with_meaningful_coverage = count of layers with alert rules and tested baselines
  integration_depth_delta = increase in vendor integration scope since last telemetry review
  coverage_lag_rate = rate at which new integration scope goes unmonitored

BUILDING MEANINGFUL LAYER 1 AND 2 COVERAGE — DETECTION QUERIES:

KQL — VENDOR ACCESS OUTSIDE NORMAL PATTERN (Layer 1 baseline anomaly):

  // First, establish vendor baseline (run as scheduled query, store results)
  let VendorBaseline = SigninLogs
  | where TimeGenerated between (ago(90d) .. ago(1d))
  | where ServicePrincipalName in (VendorServicePrincipals)
      or UserPrincipalName in (VendorUserAccounts)
  | summarize
      TypicalHours = make_set(hourofday(TimeGenerated)),
      TypicalCountries = make_set(LocationDetails.countryOrRegion),
      AvgDailyAuths = count() / 90.0
    by VendorId = tostring(AppId);

  // Then detect deviations from baseline (real-time)
  SigninLogs
  | where TimeGenerated > ago(1d)
  | where ServicePrincipalName in (VendorServicePrincipals)
      or UserPrincipalName in (VendorUserAccounts)
  | extend VendorId = tostring(AppId), Hour = hourofday(TimeGenerated)
  | join kind=leftouter VendorBaseline on VendorId
  | where Hour !in (TypicalHours)                              // unusual hour
      or LocationDetails.countryOrRegion !in (TypicalCountries)  // new country
  | project TimeGenerated, VendorId, UserPrincipalName,
            IPAddress, LocationDetails, ResultType,
            Deviation = case(
                Hour !in (TypicalHours), "OFF_HOURS",
                LocationDetails.countryOrRegion !in (TypicalCountries), "NEW_COUNTRY",
                "UNKNOWN"
            )

SPL — VENDOR API KEY ANOMALOUS DATA VOLUME (Layer 2 content anomaly):

  index=api_logs vendor_key=* action=GET OR action=POST
  | eval vendor_name=case(
      match(api_key, "^vend_.*_cust$"), "CustomerVendorA",
      match(api_key, "^svc_.*_ext$"),  "SupportVendorB",
      "unknown"
    )
  | where vendor_name != "unknown"
  | bucket _time span=1h
  | stats
      sum(records_returned) as records_accessed,
      sum(bytes_transferred) as bytes_out,
      dc(endpoint) as endpoints_hit
    by _time, vendor_name, api_key
  | eventstats
      avg(records_accessed) as avg_records,
      stdev(records_accessed) as stdev_records
    by vendor_name
  | where records_accessed > (avg_records + 3 * stdev_records)
  | eval zscore = (records_accessed - avg_records) / stdev_records
  | table _time, vendor_name, api_key, records_accessed, avg_records,
          zscore, bytes_out, endpoints_hit
  | sort -zscore

OUTPUT: Vendor API access sessions where data volume exceeds 3 standard
deviations above that vendor's mean. Each row is a potential data exfiltration
event via the vendor channel — distinguishable from the attacker's use only
by investigation of the authorization chain and the vendor's incident status.

--------------------------------------------------------------------------------
2.4 OBLIGATION RECESSION (OR) — The Ownership Mechanism for Vendor Relationships
--------------------------------------------------------------------------------

DEFINITION:
Obligation Recession measures how well the vendor's contractual security
obligations are currently being enforced — specifically, how many of the security
requirements that were active when the contract was signed have since receded
from active enforcement due to relationship maturation, organizational change,
or the absence of a verification mechanism.

This is the vendor equivalent of the ELDM's CC (Custodial Continuity) component.
For internal exceptions, CC measures whether a named custodian still owns the
exception and can be reached for incident escalation. For vendor relationships,
OR measures whether a named internal owner is still actively enforcing the
vendor's contractual security obligations.

THE RELATIONSHIP MATURATION PROBLEM:
When a vendor relationship is new, the procurement and legal teams enforce
contract terms because the negotiation is recent memory. Security teams request
quarterly reports, invoke audit rights, and escalate when SLAs are missed.

As the relationship matures:
  The procurement champion who negotiated the specific security terms moves on.
  The new relationship manager values service continuity over security enforcement.
  Requesting audit reports becomes "relationship friction" that nobody wants to create.
  The security team stops following up because the vendor has "always been fine."
  
  The contract still requires quarterly security reports. They stopped arriving
  at month 18. No one followed up. No one noticed. The obligation receded.

OR MEASUREMENT:
  OR(v,t) = (actively_enforced_obligations / total_contractual_obligations) ×
             (1 - owner_tenure_decay)

Where:
  actively_enforced_obligations = obligations with documented enforcement activity
                                   in the last 90 days
  total_contractual_obligations = total security obligations in the contract
  owner_tenure_decay = decay factor for the tenure of the vendor relationship owner
    (same formula as ELDM's CC custodian continuity — owner changes without
     formal handoff of enforcement knowledge accelerates recession)

THE OBLIGATION TAXONOMY:
  For each vendor contract, security obligations fall into five categories:

  Category A — Notification obligations (highest decay rate):
    "Vendor will notify accepting organization of security incidents within [time]"
    These are the obligations most likely to be untested until an incident occurs.
    At incident time, if the relationship has matured beyond active enforcement,
    the vendor may not know what "notification" means in this context, who to notify,
    or what the contracted timeframe is.

  Category B — Attestation delivery obligations:
    "Vendor will provide SOC 2 Type II report within 30 days of issuance"
    These are easy to track (did the report arrive?) but frequently drift because
    no automated tracking exists. The vendor delivers the report when asked.
    They are asked when someone remembers to ask.

  Category C — Access review obligations:
    "Vendor will review and certify all personnel with access to accepting
    organization's systems quarterly"
    Extremely valuable when enforced. Almost never enforced in practice because
    no accepting organization has a mechanism to verify the vendor actually
    conducted the review.

  Category D — Subprocessor notification obligations:
    "Vendor will notify accepting organization before engaging any new subprocessor"
    This is GDPR Art. 28(4) territory. Vendors frequently add and change
    subprocessors without notification, particularly for cloud infrastructure
    components. The obligation exists. The enforcement mechanism is absent.

  Category E — Right to audit:
    "Accepting organization may audit vendor's controls relevant to this contract
    on [frequency] with [notice period]"
    Almost never exercised. The legal cost, operational cost, and relationship
    friction of exercising an audit right means this obligation exists in
    99% of contracts and is exercised in approximately 1% of relationships.

QUERY — OBLIGATION ENFORCEMENT TRACKING (SQL):

  SELECT
      v.vendor_name,
      v.vendor_tier,
      o.obligation_category,
      o.obligation_description,
      o.enforcement_frequency,
      o.last_enforced_date,
      DATEDIFF(day, o.last_enforced_date, GETDATE()) AS days_since_enforcement,
      o.enforcement_owner,
      e.status AS owner_employment_status,
      CASE
          WHEN DATEDIFF(day, o.last_enforced_date, GETDATE()) > (o.enforcement_frequency_days * 2)
          THEN 'CRITICAL_RECESSION'
          WHEN DATEDIFF(day, o.last_enforced_date, GETDATE()) > o.enforcement_frequency_days
          THEN 'OBLIGATION_OVERDUE'
          WHEN e.status != 'ACTIVE'
          THEN 'OWNER_DEPARTED'
          ELSE 'CURRENT'
      END AS obligation_status
  FROM vendor_registry v
  JOIN vendor_obligations o ON v.vendor_id = o.vendor_id
  LEFT JOIN hr_directory e ON o.enforcement_owner = e.email
  WHERE v.vendor_tier IN ('Critical', 'High')
  ORDER BY obligation_status DESC, days_since_enforcement DESC

OUTPUT: All security obligations for critical and high-tier vendors, with
enforcement status. CRITICAL_RECESSION items are obligations that have not
been enforced in more than twice their required frequency — the obligation
exists in the contract but has effectively ceased to operate.

--------------------------------------------------------------------------------
2.5 TRUST OPACITY (TO) — The Fifth Decay Mechanism With No Internal Equivalent
--------------------------------------------------------------------------------

DEFINITION:
Trust Opacity is the unique decay mechanism for vendor exceptions that has
no equivalent in internal exception management. It measures the degree to which
the accepting organization is operating on trust rather than evidence for its
assessment of the vendor's current security posture.

While the four previous mechanisms (CD, AD, TD, OR) can all be improved by
better governance, Trust Opacity reflects a structural reality that cannot be
fully eliminated: you are not the vendor. You will never have complete visibility
into their environment. The opacity is irreducible — it can only be reduced,
never eliminated.

THE THREE LAYERS OF TRUST OPACITY:

OPACITY LAYER 1 — INTERNAL POSTURE OPACITY:
  The vendor's internal exception register, risk register, and security controls
  are not visible to the accepting organization. The accepting organization knows
  what the vendor claims about its security posture (through questionnaires,
  certifications, contract representations). It does not know the actual posture.
  
  The ELDM operates inside the vendor at the same rates as inside your organization.
  Vendor exceptions decay. Their EDS scores fall. Their compensating detections
  go silent. Their custodians depart. Their scope drifts.
  
  You cannot see any of this. The vendor's audit report describes controls
  at a point in time. Between audit points, the vendor's internal decay is
  invisible to you.

OPACITY LAYER 2 — FOURTH-PARTY OPACITY:
  Your vendor has vendors. Their supply chain is part of your supply chain
  at one remove. The vendor's SOC 2 report typically includes "complementary
  subservice organization controls" — an acknowledgment that the vendor relies
  on other vendors for specific functions and that the audit scope does not
  cover those sub-vendors.
  
  The critical sentence in almost every SOC 2 Type II report that most
  accepting organizations do not read carefully enough:
  "This report does not include the controls at the subservice organizations.
   Users of this report should apply the concept of carve-outs and consider
   the effect on the overall control environment."
  
  In practice: the vendor uses AWS for infrastructure, Okta for identity,
  Twilio for communications, and Salesforce for CRM. Each of these is a
  subservice organization. Each is carved out of the SOC 2 scope. The controls
  the vendor uses from each of these platforms are not tested. Your vendor's
  SOC 2 "covers" the environment, with asterisks attached to every component
  that runs on someone else's infrastructure.

OPACITY LAYER 3 — INCIDENT DISCLOSURE OPACITY:
  When the vendor has a security incident that affects your data or your
  integration, you depend on the vendor's disclosure to learn about it.
  That disclosure is filtered through:
  - The vendor's incident response program (how quickly do they detect and
    characterize incidents?)
  - The vendor's legal team (what are the notification obligations? What
    must be disclosed vs. what can be managed quietly?)
  - The vendor's relationship management team (how is this framed to
    minimize customer concern and contract termination risk?)
  - The contractual notification obligations (which may not require
    notification of all incidents — only "material" ones, which the
    vendor defines)
  
  The Okta 2022 breach was discovered by Okta approximately two months
  before they notified customers. The notification, when it came, minimized
  the scope of impact. The full scope was learned through third-party research
  and affected customer investigation, not through Okta's disclosure.
  Customers who relied solely on Okta's disclosure operated with incorrect
  information about the scope of their exposure for weeks.

TRUST OPACITY SCORE:
  TO(v,t) = (1 - opacity_fraction) where:
  opacity_fraction = (opaque_risk_surface / total_risk_surface)
  
  opaque_risk_surface = vendor assets in scope for your relationship that
    are not covered by any current, in-scope attestation or telemetry
  total_risk_surface = all vendor assets in scope for your relationship
  
  Practical approximation from vendor tiering:
    Tier 1 Critical vendor with full SOC 2, regular engagement,
    Layer 1+2 telemetry, active obligation enforcement: TO ≈ 0.3-0.5
    (even the best relationship has structural opacity)
    
    Tier 2 High vendor with aging attestation, no Layer 2 telemetry,
    receded obligations: TO ≈ 0.1-0.2
    
    Tier 3 Standard vendor with questionnaire only, no attestation,
    no telemetry, nominal obligations: TO ≈ 0.0-0.05

THE IRREDUCIBILITY OF TRUST OPACITY:
  TO cannot reach 1.0 for any real vendor relationship. The best possible
  state — full-scope SOC 2 covering all subservice organizations, real-time
  telemetry sharing, on-site audit rights exercised quarterly, complete
  fourth-party visibility — still leaves opacity in the vendor's internal
  incident detection and response timeline.
  
  This irreducibility is why vendor relationships always carry residual risk
  that internal controls do not carry. You can control your own environment.
  You cannot control your vendor's. The best you can do is reduce the opacity
  and create contractual obligations that convert vendor-side failures into
  disclosures you can act on.
  
  The practical implication for VEDS: TO sets a ceiling on VEDS that is
  always below 1.0. A perfectly managed vendor relationship has VEDS < 1.0
  because TO < 1.0. This is the honest representation of residual vendor risk:
  it cannot be eliminated, only reduced.

--------------------------------------------------------------------------------
SECTION 3 — THE VEDS FORMULA
--------------------------------------------------------------------------------

3.1 DEFINITION AND PRODUCT FORM DEFENSE

  VEDS(v,t) = CD(v,t) × AD(v,t) × TD(v,t) × OR(v,t) × TO(v,t)

The product form is defended on the same grounds as EDS (Paper 9):

These five components are serial dependencies, not parallel dimensions.
A vendor relationship with excellent attestation (AD = 0.9) but no telemetry
coverage (TD = 0.1) has VEDS = 0.09 × (other factors). The excellent attestation
does not compensate for the telemetry gap — it simply means you know, in
retrospect, what the vendor's controls were supposed to be when the attacker
walked through the telemetry gap undetected.

The attacker evaluates the weakest link, not the average. The product form
encodes the attacker's evaluation function. Averaging encodes the auditor's
evaluation function. VEDS is a security metric, not an audit metric.

Maximum VEDS given structural opacity: < 1.0 (TO ceiling)
Typical Tier 1 Critical vendor, well-managed: VEDS ≈ 0.3-0.5
Typical Tier 2 High vendor, standard management: VEDS ≈ 0.1-0.2
Typical Tier 3 Standard vendor, questionnaire-only: VEDS ≈ 0.02-0.08
Post-vendor-breach, before organizational response: VEDS ≈ 0.0

3.2 VEDS POPULATION ANALYSIS

The question every CISO should be asking: what is my VEDS distribution
across my vendor population?

This question requires:
  (a) A complete vendor inventory (which most organizations do not have — Paper 13's
      enumerable risk assumption applies to vendor inventories too)
  (b) Component data for each vendor (contracts, attestations, telemetry, obligations)
  (c) The computation engine

Most organizations have partial data for (b) in multiple disconnected systems:
  Contracts: in legal's contract management system
  Attestations: in GRC's vendor risk platform or a shared drive
  Telemetry: in the SIEM (if logged) or the firewall management console
  Obligations: in the contract management system (if tracked) or nowhere
  Trust opacity: not formally tracked anywhere

The VEDS implementation roadmap for most organizations therefore starts
not with computation but with data consolidation.

PHASE 1 — VENDOR INVENTORY AND TIER CLASSIFICATION (Month 1-2):
  Pull all vendors with any form of system access or data processing.
  Classify by tier:
    Tier 1 Critical: vendors whose failure could cause immediate operational
      or regulatory impact (cloud infrastructure, identity providers, payment
      processors, core SaaS applications, MSSPs)
    Tier 2 High: vendors with access to personal data, financial data, or
      internal systems (support tools, analytics platforms, professional services)
    Tier 3 Standard: vendors with limited access and data handling
    Tier 4 Low: no system access, no data processing

PHASE 2 — CONTRACT AND ATTESTATION DATA CONSOLIDATION (Month 2-4):
  For all Tier 1 and Tier 2 vendors:
  Pull current contract, DPA, and MSA. Extract security obligations.
  Pull latest attestation documents (SOC 2, ISO cert, pentest).
  Compute CD and AD for each vendor.
  Produce: ranked list by CD × AD score — the vendors with the worst
  contract and attestation health.

PHASE 3 — TELEMETRY AND OBLIGATION AUDIT (Month 4-6):
  For Tier 1 vendors:
  Map all vendor access paths (credentials, OAuth grants, network rules).
  Assess Layer 1 and Layer 2 telemetry coverage and alerting.
  Inventory all contractual security obligations and enforcement status.
  Compute TD and OR for each vendor.

PHASE 4 — FULL VEDS COMPUTATION AND RISK REGISTER INTEGRATION:
  Compute TO from the opacity fraction for each vendor.
  Compute VEDS = CD × AD × TD × OR × TO for all Tier 1 and Tier 2 vendors.
  Integrate VEDS scores into the risk register.
  VEDS < 0.2 for a Tier 1 vendor: immediate action required.
  Produce VEDS dashboard for board reporting (see Section 6).

--------------------------------------------------------------------------------
SECTION 4 — THE VENDOR EXCEPTION TREE (VET)
--------------------------------------------------------------------------------

4.1 DEFINITION

A Vendor Exception Tree maps the attack path by which an attacker chains through
a vendor's decayed exception into the accepting organization. It extends the
internal Exception Attack Tree (Paper 8) across the third-party boundary.

The VET has a specific structure:

  ROOT: The attacker's entry point into the vendor's environment
  TRUNK: The decay mechanisms that give the attacker access to the trust relationship
  BRANCHES: The specific trust paths from vendor into accepting organization
  LEAVES: The attacker's objectives within the accepting organization

4.2 THE CANONICAL VET — THE SUPPLY CHAIN WALKTHROUGH

This is the attack tree for the most common supply chain attack pattern,
illustrated with technical specificity:

ROOT — ATTACKER ENTERS VENDOR ENVIRONMENT:
  Entry via phishing (most common): a vendor employee with access to the
    accepting organization's systems is phished. Credential captured.
    
  Entry via unpatched vulnerability: a CVE in the vendor's customer portal,
    support system, or build pipeline is exploited.
    
  Entry via vendor's own vendor (fourth-party): the attacker compromises
    the vendor's IT management tool (RMM, monitoring platform), which has
    agent access to all customer systems.

TRUNK — VENDOR'S DECAY ENABLES LATERAL MOVEMENT:
  This is where the vendor's own ELDM score matters.
  The attacker, inside the vendor's environment, encounters:
  
  The vendor's unpatched legacy system (their own CVE backlog)
    → The vendor's patch SLA was quarterly but has drifted to "when possible"
    → Contract drift (the contract required monthly patching — CD component)
    
  The vendor's over-privileged service account for customer environments
    → Created with full-scope access when the contract was signed
    → Never reviewed or restricted as the relationship scope narrowed
    → Obligation recession (CD component — access scope not reviewed quarterly)
    
  The vendor's SOC has a detection gap for the specific technique the attacker uses
    → The vendor's detection drift (their internal CL) means the technique
       goes undetected in the vendor's SIEM
    → This is the vendor's ELDM operating against the attacker's favor
    → And the accepting organization has no visibility into this gap (TO component)

BRANCH — TRUST RELATIONSHIP EXPLOITATION:
  The attacker uses the vendor's privileged access to the accepting organization:
  
  BRANCH TYPE 1 — CREDENTIAL WALK:
    The vendor maintains a service account in the accepting organization's AD.
    The account has local admin rights on the vendor's support servers and
    on a small set of production servers for "vendor maintenance."
    
    The attacker authenticates as the vendor service account.
    They have legitimate credentials. The VPN accepts them (Layer 1 telemetry fires
    but is not alerted because "vendor connects every day").
    They have legitimate access to the vendor's support servers.
    From those servers, they enumerate what else the service account can reach.
    
    The service account was created with "domain user + local admin on server groups A, B, C."
    Over 4 years of vendor relationship, the server groups it has access to have expanded
    (Contract Drift — the access was never reviewed against the original scope).
    The service account now has local admin on 47 servers.
    
    The attacker moves to those 47 servers. The EDR alerts on the first lateral
    movement attempt. But the alert fires against the service account — which is
    in a suppression exception (because it always generates this behavior when
    the vendor runs maintenance scripts). The exception was created 2 years ago
    and has EDS = 0.1 (Paper 9 decay). The alert is suppressed.
    
    The attacker has 47 servers with local admin, suppressed alerts, and no
    immediate detection response. They have 247 days of unobserved access.

  BRANCH TYPE 2 — UPDATE DISTRIBUTION:
    The SolarWinds / 3CX pattern. The attacker compromises the vendor's
    software distribution pipeline. They inject malicious code into a
    legitimate software update. The update is cryptographically signed
    with the vendor's legitimate code signing certificate (which the attacker
    obtained through their access to the vendor's build environment).
    
    The accepting organization receives the update through normal update
    channels. The update passes signature verification (legitimate cert).
    The EDR may scan the binary — it passes behavioral analysis (the malicious
    behavior is dormant for 14 days, specifically to defeat sandbox analysis).
    The update deploys. The malicious payload activates.
    
    The telemetry gap (TD): the accepting organization has no visibility into
    the vendor's build pipeline (Layer 3 telemetry). The compromise happened
    outside any observable scope.
    
    The attestation gap (AD): the vendor's most recent SOC 2 report does not
    cover build pipeline security because it is not a common SOC 2 scope item.
    The penetration test from 11 months ago did not test the build pipeline
    because it was not in scope.

  BRANCH TYPE 3 — API ABUSE:
    The vendor has a legitimate API key with scope to read customer data
    for their support functions. The attacker, having compromised the vendor's
    support system, uses the API key to query customer data.
    
    The query volume is within normal parameters (Telemetry Drift — the Layer 2
    anomaly detection is not calibrated, so no baseline exists for "normal" vendor
    API volume). The queries access exactly the data the vendor is supposed to
    access. No alert fires.
    
    The attacker exfiltrates data at the rate that matches the vendor's normal
    export patterns, over the number of days it would take the vendor to run
    a legitimate data extract for a large customer. The exfiltration is complete
    before the vendor notices their support system was compromised.

LEAF — OBJECTIVES IN ACCEPTING ORGANIZATION:
  The attacker's objectives depend on the attacker type:
  
  Financially motivated (ransomware affiliate):
    Deploy ransomware after establishing persistence on sufficient servers.
    Wipe backup infrastructure first. Maximize encryption coverage.
    Demand: depends on organization size and assessed payment probability.
    
  Espionage (nation-state or competitor):
    Persistent, silent access to sensitive data.
    Extract IP, strategy documents, personnel files, customer data.
    Maintain access for months to years.
    Leave minimal trace. Attribution back to vendor supply chain is difficult.
    
  Supply chain amplification (attacker targeting your customers through you):
    Compromise your software or update distribution.
    Use you as a second hop in their supply chain attack.
    Your customers receive malicious updates from you, trusted by them.
    The attack tree has another branch.

4.3 THE VEDS SCORES AT EACH STAGE OF THE CANONICAL VET

The attacker's path through the VET is enabled by specific VEDS component failures:

  Entry (ROOT):
    Enabled by the vendor's internal ELDM decay.
    Your VEDS cannot prevent this. It can only ensure rapid discovery (TO reduction).

  Lateral movement (TRUNK):
    Enabled by the vendor's decayed exceptions.
    Your VEDS cannot directly influence this. Contractual obligations (OR) can
    require the vendor to maintain minimum EDS scores — but enforcement is weak.

  Trust exploitation (BRANCH):
    THIS IS WHERE YOUR VEDS APPLIES.
    CD (Contract Drift) determines whether the access the attacker exploits is
    still within the contract's defined scope — and whether controls appropriate
    to that scope were contractually required and enforced.
    TD (Telemetry Drift) determines whether you see the exploitation happening.
    OR (Obligation Recession) determines whether the vendor had notification
    obligations they have honored in time for you to respond.
    TO (Trust Opacity) is the fundamental reason you cannot prevent this
    branch entirely — only detect and contain it.

  Objective achievement (LEAF):
    Determined by the time between exploitation (BRANCH) and detection and
    response. This is your MTTD and MTTR. VEDS drives the MTTD by determining
    whether the exploitation is observable (TD component). The IR-GRC Closed
    Loop (Paper 10) drives the MTTR by ensuring the incident response channels
    are active and the feedback loop operates.

--------------------------------------------------------------------------------
SECTION 5 — REGULATORY MAPPING
--------------------------------------------------------------------------------

5.1 DORA — DIGITAL OPERATIONAL RESILIENCE ACT (EU, APPLIES FROM JANUARY 2025)

DORA is the most operationally specific major regulation for third-party ICT
risk ever enacted. It applies to financial entities in the EU and to ICT
third-party service providers that are deemed critical (designated by EU regulators).

DORA AND VEDS — THE DIRECT MAPPINGS:

DORA Art. 28 — Third-party ICT risk management policy:
  Requires: financial entities maintain a comprehensive ICT third-party risk
  management policy. The policy must include: risk assessment criteria for ICT
  third-party service providers, pre-engagement due diligence, contractual
  arrangements, ongoing monitoring, and exit strategies.
  
  VEDS mapping: DORA Art. 28 requires the infrastructure that VEDS measures.
  Specifically: the ongoing monitoring requirement maps to TD (Telemetry),
  the contractual arrangements requirement maps to CD (Contract), the risk
  assessment maps to the VEDS score itself.
  
  DORA Art. 28(3): requires a register of all contractual arrangements with
  ICT third-party providers, updated and available to competent authorities.
  This is the vendor inventory that Phase 1 of VEDS implementation produces.

DORA Art. 30 — Key contractual provisions:
  Requires specific minimum contractual provisions for ICT service providers,
  including: description of services, geographic location of data processing,
  provisions on availability and integrity, security levels, right to terminate,
  cooperation with supervisory authorities.
  
  DORA Art. 30(3): for critical ICT third-party service providers, requires:
  audit rights (the right to perform audits), right to inspect facilities,
  notification requirements (including estimated impact and remediation measures).
  
  VEDS mapping: OR (Obligation Recession) directly maps to DORA Art. 30 obligation
  enforcement. A vendor relationship where the audit rights have not been exercised
  in the last 12 months, where the notification requirements are contractually
  inadequate, or where the cooperation provisions are unverified, has high OR decay.

DORA Art. 19 — Classifying ICT incidents:
  Requires: classification of ICT incidents against criteria including duration,
  geographic spread, data losses, criticality of systems affected.
  For major ICT incidents: notification to competent authority within 4 hours
  of classification as major.
  
  VEDS mapping: To trigger DORA Art. 19 notification correctly, the organization
  must know that a vendor incident has affected it — which requires TD > 0.
  A vendor incident that the organization learns about from news coverage 72 hours
  after the fact (Okta pattern) creates a DORA notification obligation that was
  impossible to fulfill on time because TD ≈ 0 for the vendor.

DORA Art. 31 — Critical ICT third-party service providers:
  Regulators may designate specific providers as "critical" — subject to enhanced
  oversight, including direct supervisory powers over the provider.
  
  If your critical cloud provider, critical identity provider, or critical
  payment processor is designated under Art. 31, your regulatory exposure for
  incidents involving that provider is heightened regardless of your individual
  VEDS management.

5.2 NIS2 — NETWORK AND INFORMATION SECURITY DIRECTIVE (EU, TRANSPOSED BY OCTOBER 2024)

NIS2 substantially expanded the scope of the original NIS Directive and added
specific supply chain security requirements.

NIS2 ART. 21(2)(d) — Supply chain security:
  Entities must implement security measures covering supply chain security
  including security-related aspects concerning the relationships between each
  entity and its direct suppliers or service providers.
  
  This is the legislative basis for VEDS: NIS2 requires exactly the kind of
  ongoing supply chain security assessment that VEDS formalizes.
  
  The specific requirement: assess the overall quality of products and cybersecurity
  practices of suppliers and service providers, including their secure development
  procedures.

NIS2 ART. 23 — Reporting obligations:
  Significant incidents: initial notification within 24 hours, full notification
  within 72 hours, final report within one month.
  
  For supply chain incidents: the question of when the entity "became aware" of
  the significant incident determines the notification clock start. If a vendor
  breach affects the entity's systems, "became aware" begins when the entity
  had reasonable grounds to suspect its systems were affected — not when the
  vendor disclosed the breach.
  
  This creates a VEDS-relevant obligation: the organization's Layer 1 and Layer 2
  telemetry must be sufficient to generate "reasonable grounds to suspect" in a
  timely fashion. TD ≈ 0 means "reasonable grounds" may not arise until the
  vendor discloses — which may be days or weeks into the attack window.

NIS2 ART. 20 — Governance:
  Management bodies must approve cybersecurity risk management measures and
  oversee their implementation. Management bodies are personally liable for
  compliance failures.
  
  VEDS is a management body reporting metric. A CISO who cannot demonstrate
  to the management body that vendor risk is being measured, monitored, and
  actively managed is exposing management body members to personal liability
  under NIS2 Art. 20.
  
  The VEDS quarterly dashboard (Section 6) is the NIS2 Art. 20 evidence
  deliverable for the management body's vendor risk oversight.

5.3 ISO 27001:2022 — CONTROLS 5.19-5.22

ISO 27001:2022's Annex A substantially expanded the supplier relationship
controls compared to the 2013 version. Controls 5.19 through 5.22 are the
direct regulatory ancestors of the VEDS model.

CONTROL 5.19 — INFORMATION SECURITY IN SUPPLIER RELATIONSHIPS:
  Requirement: processes and procedures to manage information security risks
  associated with the use of suppliers' products or services.
  
  This control requires exactly what CD measures: that the contractual
  relationship accurately reflects the security requirements for the actual
  scope of the supplier relationship.
  
  The ISO 27001:2022 implementation guidance for 5.19 specifies:
  - Identify and document supplier categories
  - Establish processes for new and existing supplier relationships
  - Include information security requirements in contracts
  - Monitor and review supplier performance against requirements
  
  A VEDS computation produces the monitoring and review evidence that 5.19
  requires.

CONTROL 5.20 — ADDRESSING INFORMATION SECURITY WITHIN SUPPLIER AGREEMENTS:
  Requirement: specific information security requirements in agreements with
  each supplier, including minimum security standards, right to audit, incident
  notification requirements, personnel security, data handling requirements.
  
  This control maps to CD (Contract Drift) and OR (Obligation Recession).
  The audit evidence for 5.20 conformance is:
  - Current contract containing all required provisions (CD component: alignment)
  - Evidence that the provisions were enforced in the audit period (OR component)
  
  A VEDS score with high CD and high OR provides strong 5.20 audit evidence.
  A VEDS score with low CD or low OR exposes a 5.20 non-conformity.

CONTROL 5.21 — MANAGING INFORMATION SECURITY IN THE ICT SUPPLY CHAIN:
  Requirement: processes to manage information security risks associated with
  the ICT product and service supply chain, including requirements to address
  information security risks associated with the use of ICT products and services.
  
  This is the fourth-party opacity problem in ISO 27001 language. Control 5.21
  requires the organization to understand and manage the risks from its vendors'
  vendors (subprocessors, subservice organizations).
  
  The TO (Trust Opacity) component's Layer 2 (fourth-party opacity) is the gap
  that 5.21 identifies. The acceptable response to 5.21 non-conformity is not
  achieving zero opacity (impossible) but demonstrating that the organization:
  - Understands the subprocessor landscape of critical suppliers
  - Has contractual provisions requiring notification of subprocessor changes
  - Has assessed the risk of key subprocessors that are visible

CONTROL 5.22 — MONITORING, REVIEW AND CHANGE MANAGEMENT OF SUPPLIER SERVICES:
  Requirement: regularly monitor, review and audit supplier service delivery
  against agreements. Manage changes to provision of services including changes
  to technology, changes in personnel, changes in processes.
  
  This is the closest ISO 27001 analog to the full VEDS model: ongoing monitoring
  (TD), review against agreements (OR), and managing changes (CD, AD — because
  changes to the vendor environment affect the accuracy of existing attestations).
  
  5.22 is the control that VEDS operationalizes. The VEDS quarterly computation
  is the monitoring and review activity that 5.22 requires. The VEDS trend
  analysis is the evidence that the monitoring produced actionable results.

COMBINED ISO 27001:2022 MAPPING:

  VEDS Component  → ISO 27001:2022 Control(s)
  CD (Contract)   → 5.19, 5.20
  AD (Attestation)→ 5.20, 5.22
  TD (Telemetry)  → 5.22 (monitoring), 5.21 (fourth-party)
  OR (Obligation) → 5.20 (enforcement), 5.22 (review)
  TO (Opacity)    → 5.21 (supply chain), 5.22 (change management)

An organization that implements VEDS and conducts quarterly VEDS assessments
for Tier 1 and Tier 2 vendors has strong conformance evidence for all four
controls across its critical vendor population.

--------------------------------------------------------------------------------
SECTION 6 — THE CLOSED-LOOP TIE-IN (PAPER 10 EXTENSION)
--------------------------------------------------------------------------------

Paper 10 (IR-GRC Closed Loop) defined four channels through which incident
intelligence flows from IR into the risk register and the exception program:
  Channel 1: risk register updates from incidents
  Channel 2: detection gap documentation
  Channel 3: control effectiveness record
  Channel 4: threat profile updates

Paper 12 (UPE) added Channel 5 for shadow AI discoveries.

Vendor incidents require Channel 6 — the Vendor Incident Feedback Channel.
This channel is architecturally distinct from the others because:
  The incident did not originate inside the organization.
  The evidence is primarily external (vendor disclosure, vendor IR report,
    external notification from regulatory authority or third-party researcher).
  The remediation may require contractual action against a third party,
    not just internal control remediation.
  The regulatory notification obligation may have a different triggering condition
    (DORA: when the organization is affected; NIS2: when the organization "became aware").

CHANNEL 6 — VENDOR INCIDENT FEEDBACK:

TRIGGER: Any of the following activates Channel 6:
  Vendor discloses a security incident
  SIEM alerts on vendor account anomaly (Layer 1 or 2 telemetry)
  Regulatory authority notifies organization of vendor breach
  Third-party researcher or threat intelligence feed reports vendor breach
  The organization discovers vendor breach through any other means

STEP 1 — SCOPE DETERMINATION (within 4 hours, DORA-aligned):
  Is the organization's data or systems affected?
  Query: all vendor activity logs for the period of suspected breach.
  Query: all data transfers from vendor to organization and vice versa.
  Query: all changes made by vendor accounts/API keys in the organization's systems.
  
  Scope determination produces: affected data categories, affected systems,
  estimated exposure period, estimated data subject count (for GDPR notification).

STEP 2 — REGULATORY NOTIFICATION ASSESSMENT (within 4 hours):
  Apply notification decision tree from Paper 12 (adapted for vendor incidents):
  Does this meet DORA Art. 19 "major incident" criteria?
  Does this meet NIS2 Art. 23 "significant incident" criteria?
  Does this meet GDPR Art. 33 breach criteria?
  Does this meet HIPAA, SOC 2, or other applicable criteria?
  
  If any answer yes: notification clock starts from "became aware."
  Document: exactly when "became aware" — this timestamp is the regulatory anchor.

STEP 3 — VEDS UPDATE (within 24 hours):
  Immediately update VEDS components for the breached vendor:
  TD: what telemetry gap failed to detect the incident? → TD decreases
  AD: what attestation failed to cover the breached control area? → AD assessment
  OR: what notification obligation was triggered? Was it met within SLA? → OR update
  TO: what opacity factor prevented earlier detection? → TO assessment
  
  Compute new VEDS for the vendor. If VEDS < 0.1: activate vendor incident
  response protocol (access suspension or increased monitoring pending investigation).

STEP 4 — EXCEPTION REGISTER UPDATE (within 48 hours):
  The vendor incident is a new entry in the exception register:
  
  Exception ID: VENDOR-[vendor_id]-[incident_date]
  Type: Vendor Security Exception — Active Incident
  Scope: all assets and data associated with vendor relationship
  Authorization: none — this is an incident, not an accepted exception
  Custodian: Vendor Risk Manager + Legal + DPO (if PII involved)
  Compensation: increased telemetry monitoring + access review + vendor engagement
  Review frequency: daily until incident resolved
  EDS: computed from the incident's impact on each EDS component
  
  This entry creates the audit trail showing the organization responded to the
  vendor incident as a governance event, not just as an IT problem.

STEP 5 — RISK REGISTER UPDATE (within 5 business days):
  Same as Paper 10's Channel 1 procedure:
  
  Class A (new risk): vendor incidents of this type were not previously in the
    register → create new risk entry for "vendor supply chain compromise via
    [attack vector]"
  Class B (risk underrated): the vendor risk was in the register but rated
    lower than this incident's impact justifies → update likelihood/impact
  Class C (control failure): the vendor attestation and telemetry controls
    failed to prevent or detect this → update control effectiveness record
  Class D (correct rating): the risk was correctly rated and controlled —
    the incident was detected and contained within acceptable parameters → validation

STEP 6 — CONTRACT REMEDIATION (within 30 days):
  Every vendor incident produces contract remediation items:
  Notification SLA: was it met? If not: contract amendment required.
  Audit rights: should they be exercised following this incident? If yes: invoke now.
  Access restrictions: should vendor access be restricted pending security improvement?
  VEDS floor: add a VEDS minimum requirement to the contract renewal.
  
  VEDS FLOOR CONTRACT LANGUAGE (proposed standard clause):
  "Vendor shall maintain a Vendor Exception Decay Score (VEDS) of no less than
   [0.3 / 0.4 / 0.5 depending on tier] as computed by [accepting organization]
   quarterly using the VEDS methodology described in Exhibit [X]. Vendor shall
   cooperate in providing the information necessary for VEDS computation. A VEDS
   score below [floor] for two consecutive quarters constitutes a material contract
   breach giving [accepting organization] the right to terminate with 30 days'
   notice. Vendor shall notify [accepting organization] within [4/24/48] hours of
   any security incident that may affect VEDS components."
  
  This clause converts VEDS from an internal risk tool into a contractual
  standard that creates enforceable obligations. It is the contract equivalent
  of Paper 9's EDS minimum for internal exceptions.

LIS_VENDOR UPDATE (Loop Integrity Score extension):
  Paper 10's Loop Integrity Score measured how completely incident intelligence
  flows back through the four channels. Paper 12 extended it to LIS_privacy.
  Channel 6 extends it further:
  
  LIS_vendor = LIS × (vendor_incidents_processed_through_channel6 / total_vendor_incidents)
  
  If vendor incidents are processed through Channel 6 correctly:
    LIS_vendor ≈ LIS (channel 6 operating)
  If vendor incidents are handled ad hoc outside the loop:
    LIS_vendor < LIS (channel 6 absent, vendor incidents not feeding back into governance)

--------------------------------------------------------------------------------
SECTION 7 — THE CISO BOARD DASHBOARD (VEDS REPORTING)
--------------------------------------------------------------------------------

VEDS adds three metrics to the Paper 9 / Paper 11 / Paper 12 board dashboard:

METRIC 1 — VENDOR RISK HEAT MAP (VRTM):
  A two-axis visualization:
    X-axis: VEDS score (0.0 to 0.8 max)
    Y-axis: Vendor impact rating (1-5 scale: what happens if this vendor fails?)
    Size of point: annual spend with vendor (proxy for integration depth)
  
  Board language: "Each point represents a vendor relationship. The lower-left
  quadrant (low VEDS, high impact) represents our highest-priority vendor risks.
  We currently have [N] vendors in this quadrant, representing approximately
  [% of critical vendor spend]. Our target is to reduce this to [N] or fewer
  within [timeframe] through the VEDS improvement roadmap."

METRIC 2 — VENDOR ATTESTATION COVERAGE RATIO (VACR):
  VACR = (Tier 1 vendors with AD > 0.5) / (total Tier 1 vendors)
  
  AD > 0.5 means the vendor has an attestation with less than 180 days of
  audit period age — a reasonable minimum assurance threshold.
  
  Board language: "X% of our critical vendor relationships have attestations
  that provide meaningful current assurance. The remaining Y% are operating
  on attestations that are more than 180 days old. Each represents a gap in
  our third-party assurance coverage."

METRIC 3 — VENDOR INCIDENT NOTIFICATION COMPLIANCE (VINC):
  VINC = (vendor incidents notified within contractual SLA) /
         (total vendor incidents requiring notification)
  
  This is the OR component expressed as an outcome metric: not just "are
  notification obligations in the contract" but "when an incident occurred,
  was the obligation honored?"
  
  Board language: "In the last 12 months, we experienced [N] vendor security
  incidents requiring notification under our contractual terms. Of these,
  [VINC × N] were notified within the contractual SLA. The remaining [N × (1-VINC)]
  were late or not notified. Late notifications create regulatory exposure under
  DORA Art. 19 and NIS2 Art. 23 where the notification obligation exists at
  the accepting organization level regardless of the vendor's notification delay."

--------------------------------------------------------------------------------
SECTION 8 — LIMITATIONS
--------------------------------------------------------------------------------

  - VEDS requires data from five sources (contract register, attestation archive,
    SIEM telemetry, obligation tracker, opacity assessment). Most organizations
    have this data in disconnected systems or do not track it systematically.
    The implementation roadmap (Section 3.2) accounts for this, but the
    practical data consolidation cost is significant and should not be
    underestimated. VEDS computation is only as good as the underlying data.

  - TO (Trust Opacity) is the component most resistant to objective measurement.
    The formula uses opacity_fraction as the primary driver, but estimating
    the total risk surface that is opaque requires judgment about what the
    vendor's environment contains — information the organization does not have
    by definition. Practical VEDS implementations should document the TO
    estimation methodology and its assumptions explicitly.

  - The VEDS floor contract clause (Section 6, Step 6) is proposed as standard
    language. It has not been tested in litigation or regulatory proceedings.
    Organizations implementing this clause should work with legal counsel to
    ensure the clause is enforceable in the applicable jurisdictions and is
    consistent with applicable regulatory requirements (particularly for
    financial entities subject to DORA, where vendor contractual requirements
    are prescribed in detail by Art. 30).

  - Fourth-party risk (TO Layer 2) is treated in this paper as partially
    addressed through contractual subprocessor notification obligations.
    In practice, fourth-party risk requires either (a) direct vendor engagement
    on fourth-party security standards or (b) industry-level information sharing
    about shared critical vendors (the same cloud provider, the same identity
    provider). Neither mechanism is mature for most industries. VEDS
    acknowledges fourth-party opacity but does not solve it.

  - DORA Art. 31's designation of "critical ICT third-party service providers"
    for direct supervisory oversight was still being developed as of the
    paper's writing date. The regulatory landscape for designated providers
    will evolve and may impose additional obligations on accepting organizations
    not fully captured here.

--------------------------------------------------------------------------------
SECTION 9 — WHAT I WOULD DO DIFFERENTLY
--------------------------------------------------------------------------------

  1. The canonical VET in Section 4.2 presents a single attack tree. Real supply
     chain attacks are multi-variant — the SolarWinds attack tree had branches
     for different victim environments, different attacker objectives, and different
     post-exploitation paths. A full VET library for the five most common vendor
     relationship types (MSP, SaaS, professional services, infrastructure, payment
     processor) would make the attack tree model more immediately actionable.
     Building that library is the highest-priority extension of this paper.

  2. The VEDS floor contract clause needs a negotiation strategy. Most vendors
     will not accept a VEDS-based termination right without either (a) knowing
     what VEDS is and believing it is fair, or (b) being a vendor with high
     bargaining power over the accepting organization. A negotiation approach —
     how to introduce VEDS in a contract renewal, what concessions to expect,
     what alternatives to offer when vendors refuse the direct VEDS floor —
     would make the contract section significantly more practical.

  3. The query for detecting vendor access anomalies (Layer 2, SPL query) uses
     statistical anomaly detection (3 standard deviations). This threshold was
     chosen for illustration. Production deployment requires environment-specific
     calibration — in environments where vendors have highly variable legitimate
     usage, the threshold may produce excessive false positives. A calibration
     procedure should accompany the query in production deployment.

  4. This paper focuses on the accepting organization's perspective. The
     complementary paper — written from the vendor's perspective — would describe
     how a vendor can improve its own VEDS score as presented by customers,
     creating commercial incentives for vendors to maintain high VEDS scores.
     The market mechanism (customers preferring vendors with higher VEDS) is the
     most scalable way to improve supply chain security at industry scale.

--------------------------------------------------------------------------------
SECTION 10 — CONCLUSION
--------------------------------------------------------------------------------

The series began eight papers ago with a simple observation: governance failures
create SOC blind spots. The failure happens before the detection gap. The detection
gap exists because the governance failed to create the control the detection depends
on.

This paper takes that observation across the vendor boundary and arrives at the
same structure — but with a multiplier.

Inside your organization, you can observe the decay. The ELDM artifacts are in
your systems. The phantom assets are in your inventory. The departed custodians
are in your HR directory. The silent compensation rules are in your SIEM. You
can run the Paper 9 audit procedure. You can compute EDS. You can bend the decay
curve.

In your vendor relationships, the decay is happening in a system you cannot
access, at a rate you cannot observe, producing artifacts you cannot see. You
receive periodic snapshots — the SOC 2 report, the ISO certificate, the
questionnaire response — and you extend trust across the gap between snapshots.

The attacker does not need to breach your organization. They need to breach your
vendor — a smaller, less defended target — and then walk the trust relationship
you established. The credentials you provisioned. The API key you issued. The
network rule you opened. The service account you created. All of these are doors
you built, keyed to the vendor, with locks the vendor holds. When the attacker
takes the vendor's keys, your doors open.

VEDS measures how well those doors are maintained. Contract Drift measures whether
the door's specified use still matches its actual use. Attestation Drift measures
how old the last inspection of the lock was. Telemetry Drift measures whether you
can see the door from where you stand. Obligation Recession measures whether
anyone is still responsible for calling you when the door opens unexpectedly.
Trust Opacity measures the irreducible gap between what you can see and what
is actually happening on the other side.

The organizations that survive the next generation of supply chain attacks will
not be the ones with the highest VEDS scores. Supply chain attacks will still
succeed. They will be the ones with Channel 6 operating correctly — the ones
who learn about the vendor incident through their own telemetry rather than from
the news, who trigger their regulatory notification processes within hours rather
than days, and who use every vendor incident to improve their VEDS scores for
the next attack.

The decay is happening. In your vendors' exception registers, right now, there
are exceptions whose EDS is approaching zero. Some of those exceptions are in
the systems your vendor uses to access your environment. You cannot see them decay.

VEDS is the formula that makes the invisible decay visible from the outside.
Channel 6 is the mechanism that feeds what you learn back into the governance
program before the next vendor is compromised.

Together, they are the supply chain extension of everything this series has built.

--------------------------------------------------------------------------------
SERIES CONNECTIONS
--------------------------------------------------------------------------------
  The decay model this paper extends across the vendor boundary:
    "Exception Lifecycle Decay Model" (14-09-2026) — EDS extended to VEDS

  The privacy obligations that vendor relationships create:
    "The Privacy Governance Triad" (25-09-2026) — Art. 28 DPA requirements
    "The Unsanctioned Processing Exception" (27-09-2026) — vendor AI processing

  The structural assumptions vendor failures invalidate:
    "The AI Security Failure Model" (30-09-2026) — SAVS and AI vendor risk

  The closed-loop mechanism that Channel 6 extends:
    "The IR-GRC Closed Loop" (Paper 10) — LIS_vendor extends LIS

  The compliance debt that vendor exceptions contribute:
    "Risk Acceptance Backdoors & Compliance Debt" (Paper 8) — CD_vendor
    (vendor's own compliance debt transfers through supply chain)

  The detection queries that build Layer 1 and Layer 2 telemetry:
    "The Detection Paradox" (04-09-2026) — vendor detection rules age like others
    "SOC-GRC Entropy Model" (07-09-2026) — vendor telemetry as entropy source

--------------------------------------------------------------------------------
END OF PAPER — hiro001-eth — 06-10-2026

"Your vendor's decayed exceptions are your risk. You just cannot measure them
because you are on the wrong side of the boundary. The VEDS formula is the
instrument you read from where you stand. It does not eliminate the opacity.
It makes the opacity legible — so you know what you are trusting,
how old that trust is, and how much of it you can still see."
================================================================================




# The Vendor Exception Decay Problem — Part 2
## What the Research Paper Didn't Say (But Should Have)

---

### Before We Begin

The paper you just read is technically sound. It's rigorous, well-structured, and introduces a genuinely useful framework in VEDS. But here's the thing about research papers — they're written for a specific audience, in a specific voice, for a specific purpose. They're written to be cited, to be defensible, to sit in a regulatory filing or an academic database.

They're not written to be *felt*.

And the vendor risk problem? It's not just an intellectual puzzle. It's a thing that keeps CISOs awake at 3 AM. It's a thing that makes GRC analysts stare at a SOC 2 report wondering if they're reading a description of current reality or a historical document. It's a thing that makes board members nod along to a presentation they don't fully understand while somewhere in a vendor's environment, an exception is quietly rotting.

So what I want to do here is take the same concepts — the same VEDS model, the same five decay mechanisms, the same attack trees — and talk about them the way we'd talk about them if we were sitting across from each other at a conference, or on a call after a vendor just missed their second incident notification in a row, or in that moment when you realize the vendor you've trusted for four years has been running your data through systems you never approved.

Let's fill in the gaps.

---

## Part 1: The Things Research Papers Don't Say Out Loud

### The Paper Is Polite. The Reality Isn't.

When the paper says "you are accepting a vendor's exceptions on faith," it's being diplomatic. What it's actually saying is this:

You don't know what's happening inside your vendors' environments. Not really. The SOC 2 report tells you what an auditor saw during a sample period that ended months ago. The ISO certificate tells you what a certification body assessed against a control set that was designed before some of your current threats existed. The security questionnaire tells you what the vendor's security team believed about their own environment on the day they filled it out — or more accurately, what they wanted you to believe.

The paper describes this as "Trust Opacity" and assigns it a variable (TO). But here's what a variable can't capture: the *unease*. The knowledge that somewhere in the vendor's infrastructure, there's a system with an unpatched vulnerability, or a service account with too much access, or a detection rule that's been silently broken for six months, and you have no way to know.

The paper says TO can't reach 1.0 for any real vendor relationship. What it doesn't say is that TO often can't reach 0.5 either, no matter how mature your TPRM program is. The best you can do is shrink the opacity to a size where you can name it, measure it, and make a conscious decision about accepting it.

That's not failure. That's honesty. But the paper leaves you to figure that out on your own.

---

### The Five Decay Mechanisms Are Real, But They Don't Decay Equally

The paper presents CD, AD, TD, OR, and TO as five components of a product formula. Mathematically elegant. Practically, they decay at wildly different rates, and understanding those rates changes how you prioritize.

**Contract Drift (CD)** decays slowly. Contracts don't change overnight. The scope expansion that creates contract drift happens over months and years — a new integration here, an additional data field there, a service account created for a project that was supposed to last three months but is still running two years later. By the time CD hits 0.3, the relationship has usually been drifting for 18-24 months. The good news: slow decay means slow, manageable remediation. The bad news: slow decay is easy to ignore because nothing catastrophic happens on any given day.

**Attestation Drift (AD)** decays on a predictable schedule. SOC 2 reports age in a straight line from their audit period end date. ISO certificates decay in steps — full assurance at certification, partial assurance through surveillance audits, maximum staleness just before re-certification. Pentest reports decay fastest because the threat landscape moves faster than any other variable. The paper gives you formulas for all three. What it doesn't say is that most organizations treat all attestations as binary — current or expired — when the reality is a continuous gradient. A SOC 2 report that's 6 months old is meaningfully better than one that's 18 months old, even though both might pass a checkbox review. AD captures that gradient. Use it.

**Telemetry Drift (TD)** decays suddenly and then stays flat. Layer 1 coverage (access logging) is usually stable — either you're logging vendor VPN connections or you're not. Layer 2 coverage (action logging within sessions) is where the decay happens. A new integration goes live without corresponding alert rules. The vendor's API usage pattern shifts and the baseline goes stale. The SIEM rule that used to catch anomalous vendor behavior starts generating false positives, so someone tunes it, and now it catches nothing. TD doesn't decay gradually — it falls off a cliff when a specific integration outpaces its monitoring. This is why the paper's Layer 1/Layer 2/Layer 3/Layer 4 framework is useful: it forces you to ask not just "do we have telemetry?" but "do we have telemetry that actually tells us something?"

**Obligation Recession (OR)** decays with personnel changes. The paper mentions "owner_tenure_decay" but doesn't emphasize enough that this is the single biggest driver. When the person who negotiated the vendor contract leaves, the institutional knowledge of what security obligations exist and how they were supposed to be enforced leaves with them. The new relationship manager sees a vendor that "has always been fine" and doesn't want to create friction by requesting audit reports that stopped arriving 14 months ago. OR decay isn't a technical problem — it's a people problem, and it's the hardest to fix because it requires either rebuilding enforcement mechanisms or accepting that the contractual obligations you thought were protecting you have become decorative.

**Trust Opacity (TO)** doesn't decay — it's always there. The paper says TO sets a ceiling on VEDS below 1.0, which is correct. What it doesn't say is that TO is the component where your own risk appetite determines your target. Some organizations accept that their critical SaaS providers will always be partially opaque and focus their energy on TD — ensuring they can see what the vendor does in *their* environment, even if they can't see inside the vendor's. Other organizations invest heavily in contractual audit rights and exercise them aggressively, reducing TO at the cost of vendor relationship friction. Neither approach is wrong. But you have to choose, and you have to document that choice.

---

### The Vendor Exception Tree Is Scarier Than It Reads

The paper presents the VET as a structured attack path model. It's technically accurate. But reading it in a research paper format makes it feel abstract. Let me translate.

**The credential walk** — Branch Type 1 — is how most supply chain attacks actually work. Not through sophisticated zero-days. Not through elaborate social engineering of your employees. Through a vendor service account that was provisioned five years ago, scoped for a project that no longer exists, with local admin rights that were supposed to be temporary, on servers that have multiplied beyond what anyone tracked.

The attacker doesn't need to be sophisticated if your vendor access hygiene is poor. They need to find a vendor with weak internal security (which most have, because security investment scales with company size and most vendors are smaller than you), compromise that vendor's environment, and then use the trust relationship you established. The credential walk is just lateral movement through a door you built.

The paper's description of the suppression exception is particularly important. When the attacker moves laterally using a vendor service account, the EDR *does* fire. But the alert is suppressed because "the vendor always does this during maintenance." That suppression exception was created two years ago by someone who has since left the organization. The exception's EDS score — if anyone bothered to compute it — would be near zero. But no one has looked at it because vendor service account behavior is "normal." The attacker has 247 days of unobserved access. This isn't hypothetical. This is the actual post-mortem of multiple real-world breaches.

**The update distribution** — Branch Type 2 — is the one that should terrify you the most, because it's the hardest to defend against. Your defenses are built to stop malicious code. They're not built to stop malicious code signed with a legitimate certificate, distributed through a legitimate update channel, from a vendor you've explicitly trusted. The SolarWinds attackers understood this. The 3CX attackers understood this. The MOVEit attackers understood this. The paper describes the telemetry gap (Layer 3 — you can't see the vendor's build pipeline) and the attestation gap (SOC 2 doesn't cover build pipeline security), but what it doesn't emphasize enough is the *helplessness*.

If your vendor's build pipeline is compromised, you will deploy their malicious update. There is no control you can implement in your environment that reliably distinguishes between a legitimate update and a compromised one, because the compromise happened upstream of every signal you can observe. Your only defenses are: vendor diversity (if one vendor is compromised, not all are), network segmentation (limits what the malicious update can reach), and rapid detection (once the payload activates, how fast do you know?). The paper gives you the framework for measuring vendor risk. It doesn't give you the framework for accepting that some vendor risk is genuinely unmitigable.

**The API abuse** — Branch Type 3 — is the quiet one. No alerts fire. No anomalous access patterns. The attacker uses the vendor's legitimate API key to access exactly the data the vendor is authorized to access, at a volume that matches normal usage. The only way to detect this is Layer 2 telemetry with calibrated baselines, and most organizations don't have that. The paper's SPL query for anomalous data volume is a starting point, but it assumes you have a baseline, which assumes you've been logging vendor API activity at a granular enough level to establish what "normal" looks like. If you haven't, you're blind to this attack path, and you'll stay blind until the data shows up somewhere it shouldn't.

---

## Part 2: The Things the Paper Glosses Over

### The Contract Drift Query Has a Problem

The SQL query for vendor credentials not in contract registry is useful, but it has a hidden assumption: that `vendor_credentials` and `vendor_contracts` use the same vendor name. In practice, they don't. Legal knows the vendor as "Acme Solutions Inc." The credential store knows it as "acme-sso-prod." The contract registry knows it as "ACME_SOLUTIONS_2024_MSA." The GRC platform knows it as "Vendor ID 4728."

Before you can run that query, you need a vendor identity resolution process. This is unsexy work. It's also the work that determines whether your VEDS computation is based on reality or on a join that silently fails and returns empty results that you interpret as "no findings."

The paper doesn't mention this because research papers don't talk about data hygiene. But if you're actually implementing VEDS, vendor identity resolution is Phase 0, and it's usually the longest phase.

---

### Attestation Drift's Harmonic Mean Is Right, But the Interpretation Matters

The paper uses harmonic mean for combining SOC 2, ISO 27001, and pentest AD scores. This is mathematically sound — it prevents a fresh attestation in one category from masking a stale attestation in another.

But here's what the paper doesn't say: the *interpretation* of the combined AD score depends on which attestation is stale.

A vendor with a fresh SOC 2 but a 2-year-old pentest has a specific risk profile: their operational controls are probably fine (SOC 2 covers that), but you have no recent evidence about their vulnerability management or external attack surface. This is different from a vendor with an aging SOC 2 but a fresh pentest: their external attack surface is probably fine, but their internal operational controls may have drifted.

The harmonic mean gives you a single number. The paper should tell you to also look at the *pattern* — which attestations are fresh and which are stale — because the remediation path differs depending on what's missing.

---

### The Telemetry Drift Formula Is Overly Simplified

The paper's TD formula is:

`TD(v,t) = (layers_with_meaningful_coverage / 4) × (1 - integration_depth_delta × coverage_lag_rate)`

This works as a heuristic, but it has a problem: it treats all four layers as equally valuable, when in practice they're not.

For most organizations, Layer 1 (access logging) and Layer 2 (action logging) are where the detection value lives. Layer 3 (vendor-side logging) is aspirational — you're not going to get it from most vendors, and the ones who provide it often provide it through a portal you have to manually check, which makes it useless for real-time detection. Layer 4 (fourth-party visibility) is essentially nonexistent for most industries.

A better formulation would weight the layers:

`TD(v,t) = (w1 × L1_coverage + w2 × L2_coverage + w3 × L3_coverage + w4 × L4_coverage) × (1 - lag_factor)`

Where w1 and w2 are high (0.4 each, for example), w3 is low (0.15), and w4 is negligible (0.05). This reflects the reality that Layer 1 and Layer 2 telemetry is where you'll actually detect vendor-related incidents, and it prevents an organization with good Layer 1/2 coverage from being penalized for lacking Layer 3/4 visibility that no one in their industry has either.

The paper's formula isn't wrong — it's just not calibrated to how detection actually works.

---

### Obligation Recession Needs a "Who Cares?" Metric

The paper measures OR as the ratio of actively enforced obligations to total contractual obligations. This is useful. But it doesn't capture the *materiality* of the obligations that have receded.

A vendor contract might have 47 security obligations. If the ones that have receded are "vendor will provide annual security awareness training completion statistics" and "vendor will notify accepting organization of changes to its subprocessor list," that's different from if the ones that have receded are "vendor will notify accepting organization of security incidents within 24 hours" and "vendor will maintain cyber insurance with minimum coverage of $X."

OR should be weighted by obligation criticality:

`OR(v,t) = Σ(criticality_weight × enforcement_status) / Σ(criticality_weight)`

Where criticality_weight is high for notification obligations, incident response obligations, and access control obligations; medium for attestation delivery and audit rights; and low for reporting and documentation obligations.

This makes OR more actionable: instead of "40% of obligations have receded," you get "the notification obligation, which is the one that matters most during an incident, hasn't been tested in 18 months."

---

### Trust Opacity Needs a "What Would Change It?" Question

The paper defines TO as the ratio of opaque risk surface to total risk surface. This is a useful construct. But it doesn't ask the follow-up question: what would reduce this opacity?

For some opacity, the answer is "nothing you can do" — you will never have full visibility into your vendor's internal incident detection timeline. For other opacity, the answer is "exercise your audit rights" or "require the vendor to provide Layer 3 telemetry as a contractual obligation" or "participate in an industry information-sharing group for this vendor category."

The practical use of TO isn't just to compute a number — it's to identify which opacity is reducible and which isn't, and then to focus your energy on the reducible parts.

---

## Part 3: What to Do With This That the Paper Doesn't Tell You

### Start With the Vendors That Matter

The paper's implementation roadmap (Section 3.2) suggests a four-phase rollout over 6 months for Tier 1 and Tier 2 vendors. This is reasonable. But if you're reading this and thinking "I don't have 6 months," here's the shortcut:

Start with your top 10 vendors by impact. Not by spend — by impact. The vendor whose failure would stop your operations, expose your data, or trigger regulatory notification. For most organizations, that's: cloud infrastructure provider, identity provider, primary SaaS platform, payment processor, and managed security service provider (if you have one).

Compute VEDS for those 10 vendors first. You'll have partial data. You'll have to estimate TO. You'll find that CD and AD are computable from documents you already have, TD requires a conversation with your SOC, and OR requires a conversation with whoever manages the vendor relationship.

The first 10 VEDS computations will take 2-3 weeks and will surface findings that justify the full program. The paper's roadmap is correct, but it's written for organizations that need a structured rollout. If you need to demonstrate value fast, start with the 10 vendors that matter most.

---

### The VEDS Floor Contract Clause Is a Negotiation, Not a Demand

The paper proposes contract language requiring vendors to maintain a VEDS score above a floor. This is a good idea. It's also a clause that most vendors will resist, because it introduces a termination right based on a metric they don't control and may not understand.

Here's how to actually get it:

**First**, don't lead with the VEDS floor. Lead with transparency requirements. "Vendor will provide the information necessary for accepting organization to assess vendor's security posture on a quarterly basis, including but not limited to: current attestation status, incident history for the preceding quarter, material changes to subprocessors or infrastructure, and confirmation of ongoing compliance with contractual security obligations." This is easier for vendors to accept because it's about disclosure, not performance.

**Second**, introduce the VEDS floor at renewal, not at initial contracting. By renewal, you have a year or more of data. You can show the vendor their VEDS score and say "we'd like to include a floor in the renewal to formalize our mutual commitment to maintaining this level of security." Vendors who have been good partners will often accept this because it differentiates them from competitors.

**Third**, be prepared to walk away from vendors who refuse. If a vendor won't commit to maintaining a minimum security posture, that's information. It tells you they either don't believe they can maintain it, or they don't want to be held accountable if they don't. Neither is a good sign.

---

### Channel 6 Needs a Trigger That Doesn't Require Heroics

The paper describes Channel 6 (Vendor Incident Feedback) as a six-step process triggered by vendor incident disclosure or detection. The problem: in most organizations, vendor incidents are handled ad hoc. Someone from the vendor relationship team gets an email from the vendor saying "we had an incident." They forward it to security. Security looks at it and determines whether it affects the organization. By the time anyone thinks to update the risk register, the incident is 3 weeks old and the feedback loop has already failed.

Channel 6 needs an automated trigger. Something as simple as: any email to the vendor-security@yourcompany.com alias creates a ticket in the GRC platform with the Channel 6 workflow attached. The ticket can't be closed without the six steps being documented.

This is unglamorous work. It's also the difference between a closed loop and a loop that only closes when someone remembers to close it.

---

### The Board Dashboard Needs a Narrative, Not Just Metrics

The paper proposes three board metrics: VRTM, VACR, and VINC. These are good metrics. But board members don't want metrics. They want to know: "Are we safe? If not, what are we doing about it? How much will it cost?"

The VRTM heat map is useful for showing where the risk is concentrated. The VACR shows how much of your vendor population is operating on stale assurance. The VINC shows whether vendors are meeting their notification obligations.

But the narrative that ties them together is: "We have X critical vendors. Y of them have VEDS scores below the acceptable threshold. The primary driver is [attestation staleness / telemetry gaps / obligation recession]. We are addressing this through [specific actions] at a cost of [budget] and expect to improve VEDS scores to [target] by [date]."

The paper gives you the metrics. The narrative is what makes them actionable.

---

## Part 4: The Honest Limitations

### VEDS Won't Prevent Breaches

This is important to say clearly: VEDS measures the health of your vendor relationships. It does not prevent your vendors from being breached. It does not prevent attackers from exploiting vendor trust relationships. It does not eliminate the risk that a vendor you've assessed as low-risk turns out to have been compromised six months ago in a way that no attestation or telemetry would have caught.

What VEDS does is ensure that when a vendor breach happens — and it will — you have the information you need to respond quickly. You know what data the vendor had access to. You know what telemetry you have (and what you don't). You know what notification obligations exist. You know who to call.

This is not nothing. But it's not prevention. It's preparedness.

---

### VEDS Doesn't Solve Fourth-Party Risk

The paper acknowledges this in the Limitations section, but it's worth emphasizing: TO Layer 2 (fourth-party opacity) is genuinely unsolved for most organizations.

Your vendor uses AWS. AWS uses hardware from manufacturers you've never heard of. Those manufacturers use firmware from companies in countries you've never assessed. Your vendor's SOC 2 report carves out AWS. AWS's SOC 2 report carves out its hardware vendors. The chain of carve-outs goes down until it disappears into the fog of "we trust the cloud."

VEDS can measure your direct vendor's opacity. It cannot measure the opacity of the vendor's vendors' vendors. At some point, you have to accept that you're trusting the infrastructure of the internet, and that trust is not something you can assess or manage at the organizational level.

The paper says fourth-party risk requires "industry-level information sharing." This is true but incomplete. It also requires regulatory intervention — mandatory disclosure requirements for critical infrastructure providers, standardized security requirements that propagate down the supply chain, and liability frameworks that make fourth-party risk someone's problem to solve.

None of that exists yet. VEDS works with what you can measure. It doesn't pretend to measure what you can't.

---

### The VEDS Score Is Only as Good as Your Data

This is in the paper's Limitations section, but it deserves to be said louder: a VEDS score computed from bad data is worse than no VEDS score at all, because it creates false confidence.

If your vendor inventory is incomplete, your VEDS population analysis is wrong. If your contract metadata is stale, your CD scores are wrong. If your SIEM doesn't actually log what you think it logs, your TD scores are wrong. If your obligation tracker is a spreadsheet that hasn't been updated since the person who created it left, your OR scores are wrong.

The paper's implementation roadmap starts with data consolidation because that's the actual work. The formulas are elegant. The data is messy. The gap between them is where VEDS programs fail.

---

## Part 5: What I'd Actually Do

If I were implementing VEDS in a real organization, here's the sequence I'd follow:

**Month 1:** Vendor inventory and tiering. Pull every vendor with system access or data processing. Classify into Tier 1 (critical), Tier 2 (high), Tier 3 (standard), Tier 4 (low). This will take longer than you think, because vendor lists are usually spread across procurement, legal, IT, and business units, and no two lists match.

**Month 2:** Contract and attestation data collection for Tier 1 and Tier 2. Pull current contracts and latest attestations. If you don't have them, request them. The act of requesting them will surface the first findings — vendors who can't produce a current SOC 2 report, contracts that are expired, DPAs that were never signed.

**Month 3:** Compute CD and AD for Tier 1 and Tier 2 vendors. These are document-based and don't require SIEM access. The results will give you your first ranked list of vendors by contract and attestation health.

**Month 4:** Telemetry assessment for Tier 1 vendors. Work with your SOC to determine what Layer 1 and Layer 2 coverage actually exists. Don't accept "we log everything" — look at the actual rules, the actual baselines, the actual alert thresholds. The gap between "we have the data" and "we would detect an incident" is usually large.

**Month 5:** Obligation inventory and enforcement assessment for Tier 1 vendors. Talk to the people who manage each vendor relationship. Ask them: when did you last request a security report? When did you last exercise audit rights? When did the vendor last notify you of a subprocessor change? The answers will tell you the OR score without any computation needed.

**Month 6:** Compute VEDS for Tier 1 and Tier 2. Estimate TO based on the opacity framework. Integrate into risk register. Produce the first board dashboard.

**Month 7+:** Operationalize. Build Channel 6. Implement the contract clause at renewal. Calibrate the telemetry queries. Repeat quarterly.

This is a 6-month program to get to initial VEDS computation for your most important vendors. It's not fast. It's not cheap. It's the work that has to happen if you want to actually manage vendor risk rather than just document that you're aware of it.

---

## The Thing the Paper Can't Say

The paper ends with a quote about making opacity legible. It's a good quote. It captures the intellectual contribution of the work.

But here's what a research paper can't say, because research papers aren't supposed to be emotional:

**You are going to get breached through a vendor.** Not might. Will. The question isn't whether it happens. The question is whether you see it happening, whether you know what to do when you see it, and whether you've built the governance structures that turn a vendor incident into a managed response rather than a chaotic scramble.

VEDS is a tool for that. It's a good tool. It's better than what most organizations have, which is a spreadsheet of vendor names and a checkbox for "SOC 2 received: Y/N." It gives you a structured way to think about vendor risk, a quantifiable way to measure it, and a vocabulary to discuss it with your board.

But the tool only works if you use it. The formula only matters if you compute it. The dashboard only helps if you look at it. The contract clause only protects you if you negotiate it.

The decay is happening right now. In your vendors' environments, exceptions are expiring. Certifications are aging. Telemetry is going dark. Obligations are receding. Custodians are leaving. The attack surface is growing.

You can't stop it. But you can measure it. And measurement is the first step toward management.

That's what VEDS gives you. The rest is up to you.

---

## Appendix: Quick Reference — What to Do Tomorrow

If you're reading this and thinking "this is all great, but what do I actually do tomorrow," here's the answer:

1. **Pull your vendor list.** Every vendor with system access or data processing. If you don't have a single list, that's your first finding.

2. **Pick your top 5 vendors by impact.** Not spend. Impact. The ones whose failure would stop your business or trigger regulatory notification.

3. **For each of those 5 vendors, answer these questions:**
   - When was the contract last reviewed for security terms? (CD)
   - When was the most recent SOC 2, ISO cert, or pentest? (AD)
   - Do you have alert rules on vendor access to your systems? (TD)
   - When did you last enforce a security obligation in the contract? (OR)
   - What can't you see about this vendor's security posture? (TO)

4. **Score each answer 0-1.** Multiply the five scores together. That's your rough VEDS for that vendor.

5. **If any score is below 0.5, you have a finding.** Document it. Add it to the risk register. Assign an owner. Set a deadline.

That's it. That's the start. You don't need a GRC platform or a six-month program to do this. You need a spreadsheet and an hour of honesty about what you actually know versus what you've been assuming.

The paper gives you the framework. The implementation is up to you.

---

*End of Part 2.*

*The research paper told you what VEDS is. This told you what it means, what it doesn't solve, and what to do about it. The rest is execution.*

