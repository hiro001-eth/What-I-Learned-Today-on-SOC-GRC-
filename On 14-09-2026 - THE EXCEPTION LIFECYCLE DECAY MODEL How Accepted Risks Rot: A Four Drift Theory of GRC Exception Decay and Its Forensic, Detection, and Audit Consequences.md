================================================================================
ON 14-09-2026 - THE EXCEPTION LIFECYCLE DECAY MODEL
How Accepted Risks Rot: A Four-Drift Theory of GRC Exception Decay and Its
Forensic, Detection, and Audit Consequences
Author: hiro001-eth
Series: What-I-Learned-Today-on-SOC-GRC
Version: 1.1 (Research Paper - post-review revision; all six review
        improvements integrated, plus Limitations mechanism clarification)
Prequel: "Risk Acceptance Backdoors" (this repository, 10-09-2026)
================================================================================

--------------------------------------------------------------------------------
ABSTRACT
--------------------------------------------------------------------------------
The previous paper in this series established that a risk exception without
compensating detection is observationally equivalent to a backdoor. This
paper answers the natural follow-up: given that backdoors exist, how do
they rot, and what does the rot look like from each side of the house?
We introduce the Exception Lifecycle Decay Model (ELDM), a six-stage
lifecycle of every governance exception, and identify four drift
mechanisms - scope drift, temporal drift, ownership drift, and detection
drift - that operate on every exception from the day it is signed. We
formalize each drift as a measurable function, derive the compound decay
law, connect the model to incident dwell time forensics, and provide a
CISO-level reporting apparatus (metrics, dashboard structure, board
language), an audit procedure, and a detection engineering agenda. The
central claim: exceptions do not fail. They decay, on a predictable
schedule, and every department in the security organization experiences
that decay differently - the SOC as silent telemetry loss, IR as
unexplained dwell time, GRC as audit findings, the CISO as unexplained
risk posture. The ELDM is the first model that lets all four read the
same decay from their own data.

Keywords: exception management, risk decay, drift, GRC, SOC blind spots,
dwell time, audit methodology, CISO metrics

CENTRAL FORMULA:
  EDS(e,t) = SIR(e,t) · AL_n(e,t) · CC(e,t) · CL(e,t)

  Where EDS = 1 is a healthy exception and EDS = 0 is an attacker's
  door. The paper derives each component, proves the product form is
  the correct aggregation under adversarial assumptions, and shows how
  EDS maps to dwell time in post-incident forensics.

--------------------------------------------------------------------------------
1. WHY THIS PAPER EXISTS (AND WHY IT IS FOR EVERYONE)
--------------------------------------------------------------------------------
Read the backdoors paper and every department nods for a different reason.
The SOC analyst nods because they have closed ten thousand "known legacy
noise" alerts. The incident responder nods because they have stood in a
post-mortem asking why dwell time was nine months. The GRC auditor nods
because they have re-tested an exception whose scope no longer matches
its ticket. The CISO nods because they have signed an exception that
outlived its justification by two re-orgs.

What nobody has is a single model of the rotting process itself. The
literature treats exception failure as an event (expired, violated,
breached). This paper treats it as a process - continuous, measurable,
and, most importantly, PREDICTABLE. Predictable decay is the property
that converts a complaint into a control.

The contribution, stated for each audience:

  FOR THE SOC: a formal account of why alert suppression ages into
    blindness, with detection engineering countermeasures (Section 8).
  FOR IR/FORENSICS: a dwell-time explanation framework - long dwell is
    not (only) attacker skill, it is exception decay measured in months
    (Section 7).
  FOR GRC/AUDIT: an eight-step audit procedure that tests the exception
    as it exists, not as it was written (Section 9).
  FOR THE CISO: four board-presentable metrics with honest semantics
    (Section 6), and the political mechanism to transfer accountability
    for decay back to the signing layer (Section 10).

--------------------------------------------------------------------------------
2. THE SIX-STAGE EXCEPTION LIFECYCLE
--------------------------------------------------------------------------------
Every governance exception, regardless of framework (ISO 27001, SOC 2,
PCI, internal policy), traverses the same six stages:

  STAGE 0 - CREATION. A real gap is identified: a control cannot be
    applied to an asset (agent incompatibility, vendor constraint,
    migration dependency). The gap is documented with justification,
    scope, owner, expiry.

  STAGE 1 - APPROVAL. A signer accepts the risk. This is the moment of
    maximum organizational attention. The exception is fresh in exactly
    one person's mind: the signer, who will think about it for
    approximately one quarter.

  STAGE 2 - COMPENSATION (INTENDED). The stage that is supposed to
    happen and statistically does not: detection engineering restores
    observability of the waived scope. In the baseline organization this
    stage is skipped, deferred, or performed once and never re-verified.
    This is where the backdoor forms (prequel paper).

  STAGE 3 - OPERATION. The exception is live. Its decay begins. All four
    drifts (Section 3) are active from day one. Nothing in any standard
    GRC workflow measures this stage; workflows only check that a ticket
    exists.

  STAGE 4 - EXTENSION/ATTRITION. The expiry date arrives. One of three
    things happens: (a) remediation closes the gap (rare), (b) a formal
    extension is granted (visible), or (c) the expiry passes silently and
    the exception continues operating (the modal outcome - this is
    attrition, the exception outlives its authorization without a
    decision).

  STAGE 5 - CLOSURE OR INCIDENT. The exception either finally closes,
    or it appears in an incident post-mortem. These are the only two
    exits. There is no third path where an exception quietly validates
    itself back into health.

Two structural facts fall out of the lifecycle framing:

  FACT 1: The exception spends almost all of its life in Stage 3, which
    is the stage no workflow measures. Governance instruments (registers,
    dashboards, audit schedules) are dense at Stages 0-1 and absent at
    3-4. The decay occurs precisely in the unmeasured interval.

  FACT 2: Compensation (Stage 2) is the only stage that fights decay,
    and it is the least enforced. This asymmetry - decay is structural,
    compensation is optional - is the engine of the entire model.

--------------------------------------------------------------------------------
3. THE FOUR DRIFT MECHANISMS
--------------------------------------------------------------------------------
Each drift is a process by which the exception's operational reality
diverges from its recorded form. Each has a mechanism, the attacker's
gain, a signature visible in one department's data, and a measurable
function.

--------------------------------------------------------------------------------
3.1 SCOPE DRIFT
--------------------------------------------------------------------------------
DEFINITION: The set of assets, users, or behaviors actually covered by
the exception diverges from the scope recorded in the ticket.

MECHANISMS:
  - Expansion: the excepted asset is copied, imaged, restored, or
    re-IP'd; the new instance inherits the weakness but not the ticket's
    precision. A "BA-14 only" exception silently covers the VM clone
    BA-14-R and the DR replica.
  - Creep: adjacent teams observe the exception and treat it as
    precedent. "No MFA for the billing app" becomes "no MFA for billing
    contractors," then "no MFA for the billing VLAN."
  - Migration residue: the original asset is decommissioned (the
    exception's justification is now void) but the exception record is
    never closed, and the scope string still matches live assets via
    wildcard or subnet notation.

ATTACKER GAIN FROM SCOPE DRIFT:
  Scope phantoms are assets with full exclusion coverage but no
  authorization. An attacker doing passive reconnaissance cannot
  distinguish a phantom from an unmonitored system - because they are
  operationally identical. The phantom extends the attacker's
  unobserved operating space without requiring any additional
  compromise. Every scope phantom is free lateral movement surface that
  the attacker did not have to earn.

SIGNATURES:
  - SOC: suppression rules keyed to the ticket's scope string match
    assets that were never approved.
  - Audit: re-testing the exception against the recorded scope passes;
    testing it against actual network inventory fails.
  - IR: forensics reveal the compromised asset was "in scope of an
    exception nobody had looked at in two years."

MEASURE: Scope Integrity Ratio SIR(e) =
  |assets_currently_matching_scope(e) INTERSECT assets_approved(e)|
  ---------------------------------------------------------------
       |assets_currently_matching_scope(e)|
SIR = 1.0 at creation; the ELDM predicts monotone decline. Any asset in
the matching set but not the approved set is a SCOPE PHANTOM - an
unauthorized acceptance operating under an authorized signature.

--------------------------------------------------------------------------------
3.2 TEMPORAL DRIFT
--------------------------------------------------------------------------------
DEFINITION: The exception continues to operate after its authorization
has lapsed, without a recorded renewal decision.

MECHANISMS:
  - The expiry passes during a busy quarter. Nobody is notified because
    no system ties expiry to an enforced action.
  - Renewal happens informally (email, verbal) and is never transcribed.
  - The renewal IS transcribed but with a new expiry that is itself
    never enforced - each extension resets a clock that no one watches.

ATTACKER GAIN FROM TEMPORAL DRIFT:
  Authorization lag converts a time-limited risk acceptance into a
  permanent one. The attacker who discovers an excepted asset at
  month 25 (AL=300) is operating under an acceptance that expired 300
  days ago with no human review. The window that was supposed to close
  stayed open indefinitely. Temporal drift is the mechanism by which
  "acceptable for 90 days" becomes "acceptable forever."

SIGNATURES:
  - GRC: register shows "expires 2024-06-30, status: open"; current
    date 2026. The register's own metadata contradicts itself and no
    report flags it.
  - Audit: sampled exceptions show a bimodal age distribution - many
    fresh, a fat tail older than 24 months. The tail IS temporal drift.
  - CISO: the quarterly risk report counts open exceptions as a stable
    number, hiding that the composition has rotted.

MEASURE: Authorization Lag AL(e) = max(0, days_since(expiry(e))) when
no extension record exists; AL = 0 when a valid extension covers t.
Model extension chains explicitly: an exception renewed k times has a
chain length k, and closure probability falls ~ 1/k (each renewal
lowers the odds of ever remediating - renewal is the organizational
mechanism by which exceptions convert from "debt" to "architecture").

--------------------------------------------------------------------------------
3.3 OWNERSHIP DRIFT
--------------------------------------------------------------------------------
DEFINITION: The humans responsible for the exception - owner, signer,
and the engineer who understood why it existed - change roles or leave,
and their replacements inherit a record, not an understanding.

MECHANISMS:
  - The owner who wrote the justification rotates to another team. The
    replacement inherits a ticket that says "migration planned Q2 2024."
    The migration was cancelled in an email thread the replacement never
    saw.
  - The signer leaves the organization. Renewal decisions now default to
    "extend," because no one currently employed remembers the risk
    well enough to argue for remediation spend.
  - The engineer who built the compensating detection (if any) leaves;
    the rule rots silently (bridges to Detection Drift, 3.4).

ATTACKER GAIN FROM OWNERSHIP DRIFT:
  An unowned exception has no incident response path. When the SOC
  detects something on an excepted asset and escalates to the owner,
  the escalation bounces. The analyst closes the ticket. The attacker
  continues operating. Ownership drift does not create blindness - it
  destroys the response chain that acts on what is seen. Seeing an
  attack and having nowhere to escalate it is functionally equivalent
  to not seeing it.

SIGNATURES:
  - SOC: escalation to the "exception owner" bounces or goes unanswered;
    analysts learn to close tickets instead.
  - GRC: the justification text references projects, systems, or people
    that no longer exist. A dead reference in the justification field is
    the fossil record of ownership drift.
  - CISO: renewal meetings get shorter every cycle - from "should we
    remediate" to "approved, next" in eighteen months.

MEASURE: Custodial Continuity CC(e) = fraction of {owner, signer,
technical-custodian} roles occupied by the same person (or documented
successor briefing) as at creation. CC decays stepwise at re-org events.
The ELDM's prediction, testable in register history: when CC drops, the
exception has effectively become unowned, and unowned exceptions are
never remediated - they are only ever extended or breached.

--------------------------------------------------------------------------------
3.4 DETECTION DRIFT
--------------------------------------------------------------------------------
DEFINITION: Whatever compensation was built at Stage 2 silently degrades
to non-functionality while remaining nominally "in place."

MECHANISMS:
  - Rule rot: the analytic references an IP, hostname, or account name
    that changed. The rule runs every night, matches nothing, and is
    never audited for liveness. It is a placebo control.
  - Telemetry rot upstream: the log source the rule depends on (a
    firewall's flow export, an app's auth log) stops shipping - agent
    upgrade, license change, config drift - and the rule's input silently
    goes dark.
  - Disposition rot: alerts the compensation DOES still generate are
    closed as noise by analysts who joined after the exception and were
    never briefed on it. The detection technically fires; the SOC
    socially suppresses it. (This is the C3 property of the backdoors
    paper, now understood as a decay endpoint, not a constant.)

ATTACKER GAIN FROM DETECTION DRIFT:
  A compensation rule with CL=0 is not a failed control. It is an
  actively misleading one. The GRC dashboard shows it as "compensating
  control: in place." The SOC dashboard shows the rule as "enabled."
  Both are true. Neither reflects that the control has been watching
  nothing for nine months. The attacker gains not just unobserved
  access but documented assurance that they are being watched - which,
  when the record surfaces in post-incident forensics, accelerates the
  attribution inversion the prequel paper described.

SIGNATURES:
  - SOC: a rule with zero escalations in 12 months is either perfectly
    compensating or perfectly dead. Nothing distinguishes the two cases
    without a coverage test.
  - IR: post-mortem finds the "compensating control" was listed as
    operational but had produced no observable output since a date
    months before the intrusion began.
  - Audit: control tests pass on documentation, fail on execution.

MEASURE: Compensation Liveness CL(e) in [0,1], the product of:
  - input liveness (are the rule's log sources shipping? 0 or 1),
  - match liveness (does a coverage test - atomic technique against the
    scope - produce a fired alert? pass/fail within validity window),
  - disposition liveness (of alerts fired in the trailing 90 days, what
    fraction were escalated rather than auto-closed? continuous).
CL = 1 only if all three hold. This is the strictest of the four drift
measures, and intentionally so: detection drift is the drift that kills.

--------------------------------------------------------------------------------
4. THE COMPOUND DECAY LAW
--------------------------------------------------------------------------------
Define the Decay State of exception e at time t as the vector
D(e,t) = [SIR(e,t), AL_n(e,t), CC(e,t), CL(e,t)] with each component
normalized so that 1 = perfect health and 0 = fully decayed
(SIR as defined; AL normalized as 1/(1+AL/90); CC as the fraction;
CL as defined).

DEFINITION (Exception Decay Score):
  EDS(e,t) = SIR · ALn · CC · CL        (product form)

The product form is the load-bearing modeling decision, and it deserves
its own paragraph of defense. The four drifts are not independent
failures that could be averaged; they are a serial chain on the same
artifact. Scope drift without detection drift is an auditor's problem.
Detection drift without ownership drift is a tooling problem. But SCOPE
drift (wider exposure) TIMES DETECTION drift (blinder watch) TIMES
OWNERSHIP drift (nobody to call) is the exact compound condition of the
backdoors paper's C1-C4. Averaging would let three healthy drifts mask
one fatal one. Multiplication encodes the truth of the object: an
exception is as healthy as its WEAKEST load-bearing mechanism, because
the mechanisms are the attacker's options, and the attacker takes the
weakest.

THE DECAY LAW (empirical prediction): plot EDS(e,t) over the population
of exceptions and fit:
  EDS_population(t) ~ a * exp(-t / T_decay) + b
with predicted T_decay in the 9-18 month range for uncompensated
exceptions and significantly longer for compensated ones (CL ~ 1 pins
one factor high and slows apparent decay - compensation does not stop
the other three drifts but it caps their blast radius).

TESTABLE PREDICTIONS (pre-registered):
  P1: EDS distribution across a real register is bimodal - a young,
      healthy cohort and a decayed long-tail. (Null hypothesis: uniform
      decay, which the product form predicts against.)
  P2: The long-tail cohort correlates with incident-relevant assets in
      post-mortem data at rates above base rate.
  P3: CL is the single strongest predictor of incident involvement
      (compensation is the only stage that fights decay).
  P4: Renewal chain length predicts permanent status: the probability
      an exception is ever remediated falls ~geometrically in chain
      length.

--------------------------------------------------------------------------------
5. THE ROT TIMELINE
--------------------------------------------------------------------------------
TABLE 1 - EXCEPTION DECAY TIMELINE (composite, illustrative; component
values are model estimates for the narrative that follows)

Month | Event                             | SIR  | AL_n | CC   | CL   | EDS
------|-----------------------------------|------|------|------|------|------
0     | Creation WITH compensation        | 1.00 | 1.00 | 1.00 | 1.00 | 1.00
0     | Creation WITHOUT compensation     | 1.00 | 1.00 | 1.00 | 0.00 | 0.00
3     | Adjacent team scope creep begins  | 0.95 | 1.00 | 1.00 | 0.90 | 0.85
6     | First renewal (chain length 1)    | 0.95 | 1.00 | 1.00 | 0.90 | 0.85
9     | Owner rotates out                 | 0.95 | 1.00 | 0.66 | 0.90 | 0.56
12    | Log source stops shipping         | 0.90 | 1.00 | 0.66 | 0.00 | 0.00
15    | Asset cloned, phantom created     | 0.70 | 1.00 | 0.66 | 0.00 | 0.00
18    | Analysts suppress residual alerts | 0.70 | 1.00 | 0.50 | 0.00 | 0.00
24    | Expiry passes silently (AL=300)   | 0.65 | 0.23 | 0.50 | 0.00 | 0.00
30    | Attacker finds phantom asset      | 0.65 | 0.23 | 0.33 | 0.00 | 0.00
39    | Incident                          |  -   |  -   |  -   |  -   |  -

The table carries two arguments by itself. First: the moment CL hits 0
at month 12, EDS collapses to 0 regardless of every other component -
the product form made visible. Second: the uncompensated exception
(row 2) starts at EDS 0. A skipped Stage 2 is not a debt to be paid
later; it is decay at inception.

THE TIMELINE, NARRATED:

Month 0:   Exception created. Justification fresh. Signer attentive.
           SIR=1, AL=0, CC=1, CL=1 (if compensated; else CL=0 from day
           one - a skipped Stage 2 decays from the start).
Month 3:   Signer's attention moves on. First informal "temporary"
           workaround discovered by adjacent team. SIR 0.95.
Month 6:   First expiry approaches. Renewal meeting takes 20 minutes;
           extension granted. Chain length 1. AL resets (formally).
Month 9:   Owner rotates to new team. Justification references a person
           who no longer works there. CC 0.66.
Month 12:  Compensating rule's log source silently stops shipping
           during an unrelated upgrade. Input liveness 0. CL 0.
Month 15:  Asset cloned for a project; clone matches the scope's subnet
           string. SIR 0.7. Two scope phantoms now live under the
           signature.
Month 18:  Analysts hired since month 0 close the exception's residual
           alerts as noise. Disposition liveness ~0. CL remains 0.
Month 24:  Second expiry passes silently; renewal by email, never
           transcribed. AL 300. EDS ~ 0.
Month 30:  Attacker finds the phantom asset by reconnaissance (the
           absence is legible; prequel paper, Corollary 1). Dwell time
           begins.
Month 39:  Incident. Post-mortem: "unmanaged legacy asset." The
           exception record is produced as evidence the risk was "known
           and accepted." Attribution inversion executes (prequel
           paper, Corollary 2).

This timeline is not a story about negligence. Every actor behaved
reasonably at every step. That is the finding: reasonable behavior,
composed over 39 months, reliably produces a backdoor. Decay is the
default outcome of the system's design, which is why it must be
measured, not moralized.

--------------------------------------------------------------------------------
6. CISO REPORTING APPARATUS (BOARD-LEVEL)
--------------------------------------------------------------------------------
Four metrics. Each is honest about what it is; that honesty is what
makes them board-safe. Three measure stock (the state at a point in
time); one measures flow (the direction of travel).

METRIC 1 - DECAYED EXCEPTION COUNT (DEC). [stock]
  Number of exceptions with EDS < 0.5. One number, one trend line,
  one sentence for the board: "We are currently carrying N accepted
  risks whose recorded form no longer matches their operational reality."
  Semantics: exposure, not blame.

METRIC 2 - PHANTOM ASSET COUNT (PAC). [stock]
  Total scope phantoms across all exceptions: assets operating under
  an accepted-risk signature that no signer ever approved. This is the
  metric with the sharpest political edge, because it reframes audit:
  the audit finding is no longer "your exceptions are old," it is "your
  network contains unauthorized risk acceptances wearing authorized
  ones' signatures." That sentence survives translation to any board.

METRIC 3 - COMPENSATED FRACTION (CF). [stock]
  From the Compliance Debt metric (companion paper): fraction of
  accepted risk that is tested-observed. CF trend is the single best
  one-line answer to "are we getting safer?" because it moves only
  when real engineering work happens - it cannot be gamed with
  documentation (k_i requires a passing coverage test).

METRIC 4 - REMEDIATION VELOCITY RATE (RVR). [flow]
  RVR = (exceptions closed by remediation this quarter) /
        (new exceptions opened this quarter)

  RVR > 1.0: the organization is paying down exception debt.
  RVR = 1.0: exception debt is stable.
  RVR < 1.0: exception debt is accumulating faster than remediation.

  Board language: "Our current RVR is 0.6. For every three new
  exceptions we open, we close two by remediation. At this rate,
  exception debt grows by approximately 40% annually. To stabilize at
  current levels, we need to increase remediation capacity by 40% or
  reduce new exception intake by the same amount."

  Why RVR is non-negotiable: DEC tells you how many are sick. PAC
  tells you how many phantoms exist. CF tells you how many are
  compensated. RVR tells you whether you are getting better or worse.
  Without RVR, the board can see the state but not the direction.
  Direction is what drives budget decisions.

DASHBOARD STRUCTURE (one page, quarterly):
  - Top: DEC and PAC, trended 8 quarters, with RVR as the directional
    arrow beside them.
  - Middle: EDS histogram of the register (the bimodal shape of P1 is
    itself the report - show the long tail, don't average it away).
  - Bottom: CF per business unit, with paydown plan. Units pay down
    debt by either remediating (close the exception) or compensating
    (build the detection). Both are real work; the dashboard forces
    the choice.

--------------------------------------------------------------------------------
7. FOR IR: THE DWELL-TIME CONNECTION
--------------------------------------------------------------------------------
Standard dwell-time analysis attributes long dwell to attacker
sophistication. The ELDM proposes a measurable decomposition:

  observed_dwell = attacker_stealth + sensor_decay + disposition_decay

Attacker stealth is what your tooling fights. Sensor decay is CL=0 -
the watch that stopped watching. Disposition decay is analysts closing
what still fires. The ELDM's claim: in incidents touching excepted
assets, the sum of the last two terms dominates, and both are visible
in the record BEFORE the incident:

  - Query: for the incident asset, was any exception's scope matching it
    at intrusion time? (SIR data answers this retroactively if the
    scope strings were versioned - which Section 9's procedure starts
    doing.)
  - Query: what was CL of the matching exception in the 12 months
    pre-incident? If CL=0 for those 12 months, the dwell time is
    substantially a decay artifact - and the post-mortem should say so,
    in those words, with numbers.

The forensic deliverable: a Dwell Decomposition Report as a standard
post-mortem section. Its existence changes incident culture from "the
SOC missed it" to "here is the exact month the watch stopped watching,
and here is the register record that shows it was structurally
predictable." That is the paper's gift to the IR department: a
vocabulary that converts shame into engineering.

--------------------------------------------------------------------------------
8. FOR THE SOC: DETECTION ENGINEERING AGAINST DECAY
--------------------------------------------------------------------------------
  DE-1 (Liveness heartbeat): every compensating rule runs a weekly
      self-test - inject a synthetic marker matching its logic, assert
      it fires. A rule that cannot see its own test signal is dead,
      regardless of its "enabled" flag. Output feeds CL directly.
  DE-2 (Scope reconciliation): nightly diff of exception scope strings
      against live asset inventory. New matches not in the approved set
      -> phantom alert (this is PAC's sensor). Subnet and wildcard
      scopes get an annual mandatory re-approval - they are phantom
      factories.
  DE-3 (Disposition audit): monthly sampling of auto-closed alerts on
      excepted scopes; a sampled alert re-evaluated as escalation-worthy
      decays the suppression entry's trust score. Suppression entries
      are themselves decaying objects and should carry their own EDS.
  DE-4 (Ownership ping): exceptions whose owner field resolves to a
      departed employee or a defunct distribution list are flagged.
      An exception whose escalations bounce is, operationally, an
      exception with no owner - treat CC as unmeasurable and the
      exception as decayed.

--------------------------------------------------------------------------------
9. FOR GRC/AUDIT: THE EIGHT-STEP EXCEPTION INTEGRITY AUDIT
--------------------------------------------------------------------------------
A procedure that tests the exception as it exists, not as it was
written. Per-exception times are estimates with the queries of
Section 8 in place; audit time determines audit scope, so it is stated
explicitly.

  1. EXPIRY REALITY TEST [2 min]
     Does a valid, transcribed extension cover today? Email renewals do
     not count. (Temporal drift)

  2. JUSTIFICATION FRESHNESS [3 min]
     Do the people, projects, and systems named in the justification
     still exist? Dead references = the exception's original rationale
     is unverifiable. (Ownership drift)

  3. CUSTODIAN TEST [2 min effective; 24h wall-clock]
     Send a test escalation. Does a human respond within 24 hours?
     Note: the wait is wall-clock, not labor - batch across all
     exceptions and run in parallel. (Ownership drift)

  4. SCOPE RECONCILIATION [5 min with query]
     Run the asset inventory query against the scope string. List
     phantoms. (Scope drift)

  5. COMPENSATION LIVENESS [5 min]
     Run the coverage test. Verify input sources shipping. Review
     trailing-90-day disposition of the rule's alerts. (Detection
     drift)

  6. RENEWAL CHAIN REVIEW [1 min]
     Count chain length. Chain >= 3 triggers mandatory
     remediation-or-board-level-reacceptance decision. (Temporal +
     ownership drift compound)

  7. NEIGHBORHOOD CHECK [2 min with query]
     Pull exceptions sharing assets, owners, or justifications with
     this one. Decayed exceptions cluster - they share the re-orgs
     and migrations that cause drift. An exception never rots alone.
     (Superadditivity, companion paper)

  8. EDS SCORING [2 min]
     Compute the four components. Record the vector, not just the
     score - the vector says WHICH drift to fix.

  TOTAL PER EXCEPTION: ~22 minutes
  EXCEPTIONS PER ANALYST-DAY: ~20
  QUARTERLY CAPACITY (two analysts, one day each): ~40 exceptions
  TRIAGE RULE: sort the register by (age x chain_length) as a proxy
    score and audit the bottom quartile first - that is where the
    decayed exceptions are.

Audit finding language, upgraded: not "exception E-2214 expired," but
"exception E-2214 exhibits scope drift (3 phantom assets), temporal
drift (untranscribed renewal), ownership drift (custodian departed),
detection drift (compensation input dark since <date>). EDS 0.08.
Recommend: remediation, or board-level re-acceptance with rebuilt
compensation." Findings like this are un-ignorable because every clause
is independently verifiable by the auditee - and because the per-step
time model makes the audit schedulable, which is the difference between
a procedure that gets read and a procedure that gets executed.

--------------------------------------------------------------------------------
10. GOVERNANCE INTERVENTIONS (WHAT ACTUALLY SLOWS DECAY)
--------------------------------------------------------------------------------
  I1: Expiry must be an ACTION, not a date. The exception auto-closes
      at expiry unless a renewal decision is recorded in the system of
      record. Attrition (the modal Stage-4 outcome) becomes impossible
      by construction, not by diligence.
  I2: Renewal cost escalates with chain length. First renewal: manager.
      Third: director. Fifth: the renewal decision includes the
      accumulated EDS history and the phantom count. Politically, this
      converts "extend forever" into "explain forever."
  I3: Phantom assets are unauthorized acceptances. Declare, in policy,
      that an asset matching an exception scope without being in its
      approved set inherits NO protection from the exception - its
      alerts escalate normally. This single clause kills the attacker's
      favorite feature of scope drift (the phantom's free pass).
  I4: The attribution contract (from the prequel paper) extended with
      decay data: when an incident touches a decayed exception, the
      post-mortem's Dwell Decomposition Report names the drift
      mechanisms with dates. Accountability follows the decay curve,
      not the org chart.
  I5: Compensation is a stage, not a suggestion. An exception cannot
      reach "approved" without a scheduled coverage test. This one
      workflow change relocates the organization from the decay-default
      regime to the compensated regime, and CF becomes the proof.

--------------------------------------------------------------------------------
11. LIMITATIONS (STATED FOR THE AUDIENCE THAT READS THEM)
--------------------------------------------------------------------------------
  - The product form of EDS is a modeling decision, defended on
    attacker-option grounds, not derived. Alternative aggregations
    (min, weighted sum with interaction terms) should be compared in
    Phase 2 of the empirical work.
  - T_decay and the P1-P4 predictions are pre-registered hypotheses,
    not findings. The decay timeline in Section 5 is a composite
    narrative for exposition; its steps are drawn from common patterns,
    and the paper's credibility rests on testing them, not on their
    plausibility.
  - SIR measurement requires versioned scope strings; organizations
    whose registers do not version scopes must begin doing so (step 4
    of the audit procedure doubles as the instrumentation plan).
  - CL's disposition component involves analyst behavior; measure it
    with aggregate statistics, never individual surveillance - because
    the moment analysts know individual disposition is being measured,
    they rationally escalate everything to protect their own CL score,
    the metric's signal is destroyed, and the organization is left with
    a dashboard that says everything is fine while nothing is measured.
    The protection is structural (aggregate-only, sampled, anonymized),
    not a matter of analyst goodwill.
  - Cross-framework generalization (ISO vs SOC 2 vs PCI exceptions) is
    claimed on structural grounds; validate per framework before
    quoting framework-specific numbers.

--------------------------------------------------------------------------------
12. CONCLUSION
--------------------------------------------------------------------------------
The risk acceptance backdoor paper showed that governance can sign
blindness into existence. This paper shows what happens next: the
signature decays on a schedule. Scope widens past what was approved,
time outlives what was authorized, ownership dissolves until no one
remembers why, and detection rots until the compensation is a
documentation artifact. Four drifts, one artifact, and a product law
that says the attacker only needs the weakest of them.

Every department already lives inside this model. The SOC closes the
alerts; IR writes the dwell time into post-mortems; GRC files the
expired ticket; the CISO carries a number that does not mean what it
says. What has been missing is the shared object - the exception as a
decaying physical thing, with a measurable state and a predictable
future. The ELDM is that object. It converts the oldest complaint in
security governance ("we accepted this risk years ago and nobody owns
it anymore") into a control with a dashboard, an audit procedure, and
a decay curve that can be bent - measurably, quarterly, and in front
of the board.

The ELDM answers the diagnostic question: how do we measure exception
decay before it becomes incident dwell time? The governance
interventions in Section 10 identify what bends the decay curve. What
the model cannot yet describe is the systematic feedback architecture
by which incident intelligence flows back into the exception register -
the mechanism by which the IR team's post-mortem findings update the
GRC team's risk picture before the next attacker arrives. That is the
next paper. The closed loop is the cure; the ELDM is the diagnosis.
Both are required - a decay model without a remediation architecture
is a better way to measure a problem that remains unsolved. The
research continues.

--------------------------------------------------------------------------------
LINKS IN THIS REPOSITORY
--------------------------------------------------------------------------------
  Prequel (the object whose decay this paper models):
    "Risk Acceptance Backdoors, Exception Attack Trees, and Compliance
     Debt" (10-09-2026)
  Methodological siblings:
    "The SOC-GRC Entropy Model v3.0" (decay is entropy made visible;
     EDS is the per-exception entropy state)
    "The Detection Paradox" (DE-3's disposition decay; KPI gaming as a
     drift accelerator)
    "Velociraptor unified detection-forensics framework" (the lab
     stack for coverage testing and DE-1 liveness heartbeats)
  Next in series:
    "The IR-GRC Closed Loop" (announced in Section 12 - the feedback
     architecture that bends the decay curve)

--------------------------------------------------------------------------------
END OF PAPER - hiro001-eth - 13-09-2026 (v1.1)
"Exceptions do not fail. They decay. The only choice is whether you
measure the decay or inherit it."
======================================================================
