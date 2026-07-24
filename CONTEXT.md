# SOC Ticketing

The domain language for a Security Operations Center (SOC) ticketing system: alerts arrive from monitoring, get triaged, and — when real — become tickets that move through a fixed lifecycle from detection to containment to closure. This file is the glossary. It defines what terms *mean*; it is not a spec and carries no implementation detail.

## Case lifecycle

**Alert**:
A single raw detection pulled from monitoring (e.g. a Wazuh/OpenSearch alert) that has not yet been judged. An alert is a candidate, not a case.
_Avoid_: Event (an Alert is pre-judgment; "Event" is a disposition applied later), detection

**Triage**:
The act of judging whether an Alert is real. Produces a disposition of Event or Incident, or an escalation to Tier 2.
_Avoid_: Assessment, review

**Alert Triage** vs **Manual Triage**:
Alert Triage judges an Alert that arrived automatically from monitoring. Manual Triage logs a triage decision for a report that arrived through a human channel (email, phone, external org) before any Alert exists. They are two intake queues feeding the same disposition.
_Avoid_: using "triage" bare when the queue matters

**Incident**:
The disposition for an Alert/report judged to be a real, actionable security case. An Incident proceeds to containment and becomes a Ticket.
_Avoid_: True Positive, TP, TRUE_POSITIVE (all legacy encodings of this same disposition)

**Event**:
The disposition for an Alert/report judged benign. An Event is closed without containment.
_Avoid_: False Positive, FP, FALSE_POSITIVE (all legacy encodings of this same disposition)

**Classification**:
The Event-or-Incident label carried on a Ticket. Set by Tier 1, revisable by Tier 2. Gates which lifecycle transitions are legal.
_Avoid_: Disposition, verdict, TP/FP

**Ticket**:
A case opened for an Incident. Carries the full lifecycle, ownership, OLA clocks, and audit trail. Only Incidents become Tickets; Events never do.
_Avoid_: Case, issue, report

**Ticket Reference**:
The permanent, public identifier for exactly one Ticket. It is used when people, reports, notifications, and integrations refer to that Ticket, and never changes when the Ticket joins a Project Incident.
_Avoid_: Database ID, case number, bundle reference

**Manager Triage Review**:
The SOC Manager's pre-containment checkpoint every Incident passes before it reaches a handling lane. The manager flags Emergency (or not) and forwards the Ticket to the lane Tier 1 already chose — the manager cannot change the lane. Held in the `PENDING_MGR_TRIAGE` state; a blocking step, not a parallel one.
_Avoid_: Manager approval (that is the separate emergency gate at closing), triage (reserved for the Alert/report judgment)

**Handling Route**:
The lane Tier 1 picks for an Incident — System Admin or Direct-to-Owner — recorded on the Ticket (`t1_route`) so the Manager Triage Review can forward it to the fixed destination. Chosen at Ticket creation or at Tier 1 review; never changed by the manager.
_Avoid_: Assignment (assignment is the specific admin/owner, not the lane), disposition

**Containment**:
The system-admin action that stops or limits an active Incident, reported back to the SOC as a containment report. The middle phase of a Ticket's lifecycle.
_Avoid_: Remediation (remediation is the later fix-up summary), mitigation, resolution

## Grouping

**Project Incident**:
One real-world Incident that hit multiple systems, worked as several linked Tickets — one per affected system. The grouping and rollup unit. It has one group coordination gate, Project Review, but Containment and closure remain on each Member Ticket.
_Avoid_: Case Bundle is an accepted synonym in code, but prefer "Project Incident" in prose

**Project Review**:
The SOC Manager's one-time, group-level Manager Triage Review for a Project Incident. It records one Normal/Emergency assessment and forwards every waiting Member Ticket to its already-selected handling route. A later reassessment changes the Emergency state of all active members together.
_Avoid_: member review, group approval

**Member Ticket**:
A Ticket that belongs to a Project Incident. Each member is contained and closed independently on its own OLA clock; only its target (device / IP / owner / admin) differs from its siblings.
_Avoid_: Child ticket, sub-ticket

**Member Reference**:
The Project Incident Reference plus a member suffix, identifying a Ticket's place in that group. It supplements the Ticket Reference; it does not replace it.
_Avoid_: Ticket Reference, Ticket ID

**Subtask**:
A work stream spawned off a single Ticket, tracked independently of the parent Ticket's status. Two kinds: the SOC-spawned **Investigation** / **Countermeasure**, and the manager-spawned **Response Request** (below).
_Avoid_: Task, linked ticket

**Response Request**:
A specialised Subtask the SOC Manager spawns to a response team — VA / Pentest and Infrastructure Security route to the Red Team Manager; Forensics / RCA routes to the Forensic Analyst. It belongs to one Member Ticket, even inside a Project Incident, and runs in parallel to that Ticket's Containment. It is auto-assigned to the sole holder of the target role (or picked when several exist). While any Response Request is still open, its parent Incident cannot be approved (closed) — Event-close is exempt.
_Avoid_: Investigation (that is the SOC-side subtask), escalation, ticket

## People and roles

**Tier 1**:
The SOC analyst who opens Tickets, sets Classification, reviews returned containment, and verifies. The default owner of the Tier-1 side of the lifecycle. Only the original creator may drive their own Ticket's Tier-1 steps.
_Avoid_: T1 analyst (T1 is fine as shorthand), first responder

**Tier 2**:
The SOC analyst who handles escalated cases — may only return a case to Tier 1 or close it as an Event.
_Avoid_: T2, senior analyst

**SOC Manager**:
The role that runs the Manager Triage Review — flagging Emergency and forwarding every Incident to its handling lane before containment — and later verifies and approves emergency Tickets before they may close.
_Avoid_: Supervisor, lead

**System Admin**:
The owner of an affected system who performs Containment. Sees only the Tickets assigned to them.
_Avoid_: Sysadmin, admin (ambiguous with Django superuser), IT

**System Owner**:
The business owner of an affected system, notified when their system's Ticket opens and closes. Distinct from the System Admin, who does the technical work.
_Avoid_: Owner (bare), stakeholder

**Executive**:
A read-only role that consumes the dashboard rollups, not individual Tickets.
_Avoid_: Manager (reserved for SOC Manager)

**Forensic Analyst**:
A response-team role that receives Forensics / RCA Response Requests. Not a SOC member: sees only the Tickets that carry a Response Request assigned to them, and works from the "My Requests" queue.
_Avoid_: Investigator, SOC analyst

**Red Team Manager**:
A response-team role that receives both VA / Pentest and Infrastructure Security Response Requests and works them directly. Not a SOC member: sees only the Tickets with a Response Request assigned to them.
_Avoid_: Pentester, Red Team (bare — this is the receiving manager)

## Timing and priority

**OLA** (Operational Level Agreement):
The internal time target a case must meet — a triage OLA (time to raise/decide) and, for higher severities, a contain OLA (time to resolve). Measured from when the incident occurred, not when the Ticket was filed.
_Avoid_: SLA (this system's targets are internal operational commitments, not customer-facing service agreements), deadline (bare)

**OLA Breach**:
A case that missed its OLA target. Triage breach is fixed at issue time; contain breach counts live against the deadline.
_Avoid_: Overdue, late, violation

**Severity**:
The impact ranking of a case — Critical, High, Medium, Low, or Unknown. Drives OLA targets and manager-verification routing.
_Avoid_: Priority, criticality, urgency

**Unknown (severity)**:
An explicitly unclassified severity — the analyst cannot yet rank it. It is *not* low-risk; it sorts last only for queue ordering and never auto-routes to the SOC Manager.
_Avoid_: treating Unknown as equivalent to Low

**Emergency**:
A flag only the SOC Manager may set or clear — ruled at the Manager Triage Review before the Ticket reaches its handling lane, and adjustable by the manager at any later stage. For a Project Incident it is decided and reassessed at the group level, then shared by all active Member Tickets. Forces a Ticket through SOC Manager verification before close, regardless of Severity.
_Avoid_: Urgent, priority flag, critical flag

## Detection detail

**Source**:
The channel an Alert or report arrived through — SIEM, Admin, Threat Intelligence, Email, Phone, User Report, External, Other. It answers *how it reached the SOC*, never *what the threat is*.
_Avoid_: issue_type (the model field name — misleading; it is the Source), origin, channel (informal)

**Detailed Issue**:
The threat category assigned to a case (Reconnaissance, Malicious Logic, DoS, …), refined by a more specific sub-type. This is *what the threat is*, as opposed to Source.
_Avoid_: Issue type, category (ambiguous), attack type
