# Workflow Change Log

> **Audience:** developers changing the state machine · **Status:** Current · **Last updated:** 2026-07-23
> **Current-state reference:** [ticket-lifecycle-states.md](ticket-lifecycle-states.md)

A dated record of every workflow redesign and amendment, newest first, with the
reasoning behind each. Read this to understand *why* the state machine has its
current shape; read `ticket-lifecycle-states.md` for *what* that shape is today.

Apps involved: `apps/incidents` (tickets + manual triage), `apps/wazuh_ingest`
(SIEM alert triage + escalation queue), `apps/accounts` (roles/tiers),
`apps/dashboard` (aggregates).

---

## 0. 2026-07-14 update — SOC Manager pre-containment review

Layered on top of the 2026-07-08 redesign below. Diagram source of truth:
`ticket-lifecycle-states.md`. Migration `incidents/0044` (additive: new `t1_route`
field + `PENDING_MGR_TRIAGE` status choice + `MANAGER_TRIAGE_PENDING` template key).

**New blocking state `PENDING_MGR_TRIAGE`.** Every Incident now passes through the
SOC Manager *before* it reaches a handling lane. The manager flags Emergency
(yes/no) and forwards to the lane Tier 1 already chose; they cannot divert it.
A new `Ticket.t1_route` (`ADMIN`/`OWNER`) fixes the destination and is enforced
by a deterministic guard in `can_transition_to`/`transition_to`. (Spawning a
response team from this step — VA/PT/Forensic/RCA — was a deferred future phase
at the time; it is now implemented, see §0.1.)

**FSM delta** (vs. §2b below):
- **Removed:** `NEW→{CLOSED_EVENT, AWAITING_CONTAINMENT, AWAITING_OWNER}`,
  `T1_REVIEW→{AWAITING_CONTAINMENT, AWAITING_OWNER}`.
- **Added:** `NEW→PENDING_MGR_TRIAGE` [TIER1_CREATOR], `T1_REVIEW→PENDING_MGR_TRIAGE`
  [TIER1_CREATOR], `PENDING_MGR_TRIAGE→AWAITING_CONTAINMENT|AWAITING_OWNER`
  [MANAGER, `t1_route`-guarded].
- **Event path:** a Tier 1 "Event" no longer closes directly — it escalates
  (`NEW→ESCALATED_T2`); `ESCALATED_T2→CLOSED_EVENT` closes it with **no** manager.
- **Mid-containment reclassify (new):** `CONTAINMENT_REPORTED→CLOSED_EVENT` and
  `PENDING_T2_REVIEW→CLOSED_EVENT` [TIER2] — Tier 2 flips classification→EVENT and
  closes directly, even if the emergency flag is set.
- **Unchanged:** both verification loops, `PENDING_T2_REVIEW`, `PENDING_MANAGER→APPROVED`,
  and `requires_manager_verification == is_emergency` (no severity routing).

**Emergency flag permission (tightened same day):** `can_set_emergency` is now
**SOC Manager only** (superuser bypass). The 2026-07-08 rule in §2d — any role
except an unescalated Tier 1 — is superseded. The manager rules Emergency
yes/no at the pre-containment review before forwarding, and may still adjust
the flag at any later lifecycle stage; no other role can touch it.

**Notifications:** the admin/owner assignment email now fires when the manager
forwards (not at Tier 1 routing time); a new `notify_manager_triage_pending`
alerts SOC Managers when a ticket enters `PENDING_MGR_TRIAGE`.

**Surfaces updated:** SOC Manager review panel + queue nav/badge
(`MANAGER_QUEUE_STATUSES`), T1-review Admin/Owner route selector, Tier-2
reclassify-to-Event control, create-flow copy, and the executive dashboard
(IDENTIFICATION phase + a pre-containment backlog card). Report exporter and
status badges are model-driven and needed no change.

---

## 0.1. 2026-07-20 update — Response teams (Forensic / Red Team)

Realises the deferred response-team dispatch from §0. No FSM/state change —
response work is modelled as specialised subtasks that run in parallel and gate
only the closing step. Migrations `accounts/0006` (2 role choices) and
`incidents/0045` (3 subtask-type choices + `TicketAttachment.subtask` FK + 2
template keys) — all additive.

**Two new roles** (`accounts.UserProfile`): `FORENSIC` (Forensic Analyst) and
`REDTEAM_MANAGER` (Red Team Manager). Neither is a SOC member (`is_soc` is
false); each sees only Tickets carrying a Response Request assigned to them
(`TicketQuerySet.visible_to`).

**Response Request = `TicketSubtask`** with three new types: `VA_PT` and
`INFRA_SEC` route to the Red Team Manager, `FORENSIC_RCA` to the Forensic
Analyst (`TicketSubtask.RESPONSE_ROUTING`). The SOC Manager spawns them at any
active stage; assignment auto-resolves to the sole role-holder, offers a picker
when several exist, and is blocked when none exist. The optional deliverable
file attaches via the new `TicketAttachment.subtask` FK (served through the
existing hardened `download_attachment` path).

**Approval gate:** `Ticket.has_open_response_requests` blocks **every** edge into
`APPROVED` (manager approval *and* the Tier 2 direct-close paths) while any
response request is not `DONE`; `CLOSED_EVENT` is exempt. The guard lives in
`can_transition_to`/`transition_to`, so the closing action disappears from the
UI until the request completes rather than erroring on submit.

**Notifications:** `notify_response_request_created` (assigned responder) and
`notify_response_request_completed` (SOC managers, on `DONE`).

**Surfaces updated:** manager spawn card + open-request warning on the ticket
detail, responder update panel (status / notes / file) in the subtask section,
"Response Requests" queue (`/incidents/response-requests/`) + nav badge, restricted
legacy subtask form (Investigation / Countermeasure only), a cross-cutting
"รอทีมตอบสนอง" row on the executive summary (with `?f=RESPONSE_PENDING`
drill-down), admin registration for `TicketAttachment`, and seed/test accounts.

---

## 0.2. 2026-07-23 update — Event-downgrade gate, Tier 2 claim, Tier 1 My Queue

Driven by UAT feedback. Migrations `incidents/0047`–`0051` (all additive).

### New blocking state `PENDING_MGR_EVENT_REVIEW`

Tier 2 could close an escalated Incident outright by relabelling it an Event:
`ESCALATED_T2→CLOSED_EVENT` ended the case with no further review, so a ticket
was disposable by reclassification. The manager now verifies that call.

**FSM delta:**
- **Added:** `ESCALATED_T2→PENDING_MGR_EVENT_REVIEW` [TIER2],
  `PENDING_MGR_EVENT_REVIEW→CLOSED_EVENT` [MANAGER] (confirm),
  `PENDING_MGR_EVENT_REVIEW→ESCALATED_T2` [MANAGER] (reject — flips
  `classification` back to INCIDENT so Tier 2 must handle it).
- **Conditioned:** `ESCALATED_T2→CLOSED_EVENT` now requires that the ticket was
  *not* downgraded by Tier 2. New field `classification_at_escalation` is
  re-stamped on every entry to `ESCALATED_T2`, and `Ticket.is_t2_event_downgrade`
  splits the two edges deterministically in `can_transition_to`/`transition_to`.
  Exactly one Event button is ever offered on the detail page.
- **Backwards compatible:** rows escalated before the field existed have it
  blank, are treated as *not* downgrades, and close the way they always did.

**Deliberately out of scope:** `CONTAINMENT_REPORTED→CLOSED_EVENT` and
`PENDING_T2_REVIEW→CLOSED_EVENT` still close with no manager, even when the
emergency flag is set. Same disposal risk one stage later — a scope decision,
not an oversight. Revisit if the gate proves its worth.

### Tier 2 queue claim/release

`claim_escalation` / `release_escalation` were **no-op stubs** stating that
escalation "does not require a separate claim", so any Tier 2 could act on any
queued ticket and two could review the same case at once. They are now the real
implementation (URL names unchanged): `t2_claimed_by` / `t2_claimed_at`, claimed
by a single conditional `UPDATE`, released with a mandatory reason logged to the
ticket, cleared on every transition (the queue spans three stages, so a claim
only covers the stage it was made in). Enforced via `Ticket.t2_claim_blocks` in
`transition_to`. Only *another* analyst's claim blocks — an unclaimed ticket
stays actionable, because Tier 2 also works from the ticket detail page, which
has no claim button.

### Tier 1 My Queue — Manual Triage absorbed

`T1_REVIEW` is creator-gated, so when Tier 2 returned a case only its opener
could act — and nothing told them. Tier 1 was also the only SOC role without a
work queue. `/incidents/my-queue/` now carries their own-court tickets
(`Ticket.TIER1_QUEUE_STATUSES`) plus the manual-intake queue on one page. The
historical `triage_list` URL name renders the same view, so every manual-triage
redirect and deep link still works; the **Manual Triage** menu entry is retired,
and the two case-creation entries merged into one (scope chosen inside the form,
carrying `triage_id`/`wazuh_alert` across). Tier 1 sidebar: 8 items → 6.

`TriageRecord` gained a disposal path (dismiss as junk: `decision=FP`, no
ticket) and `resolved_by`/`resolved_at`, since `claimed_by` is cleared on
disposal and a dismissal previously left no accountable owner.

### Retired, not removed

`TriageRecord`'s pre-ticket Tier 2 escalation (`DECISION_ESCALATED`,
`escalated_to`, `t2_*`) has been unreachable since the decision moved onto the
Ticket. The dead `respond_escalation` view and `is_pending_t2` are gone; the
**columns are kept** (legacy data, zero cost) but are now read-only in the
admin, which was the actual hazard — a record could be given escalation state
the app has no code to process. `final_decision` and `DECISION_ESCALATED` stay:
the first is still used so an old escalated record can be converted rather than
stranded, and dropping the second would render legacy rows as a raw code.

### Surfaces updated

Shared OLA countdown badge (`incidents/_ola_badge.html`, thresholds from
`apps/incidents/ola.py`) on all four queues, plus an OLA sort on the two that
lacked one; ticket-list breach tint corrected to the live *contain* deadline
(it measured the historical triage breach while the banner, filter and sort
measured contain — so the counts never agreed); attachment uploads gated by
workflow position with soft-delete audit; `MANAGER_QUEUE_STATUSES` and the
dashboard court/heatmap groupings extended for the new state (both guarded by
exhaustiveness tests, which caught the omission).

### Emergency assessment split (later the same day)

The pre-containment review had **two** controls writing `is_emergency`: a
standalone toggle card (visible at every stage, including terminal) and an
Emergency **checkbox** inside the forward form. Duplicated decision points, and
"Normal" was merely an unchecked box — no evidence a decision was made.

- The forward form now carries a **required two-option assessment** (Normal /
  Emergency). `assess_emergency_initial(value, user)` stamps
  `emergency_decided_by` / `emergency_decided_at` **write-once even for Normal**.
- The standalone toggle is gone. `set_emergency` / `can_set_emergency` are
  replaced by `assess_emergency_initial` + `reassess_emergency` /
  `can_reassess_emergency`.
- **Reassessment** (`reassess_emergency`) is manager-only, needs a written
  reason, logs old→new+reason, and is allowed only at an active stage **past**
  the review — **not at `PENDING_MGR_TRIAGE`, not after closure**. The one
  deliberate behaviour change: terminal tickets can no longer have Emergency
  flipped (the old `set_emergency` allowed it). Migration `incidents/0052`.
- `is_emergency` and `requires_manager_verification` are unchanged, so closure
  routing is identical.

> **Note on §0's older text below:** references to `can_set_emergency` /
> `set_emergency` and "adjustable at any stage including terminal" describe the
> pre-2026-07-23 mechanism. They are left as dated record; the rules above
> supersede them.

---

## 1. CURRENT implementation (before this change)

### 1a. Ticket states & transitions — `apps/incidents/models.py` (`Ticket`)

`status` `CharField` (`STATUS_CHOICES`), driven by `Ticket.transition_to(new_status, user, note)`
which enforces `ALLOWED_TRANSITIONS` + `TRANSITION_PERMISSIONS` and writes a `TicketLog`.

| code | label (th) | terminal |
|------|-----------|----------|
| `NEW` | แจ้งเหตุใหม่ | |
| `AWAITING_CONTAINMENT` | รอการจัดการจากผู้ดูแลระบบ | |
| `CONTAINMENT_REPORTED` | รายงานการควบคุมแล้ว | |
| `UNDER_REVIEW` | กำลังตรวจสอบ | |
| `VERIFIED` | ตรวจสอบแล้ว | |
| `APPROVED` | อนุมัติแล้ว | ✓ |
| `CLOSED_FP` | ปิด (เหตุการณ์ปลอม) | ✓ |

Old edges (`ALLOWED_TRANSITIONS`):
`NEW→AWAITING_CONTAINMENT`; `AWAITING_CONTAINMENT→CONTAINMENT_REPORTED`;
`CONTAINMENT_REPORTED→UNDER_REVIEW`; `UNDER_REVIEW→{VERIFIED, AWAITING_CONTAINMENT(reject loop), CLOSED_FP}`;
`VERIFIED→APPROVED`.

### 1b. Role / permission gating

- `apps/accounts/models.py UserProfile.role`: `SOC_STAFF`, `SOC_MANAGER`, `SYSTEM_ADMIN`, `SYSTEM_OWNER`.
  `tier` (`T1`/`T2`/blank) existed but **carried no permission weight in the ticket FSM** —
  it was only used in the manual-triage and Wazuh-escalation views.
- `Ticket.TRANSITION_PERMISSIONS` tokens: `SOC` (is_soc), `ASSIGNED_CREATOR`
  (is_soc AND `user==created_by`, applied to `CREATOR_REVIEW_STATUSES`), `ASSIGNED_ADMIN`
  (`user==assigned_admin`), `MANAGER` (is_soc_manager). Superuser bypasses all.
- Visibility: `TicketQuerySet.visible_to` — SOC sees all; system admin sees only
  `assigned_admin==user`; system owner sees `system_owner==user`.

### 1c. Where TP/FP lived

- `Ticket.disposition` = `TRUE_POSITIVE` | `FALSE_POSITIVE` | `''`. **Set by the System Admin
  at the containment step** (`ticket_detail` `action=containment`). `is_false_positive`
  property + FP-gate in `transition_to` forced FP tickets to `CLOSED_FP` only.
- `WazuhAlert.triage_status` = `PENDING|TRIAGING|TRUE_POSITIVE|FALSE_POSITIVE|ESCALATED`.
- `TriageRecord.decision` (T1) = `FP|TP|ESCALATED`; `.t2_decision` = `FP|TP`.
- Dashboard counted `disposition` TP/FP for its doughnut.

### 1d. Escalation tracking (current)

- **Alert level only.** `WazuhAlert.triage_status=ESCALATED` + `escalated_to_tier`
  (`T1|T2|MANAGER`) + claim fields. No ticket-level escalation existed, and no
  "was this ticket ever escalated" flag.
- `TriageRecord` carried a separate manual escalation (`escalated_to`, `t2_decision`).

### 1e. Backend behind the four menus (`templates/base.html`)

| Menu | url name | view |
|------|----------|------|
| **Wazuh Triage** | `triage_queue` | `apps/wazuh_ingest/views.py::triage_queue` (+ `claim_alert`, `release_alert`, `triage_action`) |
| **Manual Triage** | `triage_list` | `apps/incidents/views.py::triage_list` (+ `create_triage`, `respond_escalation`) |
| **Escalation Queue** | `escalation_queue` | `apps/wazuh_ingest/views.py::escalation_queue` (+ `claim_escalation`, `release_escalation`) |
| **เปิดเคสใหม่** (Open New Case) | `create_ticket` | `apps/incidents/views.py::create_ticket` |

`triage_action` (Wazuh) previously had three branches: `close_fp`, `escalate`, `create_ticket`.

---

## 2. TARGET workflow (implemented in this change)

### 2a. New ticket states — `Ticket.STATUS_CHOICES`

| code | meaning | terminal |
|------|---------|----------|
| `NEW` | created by T1, pre-routing (transient) | |
| `ESCALATED_T2` | escalated to Tier 2 — in the escalation queue | |
| `T1_REVIEW` | T2 returned an Incident → T1 must assign admin | |
| `AWAITING_CONTAINMENT` | assigned to System Admin | |
| `CONTAINMENT_REPORTED` | admin returned ticket → T1 verification | |
| `PENDING_MANAGER` | routed to SOC Manager for verification | |
| `APPROVED` | incident handled & closed | ✓ |
| `CLOSED_EVENT` | benign Event closed (was `CLOSED_FP`) | ✓ |

### 2b. New edges + permission tokens (`ALLOWED_TRANSITIONS` / `TRANSITION_PERMISSIONS`)

| from → to | who | meaning |
|-----------|-----|---------|
| `NEW → CLOSED_EVENT` | `TIER1_CREATOR` | T1 classifies Event, closes (terminal) |
| `NEW → AWAITING_CONTAINMENT` | `TIER1_CREATOR` | T1 classifies Incident, assigns admin directly |
| `NEW → ESCALATED_T2` | `TIER1_CREATOR` | T1 classifies Incident, escalates to T2 |
| `ESCALATED_T2 → CLOSED_EVENT` | `TIER2` | T2 reclassifies Event, closes (terminal) |
| `ESCALATED_T2 → T1_REVIEW` | `TIER2` | T2 confirms Incident, **returns to T1** (only forward action T2 has) |
| `T1_REVIEW → AWAITING_CONTAINMENT` | `TIER1_CREATOR` | T1 reviews, assigns admin |
| `AWAITING_CONTAINMENT → CONTAINMENT_REPORTED` | `ASSIGNED_ADMIN` | admin submits containment, returns to T1 |
| `CONTAINMENT_REPORTED → AWAITING_CONTAINMENT` | `TIER1_CREATOR` | not contained → loop back to admin |
| `CONTAINMENT_REPORTED → PENDING_MANAGER` | `TIER1_CREATOR` | contained **and** `requires_manager_verification` |
| `CONTAINMENT_REPORTED → APPROVED` | `TIER1_CREATOR` | contained **and not** `requires_manager_verification` → T1 closes |
| `PENDING_MANAGER → APPROVED` | `MANAGER` | manager verifies → close |

Permission tokens (enforced in `Ticket.transition_to`, superuser bypasses):
- `TIER1_CREATOR` — `profile.is_tier1` **and** `user==created_by`. (Only Tier 1 creates tickets,
  so the creator is always a T1; this keeps the whole T1 side of a ticket with its opener.)
- `TIER2` — `profile.is_tier2`.
- `ASSIGNED_ADMIN` — `user==assigned_admin`.
- `MANAGER` — `profile.is_soc_manager`.

**Hard constraint enforced:** Tier 2 has exactly one forward edge (`→T1_REVIEW`) and one
close edge (`→CLOSED_EVENT`). There is no T2 edge to `AWAITING_CONTAINMENT` and T2 cannot
create tickets (the `create_ticket` view is Tier‑1‑only), so T2 can never assign to admin
or open a case.

The `CONTAINMENT_REPORTED→{APPROVED|PENDING_MANAGER}` split is guarded by
`requires_manager_verification` inside `transition_to`, so the routing is deterministic and
cannot be bypassed from a view.

### 2c. Event / Incident classification (replaces TP/FP)

- `Ticket.classification` (renamed from `disposition`): `INCIDENT` | `EVENT` | `''`.
  **Confirmed mapping: `INCIDENT` = old `TRUE_POSITIVE` (actionable → containment);
  `EVENT` = old `FALSE_POSITIVE` (benign → closed).**
- **Set by T1 in the create flow** (no longer by the admin at containment). May be revised
  by T2 while a ticket is escalated. Every ticket carries an explicit value — never derived.
- `is_event` property replaces `is_false_positive`. Model values are authoritative; display
  strings are for the UI prompt.
- Migrations: `incidents/0016` renames the column `disposition→classification`; `0017`
  (auto) adds `escalated_to_t2_at` + `is_emergency` and alters the `classification`/`status`
  choices; data migration `0018` rewrites existing rows `TRUE_POSITIVE→INCIDENT`,
  `FALSE_POSITIVE→EVENT` and remaps in-flight statuses `UNDER_REVIEW→CONTAINMENT_REPORTED`,
  `VERIFIED→PENDING_MANAGER`, `CLOSED_FP→CLOSED_EVENT`. `wazuh_ingest/0004` adds
  `release_reason`.

### 2d. Emergency flag

> **Superseded 2026-07-14 (see §0):** the permission below is historical — the flag is
> now SOC Manager only.

- `Ticket.is_emergency` (Boolean, default False), mutable at **any** lifecycle stage
  (including terminal). Toggled via `Ticket.set_emergency(value, user, note)` which writes
  a `TicketLog` audit entry (who/when/old→new).
- ~~Permission (`Ticket.can_set_emergency(user)`): any role may set/clear it **except** a
  Tier 1 analyst, who may only do so on a ticket that **was escalated to T2 at any point**.~~
- "Escalated to T2 ever" = `escalated_to_t2_at` is non-null (`was_escalated_to_t2` property).
  `escalated_to_t2_at` is stamped the first time a ticket enters `ESCALATED_T2` and is never
  cleared. (No longer gates the emergency flag; kept as an audit/history record.)

### 2e. `requires_manager_verification` — emergency flag only

> **Updated 2026-07-08:** the severity floor was removed. Tier 2 now verifies every
> containment/remediation (`CONTAINMENT_REPORTED` and `PENDING_T2_REVIEW` are Tier 2
> queues); the SOC manager reviews emergency tickets only, *after* Tier 2 verification.

```
requires_manager_verification == is_emergency
```
- Severity (even Critical) never routes to the manager on its own; the old
  `SEVERITY_FLOOR` constant and `settings.SOC_SEVERITY_FLOOR` override are gone.
  No other auto-triggers.

### 2f. Tier 1 triage — exactly 2 actions after claim (`apps/wazuh_ingest`)

After `claim_alert`, a Tier‑1 analyst has only:
1. **Create ticket** — `triage_action` `action=create_ticket` (the only remaining branch).
2. **Release** — `release_alert` now **requires a reason**, stored on the new
   `WazuhAlert.release_reason` field; alert returns to `PENDING`.

The old triage-level `close_fp` and `escalate` branches are removed, and the triage/claim/
release/create path is gated to Tier 1 (`_has_tier1_access`). Escalation is now a
ticket-level decision (`NEW→ESCALATED_T2`), not an alert-level one.

### 2g. System Admin field access

The admin's containment step (`AWAITING_CONTAINMENT→CONTAINMENT_REPORTED`) now grants the
admin **write** access to the **countermeasure** field `containment_report` and the
**investigation‑findings** field `remediation_summary` (both already existed on the model;
the admin previously could not write `remediation_summary`). The admin **no longer sets
classification** — that is T1's decision.

### 2h. Audit trail

Every new transition logs a `TicketLog` (unchanged mechanism). Emergency toggles also log a
`TicketLog`. `verified_by/at` is stamped when T1 marks a ticket contained
(`CONTAINMENT_REPORTED→{APPROVED|PENDING_MANAGER}`), `approved_by/at` at the final close —
both still write-once.

---

## 3. UI surfaces still to update (NOT touched in this backend change)

> **✅ All resolved — kept for history.** This was the follow-up list from the
> 2026-07-08 backend change; every item has since shipped. Item 2 in particular
> ("decide whether to retire Manual Triage or align it") was answered on
> 2026-07-23 — see §0.2: the queue is retained (it is the only intake path for
> non-SIEM reports) but absorbed into Tier 1's **My Queue**, and
> `triage_list.html` / `respond_escalation` no longer exist. Do not treat the
> list below as open work.

These reference renamed states/labels, the removed actions, the new classification field, or
the emergency flag and must be reworked by the UI prompt:

1. **Wazuh Triage** menu/page — `templates/wazuh_ingest/triage_queue.html`: drop the
   *Close (FP)* and *Escalate* buttons; keep *Create ticket*; add the **required release
   reason** input to the release form. Tier‑1‑only now.
2. **Manual Triage** menu/page — `templates/incidents/triage_list.html`,
   `triage_form.html`, `respond_escalation.html` + `TriageForm`: still expresses the old
   FP/TP/ESCALATE manual-triage model (`TriageRecord`). Decide whether to retire it or align
   it with create-ticket-or-release; backend `TriageRecord` left intact for now.
3. **Escalation Queue** menu/page — `templates/wazuh_ingest/escalation_queue.html` is
   alert-level and now goes empty (no new alert escalations). A **ticket** escalation queue
   (list of `status=ESCALATED_T2`) needs a view/template for Tier 2; T2 can currently reach
   them via the normal ticket list.
4. **เปิดเคสใหม่** (Open New Case) — `templates/incidents/ticket_form.html`: add the
   **Event/Incident** selector and the Incident **route** choice (assign admin vs escalate
   T2); the `classification` + `t1_route` inputs the new `create_ticket` view expects.
5. `templates/incidents/ticket_detail.html` — containment form must drop the disposition
   selector, add `remediation_summary`, expose the new T1/T2/admin/manager actions and an
   **emergency toggle**; `_status_badge.html` needs the new status codes/colours.
6. `templates/incidents/ticket_history.html` — `CLOSED_FP`→`CLOSED_EVENT`, disposition→
   classification labels and filters.
7. `templates/dashboard/dashboard.html` — pipeline labels follow `STATUS_CHOICES`
   automatically, but the "TP/FP" doughnut wording and the backlog cards (`awaiting_*`) should
   be relabelled Event/Incident and the new states.
8. Nav badge counts (`apps/wazuh_ingest/context_processors.py`) still count alert-level
   escalations; add a ticket-escalation badge if the T2 ticket queue is built.

---

## Related documents

- [ticket-lifecycle-states.md](ticket-lifecycle-states.md) — the current state machine, as it stands today
- [../adr/](../adr/) — decision records for the choices referenced above
