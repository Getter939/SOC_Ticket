# SOC Ticket Workflow Redesign — Handoff

Concise map of the **current** implementation and the **target** workflow. This is the
backend-change handoff; the UI prompt picks up from the "UI surfaces still to update"
list at the bottom.

Apps involved: `apps/incidents` (tickets + manual triage), `apps/wazuh_ingest`
(SIEM alert triage + escalation queue), `apps/accounts` (roles/tiers),
`apps/dashboard` (aggregates).

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

- `Ticket.is_emergency` (Boolean, default False), mutable at **any** lifecycle stage
  (including terminal). Toggled via `Ticket.set_emergency(value, user, note)` which writes
  a `TicketLog` audit entry (who/when/old→new).
- Permission (`Ticket.can_set_emergency(user)`): any role may set/clear it **except** a
  Tier 1 analyst, who may only do so on a ticket that **was escalated to T2 at any point**.
- "Escalated to T2 ever" = `escalated_to_t2_at` is non-null (`was_escalated_to_t2` property).
  `escalated_to_t2_at` is stamped the first time a ticket enters `ESCALATED_T2` and is never
  cleared, so a ticket T2 returned to T1 still counts.

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
