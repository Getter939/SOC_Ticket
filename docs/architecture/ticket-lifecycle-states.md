# Ticket Lifecycle States

> **Audience:** developers and SOC leads · **Status:** Current (authoritative current-workflow reference) · **Last updated:** 2026-09-22
> **Source of truth:** `apps/incidents/models/ticket.py` → `Ticket.ALLOWED_TRANSITIONS` and `Ticket.cancellation_action` (rules in `apps/incidents/cancellation.py`)

The complete ticket lifecycle as a diagram plus a transition reference, organised
by which role may perform each move. **`STATUS_CHOICES` defines 14 statuses: 13
are reachable through the workflow or cancellation process, plus 1 legacy compatibility state
(`OWNER_REMEDIATED`) that nothing transitions *into* any more** — it is retained
only so tickets already sitting in it can finish. When the state machine changes
in code, update the Mermaid block below — each line is one node or one arrow.

This is the single authoritative description of the *current* workflow; prose
docs (handover, user guides) and the diagrams should match it, not restate it.

---

**Role colors** — 🔵 Tier 1 · 🟣 Tier 2 · 🟠 System Admin · 🔴 SOC Manager · 🟢 Closed

Key rules (redesigned 2026-07-14):
- **Every Incident passes the SOC Manager pre-containment review** (`PENDING_MGR_TRIAGE`) before it reaches a handling lane. The manager flags Emergency (yes/no) and forwards to the lane already chosen (`t1_route`) — they **cannot** divert the lane.
- **Whoever routes an Incident to the manager picks its lane** (changed 2026-09-22 — `T1_REVIEW` retired). Tier 1 picks it at preparation (`NEW → PENDING_MGR_TRIAGE`); for an escalated case **Tier 2 decides and picks it**: *Incident* → choose Admin (+ the responsible System Admin) or Owner → `PENDING_MGR_TRIAGE`; *Event* → close, or watch 30 days. A concluded watch that turned up something is routed the same way. Every edge into `PENDING_MGR_TRIAGE` requires a complete lane (`Ticket.LANE_ROUTING_EDGES` / `has_handling_lane`), so a case can no longer arrive at the manager with nothing to forward to. Tier 1 no longer has a step after escalation; they see Tier 2's edits through a passive **"Tier 2 แก้ไข"** list in My Queue (`t2_changed_at` vs `creator_seen_at`, cleared when they open the ticket).
- **The manager's "return for completion" goes back to whoever routed the case** (`Ticket.manager_return_target`, `MANAGER_RETURN_EDGES`). If the ticket was ever on Tier 2's desk (`escalated_to_t2_at` set) it returns to `ESCALATED_T2` as an Incident (so a later Event call is still a downgrade needing the manager). If Tier 1 routed it straight from preparation it returns to `NEW`, where the creator fixes it and resubmits (`first_submitted_at` stays set: no repeat owner email, and the creator can no longer cancel it directly).
- **Response-team requests run in parallel.** At any active stage the SOC Manager may spawn a Response Request (a specialised `TicketSubtask`): VA / Pentest and Infrastructure Security route to the **Red Team Manager**; Forensics / RCA routes to the **Forensic Analyst**. Each is auto-assigned to the sole holder of the target role (picker when several exist). **While any Response Request is not `DONE`, no path may move the Incident to `APPROVED`** — the closing action is withheld until the response work finishes. Event-close (`CLOSED_EVENT`) is exempt: a reclassified false alarm still closes and any open request simply outlives it.
- **Only the SOC Manager may set or clear the Emergency flag** (superuser bypass). It is decided as an **explicit, required Normal/Emergency assessment** at the pre-containment review (`assess_emergency_initial`, stamping `emergency_decided_by/at` write-once even for Normal). The manager may **reassess** it later (`reassess_emergency`) — an auditable action requiring a written reason — at any active stage past the review, but **not at `PENDING_MGR_TRIAGE`** and **not after closure** (`APPROVED`/`CLOSED_EVENT`). No other role can touch it. (2026-07-23)
- **Tier 1 can no longer close an Event directly.** A Tier 1 "Event" verdict escalates to Tier 2 (`ESCALATED_T2`); Tier 2 **confirms** it and closes (`CLOSED_EVENT`) with no SOC Manager involvement.
- **A Tier 2 Event *downgrade* needs the SOC Manager** (added 2026-07-23). If the ticket reached Tier 2 as an **Incident** and Tier 2 relabels it an Event, it goes to `PENDING_MGR_EVENT_REVIEW` instead of closing: the manager either confirms (→ `CLOSED_EVENT`) or rejects (→ back to `ESCALATED_T2` with the classification flipped back to Incident). This is a counter-measure — a case must not be disposable by reclassifying it. `classification_at_escalation` records what Tier 2 was handed, so *confirming* an Event Tier 1 had already classified still closes directly.
- **Tier 2 verifies every containment/remediation** — both the System Admin lane and the System Owner lane — before a ticket can close. Tier 2 may also **reclassify an in-flight case as an Event** and close it directly (no manager), even when the emergency flag is set. ⚠️ These two mid-containment edges are deliberately **not** covered by the downgrade gate above — a known asymmetry, see the change log.
- **Tier 2 must claim a ticket before acting on it** (added 2026-07-23). The Tier 2 Queue has claim/release like the Tier 1 triage queue; a claim held by another analyst blocks the transition in `transition_to`. The claim clears on every transition, since the queue spans three stages.
- **SOC Manager reviews emergency tickets only** at the closing gate (the `is_emergency` flag; severity alone never routes to the manager). Emergency tickets pass Tier 2 first, then the manager.
- **Monitoring is a watch phase of an Event, not a stage of handling** (added v1.2.3; re-anchored to Event ownership v1.7.x). Only **Tier 2** may start it, only from `ESCALATED_T2` and only as an **Event** decision (the classification stays `EVENT`), for a **fixed 30 days**, **once per case** (`has_been_monitored`). Because it is reachable only through the Event verdict, an **Incident is never monitored** and **any Event may be**. The case sits in the Tier 1 creator's court for visibility during the watch, but **Tier 2 concludes it**: close directly as an Event (→ `CLOSED_EVENT`) or, if the watch turned up something, raise it to an Incident (→ SOC Manager triage). Expiry is computed on read — there is no scheduler.
- **The SOC Manager can step a ticket backward** along `STEP_BACK_EDGES` to correct a mis-route (e.g. the wrong admin was assigned). Step-back runs through `transition_to()`, so it inherits every invariant and the audit log instead of a parallel hand-rolled write; the `t1_route` gate allows exactly one of the two `PENDING_MANAGER` edges per ticket. No other role can move a ticket backward.
- System Owner never uses the system — Tier 1 records the owner's fix on their behalf.
- **A ticket can be saved as a draft before it is routed** (added 2026-09-17). On the creation form the analyst either sends it now or chooses *save preparation*. A draft stays in `NEW` (label "in preparation, not submitted") with its chosen lane remembered. The creator later sends it with **Submit preparation** (`ticket_workflow.submit_preparation`), which takes the same `NEW → ESCALATED_T2` / `NEW → PENDING_MGR_TRIAGE` edges. No emails are sent while it is only a draft. Project Incidents have no draft mode.
- **Tier 2 must record when the affected party was notified before moving a verified case forward** (added 2026-09-17). On `CONTAINMENT_REPORTED` / `PENDING_T2_REVIEW`, the edges to `APPROVED` and `PENDING_MANAGER` are refused until `affected_notified_at` (report row 1.4) is entered. It is optional on the send-back and Event-close edges. The date may not be in the future or earlier than the detection / occurrence time (`ticket_workflow.validate_affected_notified_at`). This check lives in the ticket-detail view, not in `transition_to`.

```mermaid
flowchart TD
    START([เริ่มต้น]) --> NEW[สร้าง Ticket — NEW<br/>ระบุความรุนแรง + จัดประเภท + IOC<br/>ส่งทันที หรือบันทึกจัดเตรียมไว้ก่อน]
    NEW -.->|บันทึกจัดเตรียม → ผู้เปิดกดส่งภายหลัง| NEW

    %% ── Tier 1 triage decision ──────────────────────────────
    NEW --> D1{Event หรือ Incident?<br/>ตัดสินโดย Tier 1}
    D1 -->|Event → ส่ง Tier 2 ยืนยัน| ESCALATED_T2
    D1 -->|Incident: มอบหมาย Admin| PENDING_MGR_TRIAGE
    D1 -->|Incident: ให้เจ้าของแก้เอง| PENDING_MGR_TRIAGE
    D1 -->|Incident: ส่ง Tier 2| ESCALATED_T2

    %% ── Tier 2 escalation triage ────────────────────────────
    ESCALATED_T2[Tier 2 ทบทวน — ต้อง Claim ก่อน<br/>ESCALATED_T2] --> D2{Event หรือ Incident?<br/>ตัดสินโดย Tier 2}
    D2 -->|Event ที่ Tier 1 จัดไว้แล้ว — ยืนยันและปิด| CLOSED_EVENT
    D2 -->|Event ที่ Tier 2 ปรับจาก Incident| PENDING_MGR_EVENT_REVIEW
    D2 -->|Event → เฝ้าระวัง 30 วัน| MONITORING
    D2 -->|Incident — Tier 2 เลือกเส้นทาง Admin / Owner| PENDING_MGR_TRIAGE

    %% ── Watch-and-wait: a watched Event, Tier 2 owns it ────
    %% Fixed 30-day window, once per case (has_been_monitored),
    %% expiry computed on read — there is no scheduler.
    MONITORING[กำลังเฝ้าระวัง 30 วัน — Event ที่กำลังเฝ้าดู<br/>MONITORING] --> D8{ครบกำหนด หรือ มีเหตุเกิดขึ้น?<br/>ตัดสินโดย Tier 2}
    D8 -->|มีเหตุเกิดขึ้น → Incident + เลือกเส้นทาง| PENDING_MGR_TRIAGE
    D8 -->|ครบกำหนดโดยเงียบ → ปิดเป็น Event| CLOSED_EVENT

    %% ── Manager verifies a Tier 2 Event downgrade ───────────
    PENDING_MGR_EVENT_REVIEW[ผู้จัดการ SOC ตรวจการปิดแบบ Event<br/>PENDING_MGR_EVENT_REVIEW] --> D7{เป็น Event จริงหรือไม่?<br/>ตัดสินโดยผู้จัดการ SOC}
    D7 -->|ใช่ — ปิดเคส| CLOSED_EVENT
    D7 -->|ไม่ใช่ — กลับเป็น Incident| ESCALATED_T2

    %% ── SOC Manager pre-containment review (blocking) ───────
    PENDING_MGR_TRIAGE[ผู้จัดการ SOC ตรวจก่อนมอบหมาย<br/>flag Emergency + ส่งต่อ<br/>PENDING_MGR_TRIAGE] --> D_ROUTE{เส้นทางที่เลือกไว้?<br/>t1_route}
    PENDING_MGR_TRIAGE -->|ส่งกลับพร้อมเหตุผล — เคยผ่าน Tier 2| ESCALATED_T2
    PENDING_MGR_TRIAGE -->|ส่งกลับพร้อมเหตุผล — Tier 1 ส่งมาโดยตรง| NEW
    D_ROUTE -->|Admin| AWAITING_CONTAINMENT
    D_ROUTE -->|Owner| AWAITING_OWNER

    %% ── Admin containment lane (verified by Tier 2) ─────────
    AWAITING_CONTAINMENT[ผู้ดูแลระบบดำเนินการควบคุม/กำจัด/กู้คืน<br/>AWAITING_CONTAINMENT] --> CONTAINMENT_REPORTED[ส่งรายงานการควบคุม — รอ Tier 2<br/>CONTAINMENT_REPORTED]
    CONTAINMENT_REPORTED --> D3{ควบคุมสำเร็จ?<br/>ตัดสินโดย Tier 2}
    D3 -->|ยังไม่สำเร็จ| AWAITING_CONTAINMENT
    D3 -->|จัดเป็น Event — ปิดเคส| CLOSED_EVENT
    D3 -->|สำเร็จ| D4{ฉุกเฉิน Emergency?}
    D4 -->|ไม่ใช่ — Tier 2 ปิดเคส| APPROVED[ปิดเคส<br/>APPROVED]
    D4 -->|ใช่| PENDING_MANAGER[ผู้จัดการ SOC ตรวจสอบ<br/>PENDING_MANAGER]

    %% ── Direct-to-Owner lane (skips System Admin) ───────────
    %% One action: Tier 1 attaches what the owner sent, records it in the note,
    %% and hands to Tier 2. Adequacy is judged once, by Tier 2 — no T1 decision.
    AWAITING_OWNER[รอเจ้าของระบบดำเนินการเอง<br/>AWAITING_OWNER] -->|T1 บันทึกผลของเจ้าของ + แนบหลักฐาน| PENDING_T2_REVIEW[รอ Tier 2 ตรวจสอบ<br/>PENDING_T2_REVIEW]
    %% LEGACY — no live edge leads INTO this node any more. Kept reachable-out
    %% so tickets already in OWNER_REMEDIATED can still finish. Do not re-wire.
    OWNER_REMEDIATED[เจ้าของแจ้งแก้ไขแล้ว — LEGACY<br/>OWNER_REMEDIATED] -.->|เฉพาะตั๋วเก่าที่ค้างอยู่| PENDING_T2_REVIEW
    PENDING_T2_REVIEW --> D6{Tier 2 ยืนยันการแก้ไข?}
    D6 -->|ปฏิเสธ — กลับไปเจ้าของ| AWAITING_OWNER
    D6 -->|จัดเป็น Event — ปิดเคส| CLOSED_EVENT
    D6 -->|ยืนยัน + ไม่ฉุกเฉิน| APPROVED
    D6 -->|ยืนยัน + ฉุกเฉิน| PENDING_MANAGER

    %% ── Manager gate (emergency only) ───────────────────────
    PENDING_MANAGER -->|อนุมัติ| APPROVED

    %% ── Manager step-back (backward correction, STEP_BACK_EDGES) ──
    %% Runs through transition_to(), so it inherits every invariant and
    %% the audit log. The t1_route gate allows exactly one of the two
    %% PENDING_MANAGER edges per ticket.
    AWAITING_CONTAINMENT -.->|↩ step-back| PENDING_MGR_TRIAGE
    AWAITING_OWNER -.->|↩ step-back| PENDING_MGR_TRIAGE
    OWNER_REMEDIATED -.->|↩ step-back| AWAITING_OWNER
    PENDING_MANAGER -.->|↩ step-back เลน Admin| CONTAINMENT_REPORTED
    PENDING_MANAGER -.->|↩ step-back เลน Owner| PENDING_T2_REVIEW

    %% ── Cancellation — a separate audited process, not a status move ──
    %% Entered through Ticket.cancellation_action from ANY active stage.
    ACTIVE_ANY[/ทุกสถานะที่ยังทำงานอยู่<br/>NEW … PENDING_MANAGER รวม MONITORING<br/>และ legacy OWNER_REMEDIATED/] -.->|ยกเลิกรายการ: ต้องมีเหตุผล<br/>ผู้เปิด/ผู้ถือขั้นตอนยื่นคำขอ · ผู้จัดการ SOC อนุมัติ<br/>(Tier 1 ยกเลิกเองได้เฉพาะตอน NEW)| CANCELLED[ยกเลิกแล้ว — terminal<br/>CANCELLED]

    %% ── Role coloring ───────────────────────────────────────
    classDef t1 fill:#e7f0ff,stroke:#3b82f6,color:#1e3a8a;
    classDef t2 fill:#f1ebfe,stroke:#8b5cf6,color:#5b21b6;
    classDef admin fill:#fef3e2,stroke:#f59e0b,color:#8a4d0a;
    classDef mgr fill:#ffece7,stroke:#fb7185,color:#9f1239;
    classDef closed fill:#e6f6ec,stroke:#34d399,color:#065f46;
    classDef decision fill:#eef0f2,stroke:#adb5bd,color:#343a40;
    classDef legacy fill:#f3f4f6,stroke:#9ca3af,color:#6b7280,stroke-dasharray:4 3;
    classDef cancelled fill:#fdecec,stroke:#dc3545,color:#7f1d1d;
    classDef meta fill:#f8f9fa,stroke:#6c757d,color:#343a40,stroke-dasharray:4 3;

    class START,NEW,AWAITING_OWNER,MONITORING t1;
    class ESCALATED_T2,CONTAINMENT_REPORTED,PENDING_T2_REVIEW t2;
    class AWAITING_CONTAINMENT admin;
    class PENDING_MGR_TRIAGE,PENDING_MANAGER,PENDING_MGR_EVENT_REVIEW mgr;
    class APPROVED,CLOSED_EVENT closed;
    class OWNER_REMEDIATED legacy;
    class CANCELLED cancelled;
    class ACTIVE_ANY meta;
    class D1,D2,D3,D4,D6,D7,D8,D_ROUTE decision;
```

## Transition reference (who can do what)

| From | To | Actor |
|------|----|-------|
| NEW | PENDING_MGR_TRIAGE (Incident) / ESCALATED_T2 (Event or Incident-escalate) | Tier 1 (creator) |
| ESCALATED_T2 | PENDING_MGR_TRIAGE (Incident — Tier 2 picks the lane) / CLOSED_EVENT (Event Tier 1 already classified) / PENDING_MGR_EVENT_REVIEW (Event **downgraded** by Tier 2) / MONITORING (Event → watch 30 days) | Tier 2 (must hold the claim) |
| MONITORING | PENDING_MGR_TRIAGE (something happened → Incident, Tier 2 picks the lane) / CLOSED_EVENT (window closed quietly → Tier 2 closes the Event) | **Tier 2** — sets the 30-day window and concludes it; the case stays in the Tier 1 creator's court for visibility; monitored at most once |
| PENDING_MGR_EVENT_REVIEW | CLOSED_EVENT (confirm) / ESCALATED_T2 (reject → classification back to Incident) | **SOC Manager** |
| PENDING_MGR_TRIAGE | AWAITING_CONTAINMENT (t1_route=ADMIN) / AWAITING_OWNER (t1_route=OWNER) / ESCALATED_T2 or NEW (return for completion — to whoever routed it) | **SOC Manager** — return requires a written reason |
| AWAITING_CONTAINMENT | CONTAINMENT_REPORTED | Assigned Admin |
| CONTAINMENT_REPORTED | AWAITING_CONTAINMENT (ไม่สำเร็จ) / CLOSED_EVENT (จัดเป็น Event) / APPROVED (ไม่ฉุกเฉิน) / PENDING_MANAGER (ฉุกเฉิน) | **Tier 2** |
| AWAITING_OWNER | PENDING_T2_REVIEW (record owner's fix + attach, hand to Tier 2 — one action) | Tier 1 (creator) |
| ~~OWNER_REMEDIATED~~ (legacy) | PENDING_T2_REVIEW | Tier 1 (creator) — **legacy only**: no live edge enters this state; used solely by tickets already sitting in it |
| PENDING_T2_REVIEW | APPROVED (ไม่ฉุกเฉิน) / PENDING_MANAGER (ฉุกเฉิน) / CLOSED_EVENT (จัดเป็น Event) / AWAITING_OWNER (ปฏิเสธ) | **Tier 2** |
| PENDING_MANAGER | APPROVED | SOC Manager |
| AWAITING_CONTAINMENT | PENDING_MGR_TRIAGE | **SOC Manager** — ↩ step-back |
| AWAITING_OWNER | PENDING_MGR_TRIAGE | **SOC Manager** — ↩ step-back |
| ~~OWNER_REMEDIATED~~ (legacy) | AWAITING_OWNER | **SOC Manager** — ↩ step-back |
| PENDING_MANAGER | CONTAINMENT_REPORTED (t1_route=ADMIN) / PENDING_T2_REVIEW (t1_route=OWNER) | **SOC Manager** — ↩ step-back |

**Terminal states:** APPROVED, CLOSED_EVENT, CANCELLED.

### Cancellation (การยกเลิกรายการ)

Cancellation is a separate audited process, entered through `Ticket.cancellation_action`,
not a generic status-dropdown transition. It is available from every active stage,
including MONITORING and legacy OWNER_REMEDIATED, irrespective of Classification
or Emergency. It applies to an individual Member Ticket, retaining group membership,
shared evidence and linked Alerts. It does not return Alerts to triage.

- The Tier 1 creator may cancel directly only at NEW — i.e. while the ticket is still a
  saved draft (*save preparation*) that has never been submitted. A ticket sent on save
  leaves NEW immediately, and one the manager returned to NEW has already been reviewed
  (`first_submitted_at` set), so cancelling either requires manager approval.
- The creator or current workflow actor may request cancellation. Tier 2 claims
  still block another Tier 2 analyst. Response-team assignment alone does not allow it.
- The SOC Manager approves/rejects pending requests or cancels an active ticket
  directly. The existing superuser override applies with the same audit requirements.
- Only the requester can withdraw a pending request. Rejection permits a new request.
- Reasons are รายการซ้ำ, สร้างรายการผิด, or เหตุผลอื่น, with a mandatory explanation.
  Duplicates must reference another accessible, non-cancelled ticket, rechecked at approval.
- There is at most one pending request. It leaves status and OLA clocks unchanged;
  work continues. Normal closure supersedes it. Rejection leaves the current stage intact.
- Approval requires unfinished subtasks/Response Requests to be completed, or explicitly
  selected for cancellation by the manager. Those tasks become CANCELLED, never DONE.
- CANCELLED is terminal and frozen. Requester, decision maker, reasons, timestamps,
  cancelled task IDs and TicketLog entries remain available. Cancellation stamps
  `closed_at` without stamping resolution `approved_by` or `verified_by`.
- Cancelled tickets leave active queues/OLA pressure, appear separately in history and
  dashboards, and are excluded from successful-resolution and MTTR aggregates.
  Historical clocks remain stored. Reports label cancellation and include its decision.

The user-facing cancellation forms, outcomes and audit labels are Thai.
See [ADR-0005](../adr/0005-ticket-cancellation.md).

**Legacy state:** `OWNER_REMEDIATED` — Tier 1 used to stop here to record the
owner's report before forwarding, which cost two clicks for one act. The live
owner lane now goes `AWAITING_OWNER → PENDING_T2_REVIEW` directly. `OWNER_REMEDIATED`
is retained only so tickets already in it can finish; **do not wire a new edge
into it.** (Retired in the workflow change log; see
[workflow-change-log.md](workflow-change-log.md).)

**`t1_route` routing:** whoever sends an Incident to `PENDING_MGR_TRIAGE` records the chosen lane (`ADMIN` + `assigned_admin` / `OWNER`) — Tier 1 from preparation, Tier 2 from `ESCALATED_T2` or `MONITORING`. The field keeps its historical name. The SOC Manager forward is deterministically guarded so it can only reach the lane matching `t1_route` — the manager reviews and flags Emergency but cannot swap Admin ↔ Owner.

**Manager routing at the closing gate:** `requires_manager_verification` = `is_emergency` only. Severity (even Critical) never routes to the manager by itself.

**Event closes and the manager:** there are now two different answers, and the distinction is the *origin* of the Event verdict, not the stage:

| Event close | Manager? | Why |
|---|---|---|
| `ESCALATED_T2 → CLOSED_EVENT` where Tier 1 had already classified it an Event | no | Tier 2 is confirming, not disposing |
| `ESCALATED_T2 → …` where Tier 2 downgraded an Incident | **yes** — via `PENDING_MGR_EVENT_REVIEW` | the case could otherwise be closed by relabelling it |
| `CONTAINMENT_REPORTED → CLOSED_EVENT` (mid-containment reclassify) | no | ⚠️ bypasses the manager even when Emergency is set |
| `PENDING_T2_REVIEW → CLOSED_EVENT` (owner lane reclassify) | no | ⚠️ same |

The two ⚠️ rows are a deliberate scope decision from 2026-07-23, not an oversight — but they are the same disposal risk one stage later, so revisit them if the gate proves useful.

**Tier 2 queue claim:** `t2_claimed_by` / `t2_claimed_at`. Claiming is a single conditional `UPDATE`, so simultaneous clicks cannot both win; releasing requires a written reason, logged against the ticket. `Ticket.t2_claim_blocks(user)` is enforced inside `transition_to`, so the guarantee holds for any caller. Only a claim held by *someone else* blocks — an unclaimed ticket stays actionable, because Tier 2 also works from the ticket detail page, which has no claim button.

**Response-team gate:** every edge into `APPROVED` is blocked while `Ticket.has_open_response_requests` is true (any VA/PT, InfraSec, or Forensics `TicketSubtask` not yet `DONE`). This covers the SOC Manager approval *and* the Tier 2 direct-close paths, so a non-emergency Incident with pending forensics cannot slip closed. `CLOSED_EVENT` is deliberately exempt. In the UI the closing action is withheld (not just rejected on submit) until the request completes. Response-team members (Forensic Analyst / Red Team Manager) see only the Tickets carrying a request assigned to them, worked from the **Response Requests** queue (`/incidents/response-requests/`).

**Sign-offs:** `verified_by` = the Tier 2 analyst who confirmed containment/remediation (stamped leaving CONTAINMENT_REPORTED or PENDING_T2_REVIEW forward to APPROVED/PENDING_MANAGER). `approved_by` = whoever closed the case (Tier 2 or SOC Manager).

**SOC Manager Queue** (ticket list, manager-scoped) shows all three manager stages: PENDING_MGR_TRIAGE (pre-containment review), PENDING_MANAGER (emergency approval) and PENDING_MGR_EVENT_REVIEW (Event-downgrade verification).

**Tier 2 Queue** (`/incidents/tier2-queue/`) shows all three Tier 2 stages: ESCALATED_T2, CONTAINMENT_REPORTED, PENDING_T2_REVIEW — each row claimable, with an OLA countdown column.

**Tier 1 My Queue** (`/incidents/my-queue/`) is the Tier 1 counterpart: their own-court tickets (NEW, MONITORING, AWAITING_OWNER, OWNER_REMEDIATED — `Ticket.TIER1_QUEUE_STATUSES`) plus the manual-intake queue. The page has tabs for tickets, monitoring (cases with their 30-day countdown), **Tier 2 แก้ไข** (the passive changed-by-Tier-2 list — not counted in the sidebar badge), manual intake and recent history. A preparation the SOC Manager returned is flagged at the top, since only its opener may act on it.

**Retired status:** `T1_REVIEW` (“รอ Tier 1 ทบทวน”) was removed on 2026-09-22 — Tier 2 used to hand a confirmed Incident back to Tier 1 just to pick the lane, which stalled cases. Migration `incidents 0083` moved any ticket still in it back to `ESCALATED_T2`. Old `TicketLog` rows keep the code; `Ticket.LEGACY_STATUS_LABELS` renders it as “ส่งกลับ Tier 1 (legacy)”.

**OLA countdown:** every queue shows the shared `_ola_badge.html` pill, built from `apps/incidents/ola.py`. Tickets use the live **contain** deadline; Wazuh alerts use their flat 4-hour triage OLA. The badge is hidden when there is no deadline (Medium/Low are notification-only) or the work is finished.

---

## Related documents

- [workflow-change-log.md](workflow-change-log.md) — *why* the state machine has this shape
- [../handover/engineering-handover.md](../handover/engineering-handover.md) §3.1 — the same lifecycle in prose, with the gotchas
- [../adr/0003-manager-verification-gate-in-model.md](../adr/0003-manager-verification-gate-in-model.md) — why the manager gate lives in the model
- [../adr/0005-ticket-cancellation.md](../adr/0005-ticket-cancellation.md) — the cancellation process (separate from resolution)
- [soc-end-to-end-workflow.md](soc-end-to-end-workflow.md) — end-to-end workflow from Wazuh alert / manual intake to closure, with every side-flow and a numbered scenario catalogue
- [soc-end-to-end-workflow-v1.7.1.drawio](soc-end-to-end-workflow-v1.7.1.drawio) — editable draw.io version of the same (role swimlanes), for diagramming in diagrams.net
- [soc-end-to-end-workflow-v1.7.0.drawio](soc-end-to-end-workflow-v1.7.0.drawio) / [ticket-workflow-v1.5.0.drawio](ticket-workflow-v1.5.0.drawio) — *superseded* historical versions (still show `T1_REVIEW`)
