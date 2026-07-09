# SOC Ticket Workflow — by responsible role

Source of truth: `apps/incidents/models.py` → `Ticket.ALLOWED_TRANSITIONS`.
Edit the Mermaid block below; each line is one node or one arrow.

**Role colors** — 🔵 Tier 1 · 🟣 Tier 2 · 🟠 System Admin · 🔴 SOC Manager · 🟢 Closed

Key rules (redesigned 2026-07-08):
- **Tier 2 verifies every containment/remediation** — both the System Admin lane and the System Owner lane — before a ticket can close.
- **SOC Manager reviews emergency tickets only** (the `is_emergency` flag; severity alone never routes to the manager). Emergency tickets pass Tier 2 first, then the manager.
- System Owner never uses the system — Tier 1 records the owner's fix on their behalf.

```mermaid
flowchart TD
    START([เริ่มต้น]) --> NEW[สร้าง Ticket — NEW<br/>ระบุความรุนแรง + จัดประเภท]

    %% ── Tier 1 triage decision ──────────────────────────────
    NEW --> D1{Event หรือ Incident?<br/>ตัดสินโดย Tier 1}
    D1 -->|Event| CLOSED_EVENT[ปิดเคส<br/>CLOSED_EVENT]
    D1 -->|Incident: มอบหมาย Admin| AWAITING_CONTAINMENT
    D1 -->|Incident: ติดต่อเจ้าของโดยตรง| AWAITING_OWNER
    D1 -->|ส่ง Tier 2| ESCALATED_T2

    %% ── Tier 2 escalation triage ────────────────────────────
    ESCALATED_T2[Tier 2 ทบทวน<br/>ESCALATED_T2] --> D2{Event หรือ Incident?<br/>ตัดสินโดย Tier 2}
    D2 -->|Event| CLOSED_EVENT
    D2 -->|Incident| T1_REVIEW[ส่งกลับ Tier 1 มอบหมาย<br/>T1_REVIEW]
    T1_REVIEW -->|มอบหมาย Admin| AWAITING_CONTAINMENT
    T1_REVIEW -->|ติดต่อเจ้าของโดยตรง| AWAITING_OWNER

    %% ── Admin containment lane (verified by Tier 2) ─────────
    AWAITING_CONTAINMENT[ผู้ดูแลระบบดำเนินการควบคุม/กำจัด/กู้คืน<br/>AWAITING_CONTAINMENT] --> CONTAINMENT_REPORTED[ส่งรายงานการควบคุม — รอ Tier 2<br/>CONTAINMENT_REPORTED]
    CONTAINMENT_REPORTED --> D3{ควบคุมสำเร็จ?<br/>ตัดสินโดย Tier 2}
    D3 -->|ยังไม่สำเร็จ| AWAITING_CONTAINMENT
    D3 -->|สำเร็จ| D4{ฉุกเฉิน Emergency?}
    D4 -->|ไม่ใช่ — Tier 2 ปิดเคส| APPROVED[ปิดเคส<br/>APPROVED]
    D4 -->|ใช่| PENDING_MANAGER[ผู้จัดการ SOC ตรวจสอบ<br/>PENDING_MANAGER]

    %% ── Direct-to-Owner lane (skips System Admin) ───────────
    AWAITING_OWNER[รอเจ้าของระบบดำเนินการเอง<br/>AWAITING_OWNER] --> OWNER_REMEDIATED[T1 บันทึกผลการแก้ไขของเจ้าของ<br/>OWNER_REMEDIATED]
    OWNER_REMEDIATED --> D5{แก้ไขจริงหรือไม่?<br/>ตัดสินโดย Tier 1}
    D5 -->|ยังไม่แก้ไข| AWAITING_OWNER
    D5 -->|ส่งตรวจสอบ| PENDING_T2_REVIEW[รอ Tier 2 ตรวจสอบ<br/>PENDING_T2_REVIEW]
    PENDING_T2_REVIEW --> D6{Tier 2 ยืนยันการแก้ไข?}
    D6 -->|ปฏิเสธ — กลับไปเจ้าของ| AWAITING_OWNER
    D6 -->|ยืนยัน + ไม่ฉุกเฉิน| APPROVED
    D6 -->|ยืนยัน + ฉุกเฉิน| PENDING_MANAGER

    %% ── Manager gate (emergency only) ───────────────────────
    PENDING_MANAGER -->|อนุมัติ| APPROVED

    %% ── Role coloring ───────────────────────────────────────
    classDef t1 fill:#e7f0ff,stroke:#3b82f6,color:#1e3a8a;
    classDef t2 fill:#f1ebfe,stroke:#8b5cf6,color:#5b21b6;
    classDef admin fill:#fef3e2,stroke:#f59e0b,color:#8a4d0a;
    classDef mgr fill:#ffece7,stroke:#fb7185,color:#9f1239;
    classDef closed fill:#e6f6ec,stroke:#34d399,color:#065f46;
    classDef decision fill:#eef0f2,stroke:#adb5bd,color:#343a40;

    class START,NEW,T1_REVIEW,AWAITING_OWNER,OWNER_REMEDIATED t1;
    class ESCALATED_T2,CONTAINMENT_REPORTED,PENDING_T2_REVIEW t2;
    class AWAITING_CONTAINMENT admin;
    class PENDING_MANAGER mgr;
    class APPROVED,CLOSED_EVENT closed;
    class D1,D2,D3,D4,D5,D6 decision;
```

## Transition reference (who can do what)

| From | To | Actor |
|------|----|-------|
| NEW | AWAITING_CONTAINMENT / AWAITING_OWNER / ESCALATED_T2 / CLOSED_EVENT | Tier 1 (creator) |
| ESCALATED_T2 | T1_REVIEW / CLOSED_EVENT | Tier 2 |
| T1_REVIEW | AWAITING_CONTAINMENT / AWAITING_OWNER | Tier 1 (creator) |
| AWAITING_CONTAINMENT | CONTAINMENT_REPORTED | Assigned Admin |
| CONTAINMENT_REPORTED | AWAITING_CONTAINMENT (ไม่สำเร็จ) / APPROVED (ไม่ฉุกเฉิน) / PENDING_MANAGER (ฉุกเฉิน) | **Tier 2** |
| AWAITING_OWNER | OWNER_REMEDIATED | Tier 1 (creator) |
| OWNER_REMEDIATED | AWAITING_OWNER (ยังไม่แก้ไข) / PENDING_T2_REVIEW (เสมอ) | Tier 1 (creator) |
| PENDING_T2_REVIEW | APPROVED (ไม่ฉุกเฉิน) / PENDING_MANAGER (ฉุกเฉิน) / AWAITING_OWNER (ปฏิเสธ) | **Tier 2** |
| PENDING_MANAGER | APPROVED | SOC Manager |

**Terminal states:** APPROVED, CLOSED_EVENT.

**Manager routing:** `requires_manager_verification` = `is_emergency` only. Severity (even Critical) never routes to the manager by itself.

**Sign-offs:** `verified_by` = the Tier 2 analyst who confirmed containment/remediation (stamped leaving CONTAINMENT_REPORTED or PENDING_T2_REVIEW forward). `approved_by` = whoever closed the case (Tier 2 or SOC Manager).

**Tier 2 Queue** (`/wazuh/escalation_queue/`) shows all three Tier 2 stages: ESCALATED_T2, CONTAINMENT_REPORTED, PENDING_T2_REVIEW.
