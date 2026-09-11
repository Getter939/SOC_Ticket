# Section 8 carries a fixed remediation checklist, ticked by Tier 2

Date: 2026-09-11

On 2026-08-06 the SOC Manager asked to remove Section 8's fixed remediation checklist
(UAT round 1). The objection was specific: the 15-item list was static boilerplate —
it always printed unticked and was driven by no ticket field, so it added nothing over
Section 6's data-driven containment checklist. Section 8 was reduced to its two free-text
rows, `remediation_summary` (ผลการตรวจสอบ / Investigation Findings) and
`containment_report` (มาตรการควบคุม / Countermeasure).

This decision supersedes that removal. Section 8 again carries a fixed 15-item checklist,
but it is now data-driven and audited, which is exactly what the original objection asked
for. The checklist lives in `report_content.REMEDIATION_CHECKLIST` (stable key + printed
label per item) plus an "อื่นๆ ระบุ" free-text line. Tier 2 ticks it while verifying that
containment actually happened: on the Admin lane at `CONTAINMENT_REPORTED`, and on the
System Owner lane at `PENDING_T2_REVIEW`. Ticks are stored on `Ticket.remediation_checklist`
as a list of item keys (order-canonical, so a re-save is byte-identical and never fabricates
a history entry), with the free text on `Ticket.remediation_other`; the "อื่นๆ" box prints
ticked whenever that text is filled. Every change is written to field history with source
`t2_remediation`, so unlike the old static list, each tick is attributable.

The two free-text rows are retained. In the Owner lane Tier 2 may also fill Findings and
Countermeasure (optional); in the Admin lane those two remain the System Admin's to enter
through the containment form. Section 8's heading and checklist always print (including in
compact mode); the two free-text rows still drop individually when empty. The checklist is
Incident-report only — the Event report has no Section 8.

This is recorded here because the change reverses a prior UAT decision. The canonical UAT
tracker is in Notion; the SOC Manager approval of this supersession should be reflected
there as well.
