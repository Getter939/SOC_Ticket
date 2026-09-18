# SOC workflow navigation — implementation plan

Status: implemented · 2026-09-18

## Objective

Make the workflow understandable from one main-functions diagram, then let the reader follow a named handoff into the appropriate detail page. The overview must explain what happens between functions without reproducing every state, form, exception, and notification.

The current overview feels abrupt because a reader loses the narrative when a box refers elsewhere. Expanding every box would make the overview too large. Use a compact process map and paired page connectors to preserve both continuity and detail.

**Reviewable source:** [one-page main-functions diagram](soc-workflow-main-functions-proposal.drawio). This function map is now integrated as page 1 of the [12-page operational workflow](soc-end-to-end-workflow-v1.7.0.drawio). The operational detail pages contain the paired connectors and remain the authoritative visual companion to the state machine.

![Single-page function map with handoff IDs and supporting controls](soc-workflow-main-functions-proposal.png)

## Page structure

Keep the existing page IDs and numbering. Replace page 1 with the compact function map when implementing this proposal.

| Page | Function and boundary |
|---|---|
| 1 | Main functions, alternative paths, terminal outcomes, and relationships to supporting controls |
| 2 | Intake: ingest/log, claim, dismiss manual reports, choose ticket or project creation |
| 3 | Single-ticket preparation: classification, route, draft, submission; Alert Bundle creates one ticket |
| 4 | Tier 2 escalation review, Event downgrade approval, monitoring, and creator lane selection |
| 5 | Individual-ticket manager review, completeness return, Normal/Emergency assessment, forwarding |
| 6 | Admin remediation, Tier 2 verification, rejection, Event reclassification, and closure gates |
| 7 | Owner remediation through the creator, Tier 2 verification, rejection, and closure gates |
| 8 | Project creation, members, project review, additions, and member routing |
| 9 | Parallel Response Requests and RCA; their effect on the APPROVED gate |
| 10 | Cancellation requests/direct cancellation, decisions, and effects on subtasks |
| 11 | Corrections and Emergency reassessment at eligible stages, with explicit return destinations |
| 12 | Terminal outcomes, notifications, OLA, and reference notes; not an execution step |

Pages 6 and 7 each retain their verification and closing steps. The overview groups those functions into one subprocess with both detail references; it does not imply a new shared application stage.

## Connector contract

Use three visually distinct relationship types:

- **Handoff:** solid arrow between function boxes. A boundary connector carries a stable `Hnn` ID, a short result/condition, the destination page, and the destination entry status or action.
- **Control or dependency:** a named badge (`G1`, `K1`, `C1`, `R1`) identifies where a parallel process or reference applies. A dependency must not appear to move the ticket to another status.
- **Navigation:** a small “Details: Pn” link and “Back to overview” link. Navigation links are not workflow arrows. A printed/exported diagram must remain usable without clicking.

On a source detail page, show an outgoing off-page connector. On its destination, show an incoming connector with the same ID. For example:

`P3 → [H04 · Incident + lane chosen · to P5]`

`P5: [H04 · from P3/P4 · PENDING_MGR_TRIAGE] → Manager review`

The page number alone is insufficient: it says where to read, but not why the process continues there. Store the source, destination, result, and entry status in one connector inventory so both ends remain consistent.

## Handoff inventory

| ID | From → to | Meaning and entry contract |
|---|---|---|
| H01 | P2 → P3 | Open a ticket form from eligible claimed source(s); an Alert Bundle still produces one ticket. Opening a form does not consume its source. |
| H02 | P2 → P8 | Open Project Incident creation from one eligible source, or create without a source; member rules stay on P8. |
| H03 | P3/P8 → P4 | Submitted Event/escalation; enters ESCALATED_T2. Project members use the Event route and cannot enter monitoring. |
| H04 | P3/P4 → P5 | Submitted Incident with Admin/Owner lane chosen; enters PENDING_MGR_TRIAGE. P4 includes T1_REVIEW completion and Monitoring → Incident. |
| H05 | P5/P8 → P6 | ADMIN forwarding enters AWAITING_CONTAINMENT. P8 performs project review or inherits an existing project verdict where allowed. |
| H06 | P5/P8 → P7 | OWNER forwarding enters AWAITING_OWNER, with the same distinction between individual and project review. |
| H07 | P4 → outcome | CLOSED_EVENT after Tier 2 confirmation and manager downgrade approval where required; documented on P12. |
| H08 | P6/P7 → outcome | APPROVED only after verification and required notified date, no open Response Request, and manager approval for Emergency. |
| H09 | P6/P7 → outcome | CLOSED_EVENT via the separate reclassification action; its current manager-gate asymmetry remains documented in the detail pages. |
| H10 | P10 → outcome | CANCELLED only when the direct-cancel or approved-request requirements pass. A pending cancellation request is not this handoff. |

The compact map combines H05/H06 on one arrow to the grouped remediation function and H08/H09 on one arrow to the outcome group. The detailed pages show these connectors separately with their exact entry/exit conditions. H07–H10 terminate at actual outcomes; P12 is their reference page, not a required processing stage.

## Supporting relationships

| Badge | Detail page | Scope and relationship |
|---|---|---|
| G1 | P9 | Manager opens Response Requests on active tickets. Requests run in parallel. Open requests block APPROVED; they do not block CLOSED_EVENT or PENDING_MANAGER. Show G1 at the approval gates on P6/P7. |
| K1 | P11 | Corrections apply only at eligible statuses. Each correction explicitly returns to its real destination on P5/P6/P7; reassessment changes a flag and does not universally move status. |
| C1 | P10 | Cancellation is available through role/stage-specific actions on active tickets. Pending, rejected, or withdrawn requests do not change the ticket stage. Successful cancellation produces H10. |
| R1 | P12 | Outcomes, email triggers, and OLA explain lifecycle-wide behavior. Reference association only. |

Do not draw one shared “active ticket” bus as a sequential step. Put a clearly labeled supporting-controls band below the main map. Use matching badges at the affected detail steps instead of connecting every control to every overview box.

## Implementation sequence

1. **Reconcile the page boundaries.** Inspect the latest draw.io file, companion Markdown, and relevant transition/action code. Confirm the handoff inventory above. Resolve any drift before changing diagram semantics, especially Monitoring → Event downgrade memory, lane selection, project review, and the APPROVED gate. Preserve unrelated or concurrent edits.
2. **Replace the overview.** Integrate the standalone draft into page `p1`. Keep one primary row, one alternative-path row, and the supporting-controls band. Preserve `p1` so existing links keep working. Use role text inside function boxes instead of full-height swimlanes on this page.
3. **Add paired connectors.** Add incoming and outgoing H01–H10 connectors to P2–P10 where applicable. H05/H06 and H08/H09 must remain separate on detail pages. Add condition labels and entry statuses; replace abrupt “go to page” boxes without removing any operational steps.
4. **Add return navigation and control badges.** Every detail page receives a Back to overview link. Add G1 at both approval gates, C1 where cancellation is referenced, K1 at correction entry/return points, and R1 for reference behavior. Use native draw.io page links such as `data:page/id,p5` only after the pages are in the same file. For the grouped P6/P7 overview box, provide two distinct clickable detail labels.
5. **Standardize diagram language.** Function subprocesses appear only on the overview. Detail pages distinguish states, actions, decisions, and off-page connectors. Arrow labels describe triggers/results; role colors remain stable. Use solid handoffs, dashed returns, and unobtrusive annotation links. Keep email paths and implementation notes away from the main route.
6. **Synchronize the companion document.** Replace its overview, publish the connector inventory and reading guide, and update references without renumbering pages. Retain detailed scenarios and current implementation caveats.
7. **Validate and publish locally.** Render with the official draw.io viewer, trace representative scenarios end to end, check hyperlinks in the editable file, and inspect a static export. Save the final editable file and a single-page overview export.

Each step depends on the preceding inventory/integration work. No runtime application changes or GitHub issues are needed for this documentation task.

## Acceptance checks

- The overview names all main functions represented by P2–P12 and fits on one landscape page. Target an A3 landscape export and readable text at 100%; no tiny text added to accommodate another exception.
- Every overview arrow states what crosses the boundary. The overview does not invent ticket statuses or suggest that browsing a detail page is an execution step.
- Handoff IDs match at both ends. Each source exit has a destination entry or an explicit terminal outcome, and each detail page offers a return link.
- Follow normal Admin and Owner cases, an Emergency case, confirmed Event, Incident downgrade, both monitoring conclusions, a Project Incident with mixed members, open Response Requests, cancellation request rejection/approval, and a manager step-back without guessing the next page.
- Monitoring remains inside P4; Project Incident review stays in P8 and does not falsely route every member through individual review on P5.
- Normal/Emergency, notified-date, and Response Request gates remain explicit on P6/P7. A requested cancellation is never shown as an immediately cancelled ticket.
- Crossings use jumps, opposing flows have separate tracks, labels do not overlap shapes, and connector meaning remains legible in a static export.
- Existing operational steps, legacy handling, implementation warnings, and page IDs remain preserved in the detailed views.

## Implemented scope

Page 1 is the compact function map. Pages 2–12 contain clickable **Back to main functions** links and footer rails for their incoming, outgoing, control, and reference relationships. Existing page IDs and detailed operational flows are preserved. The main map intentionally groups internal decisions; its completeness is at the function-and-handoff level, while the detail pages retain state-level behavior.
