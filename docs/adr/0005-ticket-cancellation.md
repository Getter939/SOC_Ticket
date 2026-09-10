# Cancellation requires an audited decision separate from incident resolution

Date: 2026-09-10

A mistaken or duplicate Ticket may end as `CANCELLED`. Cancellation does not classify
the case as an Event and does not certify successful remediation. Classification,
evidence, references, Alert links and Project Incident membership remain intact.

The Tier 1 creator may cancel only while a Ticket remains NEW. After handoff, the
creator or current workflow actor requests cancellation and the SOC Manager approves
or rejects it. The manager may also cancel directly. A superuser has the existing
manager override, with the same reason and audit requirements. The requester may
withdraw a pending request. There is no cancellation of a terminal Ticket or reopening.

`TicketCancellationRequest` stores separate request and decision history, including
direct decisions. A conditional unique constraint allows one pending request per Ticket.
Pending requests do not pause OLA or move the Ticket into a new workflow stage.
Normal closure supersedes the request; rejection leaves the current stage unchanged.

`Ticket.cancellation_action` is the authoritative model entry point; its implementation
validates permissions under a parent Ticket row lock. Generic status changes cannot
enter CANCELLED. Ordinary saves, transitions and subtask creation serialize against
cancellation; stale writes cannot restore a cancelled Ticket or create unfinished work.
Project members use the Project Review lock order (Project Incident, then Ticket).

All unfinished subtasks must be completed or individually selected for cancellation by
the manager. Selection is rechecked against current work at approval; cancelled work
gets its own CANCELLED status rather than being counted as DONE.

The cancellation decision stamps terminal `closed_at`; resolution sign-offs remain
untouched. Dashboards and the reporting mart distinguish cancellation from resolution,
exclude it from MTTR and OLA-success denominators, and preserve historical timing.
Notifications run after commit. All new user-facing text is Thai.

This follows ADR-0003's model-level enforcement principle and ADR-0004's independent
Member Ticket lifecycle. There is no bulk Project Incident cancellation in this change.
