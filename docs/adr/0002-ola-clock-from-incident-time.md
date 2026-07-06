# OLA clocks start from incident time, not ticket-creation time

OLA triage and contain deadlines are computed from when the incident actually occurred (`incident_datetime`), falling back to now() only if that is left blank — not from when the Ticket was filed (`created_at`).

Chosen so that the OLA reflects real responsiveness to the threat: a Ticket opened hours after an incident is already burning its triage margin, and the metric should show that rather than resetting the clock at filing time. The surprising consequence is that a Ticket can be **born already breached**, and `is_ola_triage_breached` is fixed at issue time rather than counting live — a reader who assumes the clock starts at creation would "fix" this incorrectly, so it is recorded here.
