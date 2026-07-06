# Case Bundling: one Project Incident fans out to many independent member Tickets

When a single real-world Incident affects multiple systems, we model it as a **Project Incident** that fans out into one **member Ticket per affected system**, rather than one Ticket carrying many assets. Each member routes to its own System Admin and is contained and closed independently on its own OLA clock; the Project Incident is only a grouping/rollup unit with no lifecycle of its own.

Chosen because affected systems have different owners, admins, and containment timelines that must be tracked and closed separately — a single multi-asset Ticket cannot express per-system OLA breach or per-admin routing. The cost is a stable trackable id scheme (`<project_code>-<bundle_suffix>`, e.g. `PI-260706-01-C`) and rollup logic to report bundle-level status. This is schema-level and hard to reverse, so it is recorded here.
