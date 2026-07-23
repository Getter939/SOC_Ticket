# Documentation Index

> **Audience:** everyone · **Status:** Current · **Last updated:** 2026-07-21
> **Conventions:** lowercase kebab-case filenames; `.th.md` marks a Thai version

Every document in this folder, by audience. Start with the row that matches who
you are.

| I am… | Start here |
|---|---|
| A developer taking over the project | [handover/engineering-handover.md](handover/engineering-handover.md) |
| New to the domain vocabulary | [../CONTEXT.md](../CONTEXT.md) — the glossary |
| Setting up a dev environment | [../README.md](../README.md) |
| Deploying to production | [operations/production-deployment.md](operations/production-deployment.md) |
| Operating the reporting / analytics layer | [operations/reporting-layer-operations.md](operations/reporting-layer-operations.md) |
| A SOC analyst / manager using the app | [user-guides/end-user-guide.th.md](user-guides/end-user-guide.th.md) |
| Running a UAT session | [uat/uat-environment-setup.md](uat/uat-environment-setup.md) |
| An executive wanting the summary | [user-guides/executive-brief.th.md](user-guides/executive-brief.th.md) |

---

## handover/ — Project handover

The entry point for anyone taking over the codebase: what the system is, how the
state machine works, where the code lives, and the things not obvious from
reading the source.

| File | Contents |
|---|---|
| [engineering-handover.md](handover/engineering-handover.md) | Full technical tour (English) |
| [engineering-handover.th.md](handover/engineering-handover.th.md) | Thai translation, kept in sync |

## architecture/ — How the system is designed and why

| File | Contents |
|---|---|
| [ticket-lifecycle-states.md](architecture/ticket-lifecycle-states.md) | The current 12-state lifecycle as a mermaid diagram + transition table, organised by responsible role |
| [workflow-change-log.md](architecture/workflow-change-log.md) | Rationale for the workflow redesign and each later amendment (manager triage, response teams) |
| [reporting-layer-design.md](architecture/reporting-layer-design.md) | Reporting layer (Layer ③ `mart` schema) design spec — grains, canonical metric definitions, severity normalization, derived-vs-snapshot, phased rollout |
| [reporting-layer-build.md](architecture/reporting-layer-build.md) | As-built record of the reporting layer (Phases 1–3): objects, migrations, privilege model, decisions |
| [data-infrastructure.md](architecture/data-infrastructure.md) | The whole data picture — every store, the flows between them, the four-layer model, and how backup fits (with a mermaid diagram) |

## adr/ — Architecture decision records 📌

One decision per file, sequentially numbered. Read these before changing the
area they cover — they record *why*, which the code cannot.

| File | Decision |
|---|---|
| [0001](adr/0001-case-bundling-fan-out.md) | A Project Incident fans out into one member Ticket per affected system, rather than one Ticket carrying many assets |
| [0002](adr/0002-ola-clock-from-incident-time.md) | OLA clocks start from when the incident occurred, not when the Ticket was filed |
| [0003](adr/0003-manager-verification-gate-in-model.md) | The manager-verification gate is enforced in the model, not only the view |

## operations/ — Running it in production

| File | Contents |
|---|---|
| [production-deployment.md](operations/production-deployment.md) | Docker/nginx/gunicorn runbook, account creation, roles, logs |
| [reporting-layer-operations.md](operations/reporting-layer-operations.md) | Running & deploying the reporting layer: the `refresh_reporting` command, scheduling, the **production-readiness checklist**, verification, rollback, troubleshooting |
| [reporting-ro-setup.sql](operations/reporting-ro-setup.sql) | One-time superuser SQL creating the read-only `reporting_ro` role for Grafana/BI (run at Phase 4 cutover) |
| [backup-and-restore.md](operations/backup-and-restore.md) | What the backup covers, the restore procedure (incl. the roles/grants-not-in-the-dump gap), retention, and the 3-2-1 storage strategy |
| [backup-storage-decision-brief.md](operations/backup-storage-decision-brief.md) | One-page brief for the CISO / data-governance / compliance decision on backup storage location & retention |
| grafana-wazuh-wall.md 🚫 | The "Wazuh SOC Wall" big-screen board. Reads **directly** from the Wazuh Indexer (OpenSearch), not from this app's PostgreSQL |

## user-guides/ — For people using the app

| File | Contents |
|---|---|
| [end-user-guide.th.md](user-guides/end-user-guide.th.md) | Thai end-user guide: every state, every role, per-screen walkthroughs |
| [executive-brief.th.md](user-guides/executive-brief.th.md) | Thai one-pager for executives — capabilities and governance, no implementation detail |
| feature-guide.docx | Feature guide with screenshots and per-role walkthroughs |
| system-overview.th.docx / .th.pdf | Thai system overview document (was `ระบบจัดการการรายงานปัญหา (SOC Ticketing System)`) |

## uat/ — User acceptance testing

| File | Contents |
|---|---|
| uat-environment-setup.md 🚫 | Getting the UAT VM seeded so every role has a login and every dashboard has data |
| uat-test-scenarios.md 🚫 | Guided end-to-end scenarios to run as a group, then a free-play checklist |
| uat-feedback-log.md 🚫 | Low-friction feedback capture — one row per observation |
| uat-vm-operations-guide.docx | VM setup and operations manual. Generated by `.codex_work/build_uat_vm_guide.py` — edit the script, not the .docx |

## diagrams/ — Generated and hand-drawn diagrams

| File | Contents |
|---|---|
| database-er-diagram.svg | ER diagram of the live schema |
| ticket-flow-by-role.svg | Ticket flow swimlanes by role |

## agents/ — AI coding-agent configuration 📌

Not product documentation. These files configure how the engineering skills in
`.agents/skills/` interact with this repo.

| File | Contents |
|---|---|
| [domain.md](agents/domain.md) | Declares the single-context layout (one `CONTEXT.md` + `docs/adr/`) |
| [issue-tracker.md](agents/issue-tracker.md) | Issues live in GitHub `Getter939/SOC_Ticket`, driven via `gh` |
| [triage-labels.md](agents/triage-labels.md) | Maps the five canonical triage roles to this repo's label strings |

---

## Notes

**📌 `adr/` and `agents/` are exempt from the conventions above.** Their paths
and filenames are hardcoded in the agent skills under `.agents/skills/` and in
the root `AGENTS.md`, so they keep their existing names. ADRs additionally
follow a prescribed format (`NNNN-slug.md`, often a single paragraph) defined in
`.agents/skills/domain-modeling/ADR-FORMAT.md` — do not impose the house header
block on them.

**🚫 marks files that git does not track.** `.gitignore` line 62 is a bare
`*.md`, so these exist on disk but are untracked. Do not conclude from
`git log` alone that they are missing or unwritten.

**Paths changed on 2026-07-21.** Files were previously flat in `docs/`; older
commit messages and Notion pages still reference the old locations. See §7 of
[handover/engineering-handover.md](handover/engineering-handover.md) for the old→new mapping.

**Source of truth.** For *behaviour*, the code wins — specifically
`apps/incidents/models.py` (`STATUS_CHOICES`, `ALLOWED_TRANSITIONS`) and
`apps/accounts/models.py` (`ROLE_CHOICES`). For *terminology*,
[../CONTEXT.md](../CONTEXT.md) wins. Prose docs are downstream of both.
