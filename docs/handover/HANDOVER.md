# SOC Ticketing System — Handover Document

_Last updated: 2026-07-21 (repo at commit `3967bfb`, "21/7 Codebase Audit")_
_ฉบับภาษาไทย: [HANDOVER.th.md](HANDOVER.th.md)_

This document is the entry point for anyone taking over this project. It covers
what the system is, how it works, where the important code lives, how to run
and deploy it, and the things that are **not** obvious from reading the code.

Companion documents (read in this order):

| Document | What it covers |
|---|---|
| [README.md](../../README.md) | Local dev setup, test-data seeding, offline Wazuh fixtures |
| [CONTEXT.md](../../CONTEXT.md) | **The glossary** — what every domain term means (Incident vs Event, OLA, Response Request…). Read this first if the vocabulary is unfamiliar |
| [workflow-redesign.md](../architecture/workflow-redesign.md) | Full rationale for the ticket workflow redesign and its later amendments |
| [soc-ticket-flow.md](../architecture/soc-ticket-flow.md) | The current end-to-end flow, per role |
| [deployment.md](../operations/deployment.md) | Production deployment (Docker, nginx, gunicorn) |
| [adr/](../adr/) | Architecture decision records (case bundling, OLA clock origin, manager gate) |
| `../user-guides/SOC_Ticketing_System_Feature_Guide.docx` | End-user feature guide (screenshots, per-role walkthroughs) |
| [user-guide-th.md](../user-guides/user-guide-th.md) | Thai end-user guide |
| Notion: "SOC Ticketing System — Technical Documentation" | Full technical reference |

---

## 1. What this is and why

A Django-based **SOC (Security Operations Centre) ticketing and incident
management platform** for an internal Thai SOC team. It manages the full
lifecycle of security incidents: alert ingestion from Wazuh/OpenSearch, triage,
ticket creation, escalation, containment by system administrators, analyst
verification, manager approval, and OLA (Operational Level Agreement)
deadline tracking — plus a KPI dashboard.

- A previous iteration lives at `C:\Users\NT\Documents\soc-crm`; this repo is
  the current, active version.
- UI labels are a mix of Thai and English (verbose_names on models are Thai).
- Runs on an internal LAN over HTTP by default; HTTPS hardening flags exist
  but are opt-in via `.env` (see §7).

**Key design decisions and their rationale:**

- **Two separate assignment fields** — `assigned_to` (SOC analyst working the
  ticket) and `assigned_admin` (system administrator doing containment) are
  deliberately separate roles on a ticket. Do **not** merge them.
- **The SOC Manager sits *before* containment, not only at the end** — every
  Incident stops at `PENDING_MGR_TRIAGE` so the manager can rule Emergency and
  forward it. This is a blocking checkpoint, deliberately not a parallel one.
- **Emergency is a manager-only flag** — it is the single input that decides
  whether a ticket needs manager approval to close. No other role may touch it.
- **Classification is authoritative, never derived** — `classification`
  (`INCIDENT` / `EVENT`, formerly TP/FP) is set explicitly by Tier 1 at
  creation (Tier 2 may revise it on escalated tickets). It gates which state
  transitions are legal.
- **Tier carries permission weight** (since the 2026-06-19 redesign) — T1/T2
  on SOC staff is not just a seniority label. Only Tier 1 creates tickets and
  drives the T1 side of the workflow; Tier 2 only handles escalated tickets
  and can never assign admins or create tickets. See architecture/workflow-redesign.md for
  the full reasoning.
- **OLA breach semantics differ by deadline** — the *triage* breach is a fixed
  historical fact ("was the ticket raised in time?"), while the *contain*
  breach is a live countdown on active tickets. See §4.
- **Attachments are evidence** — they are only served through an
  authenticated, authorization-checked download view. This closed a real
  stored-XSS / unauthenticated-download hole. See §8.

## 2. Tech stack

| Component | Version / detail |
|---|---|
| Python / Django | Django 6.0.7 (see `requirements.txt` for exact pins) |
| Database | PostgreSQL 16 (`psycopg2-binary`) |
| Config | `python-decouple` reading `.env` (template: `.env.example`) |
| Static files | WhiteNoise |
| Prod server | gunicorn behind nginx, via `docker-compose.prod.yml` |
| Excel export | openpyxl (`export_tickets_excel` in incidents views) |
| Alert source | Wazuh alerts via the OpenSearch REST API (`requests`) |
| Login throttling | `django-axes` 7.1.0 (lockout on repeated failed logins) |

Migration heads at time of writing: `incidents 0046`, `wazuh_ingest 0006`,
`accounts 0006`.

## 3. Feature summary

### 3.1 Ticket lifecycle (state machine)

**Twelve** states, defined in `apps/incidents/models.py` (`STATUS_CHOICES`,
`ALLOWED_TRANSITIONS`) and enforced by `Ticket.transition_to`:

```
NEW
 ├─(T1 escalates; either classification)──► ESCALATED_T2
 │                                            ├─(T2: EVENT)──────► CLOSED_EVENT (terminal)
 │                                            └─(T2: INCIDENT)───► T1_REVIEW
 │                                                                    │
 └─(T1 commits an INCIDENT, picking t1_route)◄───────────────────────┘
    │
    ▼
 PENDING_MGR_TRIAGE          ← SOC Manager: rule Emergency, forward to the
    │                          lane Tier 1 already chose (cannot change it)
    ├─(t1_route = ADMIN)──► AWAITING_CONTAINMENT ──► CONTAINMENT_REPORTED
    │                             ▲   (admin submits report)   │
    │                             └───(T2: not contained)──────┤
    │                                                          │
    └─(t1_route = OWNER)──► AWAITING_OWNER ──► OWNER_REMEDIATED │
                                 ▲  (T1 records owner fix)   │  │
                                 └──(not actually fixed)─────┘  │
                                 ▲                              │
                                 │        PENDING_T2_REVIEW ◄────┤ (mandatory
                                 └──(T2 rejects)──┘              │  T2 verify)
                                                                 │
        both verification queues ─┬─(verified, not emergency)────┴──► APPROVED (terminal)
                                  ├─(verified + emergency)──► PENDING_MANAGER ──► APPROVED
                                  └─(T2 reclassifies → EVENT)──────────► CLOSED_EVENT (terminal)
```

Rules that are easy to get wrong:

- **Two handling lanes, chosen by Tier 1 and frozen.** `t1_route` (`ADMIN` /
  `OWNER`) is picked when Tier 1 commits an Incident, and the manager's review
  can only forward it to that predetermined lane — the manager cannot switch
  lanes. `ADMIN` → System Admin contains it; `OWNER` → the system owner fixes
  it themselves and Tier 1 records the outcome.
- **The manager review is blocking and Incident-only.** Every Incident passes
  `PENDING_MGR_TRIAGE` before any containment work starts. Events never reach
  it — the SOC Manager is never involved in an Event.
- **On escalations T2 can only return tickets to T1 (`T1_REVIEW`) or close
  events** — T2 never assigns admins and never creates tickets. T2 *does*
  verify: `CONTAINMENT_REPORTED` and `PENDING_T2_REVIEW` are both Tier 2
  queues (`TIER2_QUEUE_STATUSES`), and the owner lane's T2 verification is
  mandatory, not optional.
- Two **rejection loops**: `CONTAINMENT_REPORTED → AWAITING_CONTAINMENT` (T2
  judges containment insufficient; the admin is re-notified) and
  `PENDING_T2_REVIEW → AWAITING_OWNER` / `OWNER_REMEDIATED → AWAITING_OWNER`.
- **Mid-containment reclassification**: Tier 2 may flip an in-flight Incident
  to `EVENT` and close it from either verification queue
  (`EVENT_CLOSE_TRANSITIONS`) — this bypasses the manager *even if the
  emergency flag is set*, because the manager never handles Events.
- **Manager routing**: `requires_manager_verification` is true **only when the
  ticket is flagged emergency** — severity alone never routes to the manager
  (the old `SOC_SEVERITY_FLOOR` setting is gone). An emergency ticket passes
  Tier 2 verification first, then `PENDING_MANAGER`; everything else is closed
  (`APPROVED`) by Tier 2 directly.
- **Open Response Requests block closure.** Any open response-team subtask
  makes `has_open_response_requests` true, and `transition_to` refuses *every*
  edge into `APPROVED` until they are done. Event-close is exempt. See §3.5.
- Permission tokens (`TIER1_CREATOR`, `TIER2`, `ASSIGNED_ADMIN`, `MANAGER`) are
  declared per-transition in `TRANSITION_PERMISSIONS`; `transition_to` also
  enforces the classification gate, the manager-routing gate, and the
  response-request gate. `TIER1_CREATOR` means *the original creator* — not any
  Tier 1 analyst (see `CREATOR_REVIEW_STATUSES`).
- Old states `UNDER_REVIEW` / `VERIFIED` / `CLOSED_FP` were removed by
  migration 0018 (remapped to `CONTAINMENT_REPORTED` / `PENDING_MANAGER` /
  `CLOSED_EVENT`). If you see them in old docs or the git history, translate.
- `STATUS_PILL_COLORS` on the model is the **single source of truth** for
  status colors across the dashboard, ticket list, and queue badges. Red is
  deliberately reserved for danger (Critical / Emergency / OLA breach) and is
  never a status color.

### 3.2 Roles (`apps/accounts/models.py` — `UserProfile`)

**Seven** roles (`UserProfile.ROLE_CHOICES`), the last two added 2026-07-20:

| Role | Capabilities |
|---|---|
| **SOC Staff, Tier 1** | Creates tickets (manual triage or from Wazuh alerts), sets classification, picks the handling route (`t1_route`), escalates to T2, and drives the Direct-to-Owner lane. The only role that creates tickets. |
| **SOC Staff, Tier 2** | Works `ESCALATED_T2` (revise classification, return to T1, close as Event) **and** both verification queues — `CONTAINMENT_REPORTED` and `PENDING_T2_REVIEW`. Closes every non-emergency ticket. |
| **SOC Manager** | Runs the pre-containment review (`PENDING_MGR_TRIAGE`): rules Emergency and forwards to the fixed lane. The **only** role that may set `is_emergency`. Spawns Response Requests. Approves `PENDING_MANAGER` → `APPROVED`. |
| **System Admin** | Sees only tickets where they are `assigned_admin`. Writes `containment_report` (countermeasure) and `remediation_summary` (findings), returns the ticket for verification. Never sets classification. |
| **System Owner** | Notified when tickets open/close on systems they own; has a read-oriented "My Tickets" dashboard at `/incidents/my-tickets/`. |
| **Forensic Analyst** | Response-team role, **not** a SOC member. Sees only tickets carrying a Forensics/RCA Response Request assigned to them; works from the "Response Requests" queue. |
| **Red Team Manager** | Response-team role, **not** a SOC member. Receives both VA/Pentest and Infrastructure Security Response Requests. |

Visibility is centralized in `TicketQuerySet.visible_to(user)`: SOC roles see
all tickets, system admins see only their assigned tickets, the two response
roles see only tickets with a Response Request assigned to them, and users
without a profile see nothing. **Always check `getattr(user, 'profile', None)`
before role checks** — superusers created via `createsuperuser` have no profile.

### 3.3 Emergency flag

`is_emergency` is **SOC-Manager-only** (`can_set_emergency`; superusers may
too). No other role — including Tier 1 and Tier 2 — may touch it. The canonical
decision point is the pre-containment review (`PENDING_MGR_TRIAGE`), where the
manager rules Emergency yes/no before forwarding, but the manager may still
correct or raise it at **any** later stage, including terminal states. Every
toggle writes a `TicketLog` recording who changed it and the old→new value.
Emergency is the sole trigger for manager verification before close.

> Historical note: an earlier design let any role *except* Tier 1 toggle this,
> with a `was_escalated_to_t2` carve-out. That rule is gone — if you find code
> or docs referring to it, they predate the manager-triage redesign.

### 3.4 OLA policy (reworked 2026-07-01 — the most recent change)

Terminology: this system says **OLA**, not SLA (renamed in migrations
0028–0030). Two deadlines per ticket, both computed at creation from
`incident_datetime` (fallback: now), per severity via `Ticket.OLA_TARGETS`:

| Severity | Triage (raise ticket within) | Contain (resolve within) |
|---|---|---|
| Critical | 30 min | 4 h |
| High | 2 h | 24 h |
| Medium | 24 h | — (notification-only) |
| Low | 24 h | — (notification-only) |
| Unknown | mirrors Critical | mirrors Critical |

- **Triage OLA** (`is_ola_triage_breached`, alias `is_ola_breached`): a
  **fixed fact** — was `created_at` later than the triage deadline? Evaluated
  at issue time, never changes afterwards.
- **Contain OLA** (`is_ola_contain_breached`): a **live countdown** — an
  active (non-terminal) ticket past its contain deadline. Medium/Low have no
  contain deadline and can never contain-breach.
- `apps/incidents/ola.py` is the **single source of truth** for bucketing the
  active queue by contain-deadline pressure (Overdue / Due ≤1h / Due 1–4h /
  On-track). The dashboard chart and the ticket-list OLA filter both use it —
  change policy there, both surfaces follow.
- **Separate from all of the above**: `WazuhAlert` has its own flat 4-hour
  *alert triage* OLA (`WazuhAlert.OLA_HOURS`) running live from
  `alert.timestamp` until the alert is triaged.

### 3.5 Response Requests (response teams) — added 2026-07-20

A **Response Request** is a specialised `TicketSubtask` the SOC Manager spawns
to a team outside the SOC, running **in parallel** to containment.

- `TicketSubtask.TYPE_CHOICES` holds five types. Two are the ordinary
  SOC-spawned kinds (`INVESTIGATION`, `COUNTERMEASURE`); the three in
  `RESPONSE_TYPES` are response requests:

  | Type | Routes to |
  |---|---|
  | `VA_PT` (VA / Pentest) | Red Team Manager |
  | `INFRA_SEC` (Infrastructure Security) | Red Team Manager |
  | `FORENSIC_RCA` (Forensics / RCA) | Forensic Analyst |

- Spawning **auto-assigns** to the sole holder of the target role; if several
  exist, the manager picks. The responder works it from the **"Response Requests"** queue.
- **The approval gate**: while any response request on a ticket is not `DONE`,
  `Ticket.has_open_response_requests` is true and `transition_to` blocks every
  edge into `APPROVED` — the Verify button disappears in the UI rather than
  failing on submit. **Event-close is deliberately exempt.**
- Subtask status is `OPEN` / `IN_PROGRESS` / `DONE`, tracked independently of
  the parent ticket's status.
- Two notification templates cover it: `RESPONSE_REQUEST_CREATED` (to the
  responder) and `RESPONSE_REQUEST_COMPLETED` (back to the manager).

### 3.6 Project Incidents (case bundling)

One real-world incident that hit multiple systems is worked as several linked
tickets — one per affected system — grouped by a `ProjectIncident` with a
`bundle_suffix` per member. See [adr/0001-case-bundling-fan-out.md](../adr/0001-case-bundling-fan-out.md).

- The grouping is a **rollup unit only**; it has no lifecycle of its own. Each
  member ticket is contained, verified, and closed independently on its own OLA
  clock. Only the target (device / IP / owner / admin) differs between siblings.
- A ticket's own **Ticket Reference never changes** when it joins a project
  incident — the member reference supplements it, never replaces it.
- Dashboard rollup and bundled report export were scoped out of phase 1 and are
  still not implemented.

### 3.7 Wazuh alert ingestion & triage (`apps/wazuh_ingest`)

- `python manage.py ingest_wazuh_alerts` pulls alerts from the OpenSearch REST
  API (`wazuh-alerts-*/_search`, HTTP Basic auth, config in `.env`). An ingest
  watermark prevents re-pulling; OpenSearch document IDs dedupe.
- `--fixture` mode loads bundled demo alerts with no network access (see
  README) — this is how you demo/test without reaching the cluster.
- Triage (claim / create ticket / release) is **Tier-1-only**. Releasing an
  alert **requires a reason** (`release_reason`). The alert-level
  `escalation_queue` is vestigial — escalation now happens at ticket level.
- There is **no scheduler in the repo** for ingestion — if production ingests
  periodically, that's an external cron/scheduled task on the host. Verify
  with the operator.

### 3.8 Notifications (`apps/incidents/notifications.py`)

- Email via SMTP (config in `.env`); `SITE_URL` builds absolute links.
- Subjects and bodies are **editable in the admin** via `NotificationTemplate`,
  keyed by `KEY_CHOICES` with per-key placeholder hints (`PLACEHOLDERS`). Seven
  keys exist today:

  | Key | Goes to |
  |---|---|
  | `CONTAINMENT_REQUIRED` | assigned System Admin |
  | `CONTAINMENT_SUBMITTED` | SOC | 
  | `MANAGER_TRIAGE_PENDING` | SOC Manager — an Incident is waiting at the pre-containment review |
  | `OWNER_CREATED` / `OWNER_CLOSED` | System Owner |
  | `RESPONSE_REQUEST_CREATED` | Forensic Analyst / Red Team Manager |
  | `RESPONSE_REQUEST_COMPLETED` | SOC Manager |

- `notify_containment_required` fires whenever a ticket reaches
  `AWAITING_CONTAINMENT` (initial assignment **and** every rejection loop).
- System owners are notified on open/close of tickets for their systems.
- New-user credential emails and admin-panel actions to resend usernames /
  reset passwords (Thai-labelled actions in the Users admin).
- Failures are **non-fatal by design**: a failed email shows a warning but
  never rolls back the transition.

### 3.9 Dashboard (`apps/dashboard`)

KPI/chart home page (`/`): case status pipeline, categories, OLA-pressure
buckets, and a ticket table with a "Status Updated" column driven by
`status_changed_at` (a dedicated field re-stamped **only** on real status
transitions — notes and emergency toggles bump `updated_at` but not this).
Charts are fed via `json_script` (no `|safe` on user data — keep it that way).

### 3.10 Other features

- Ticket attachments (25 MB cap, download-only serving — see §8), subtasks,
  ticket logs/history with edit, Excel export, global search, IP lookup,
  manual triage records (`TriageRecord.source` shares choices with
  `Ticket.source`).

## 4. Codebase guide

```
config/                 settings.py, urls.py, middleware.py (CSP)
apps/
  incidents/            ★ THE core app — start here
    models.py           Ticket + state machine + OLA + logs/attachments/subtasks/
                        ProjectIncident/NotificationTemplate (~106 KB)
    views.py            all ticket/triage/response-queue views (~82 KB)
    notifications.py    every email the system sends
    ola.py              OLA bucketing single source of truth
    forms.py            ticket/triage/attachment forms (incl. upload size cap)
    reports.py          report generation
    report_content.py   report copy / content blocks
    report_templates/   report layout templates
    management/commands/
      seed_data.py               synthetic tickets for dev (7 role users)
      seed_dashboard_mockup.py   demo/screenshot dataset
      seed_ola_demo_buckets.py   OLA-chart demo dataset
      seed_response_demo.py      response-team demo data
      seed_uat_states.py         one ticket per lifecycle state, for UAT
      seed_ceo_demo.py           executive-dashboard demo dataset
      import_trendmicro.py       Trend Micro CSV import
  accounts/             UserProfile (role, tier), admin actions for credentials
  dashboard/            KPI views + executive dashboard + tests
  wazuh_ingest/         WazuhAlert model, OpenSearch ingest, triage views
templates/              Django templates (base.html + per-app dirs)
```

**Reading order for a new developer:**

1. [CONTEXT.md](../../CONTEXT.md) — the glossary. Twenty minutes here saves hours
   of guessing what "Event", "OLA", or "Response Request" mean.
2. `apps/incidents/models.py` — the `Ticket` model top to bottom: statuses,
   `ALLOWED_TRANSITIONS`, `TRANSITION_PERMISSIONS`, `transition_to`,
   `OLA_TARGETS`, `save()`.
3. [workflow-redesign.md](../architecture/workflow-redesign.md) — why the state machine is
   shaped this way, including the manager-triage and response-team amendments.
4. `apps/incidents/views.py` — `ticket_detail` and the transition-posting
   views; then `apps/wazuh_ingest/views.py` for the alert-to-ticket path.
5. Trace one ticket end-to-end in the UI using the seeded accounts (§5).

**Tests** are substantial and are the executable spec of the workflow:
`apps/incidents/tests.py` (~148 KB) covers transitions/permissions,
`apps/dashboard/tests.py` covers KPI math, `apps/wazuh_ingest/tests.py` mocks
all HTTP, plus focused suites in `apps/incidents/test_ui_smoke.py`,
`test_lookup_search_import.py`, and `test_dashboard_mock_seed.py`. Run
everything with `python manage.py test` — do this before and after any workflow
change.

## 5. Running it locally

Condensed from README.md (authoritative if they diverge):

```bash
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt
copy .env.example .env                               # then fill in values
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:8088
```

Needs a reachable PostgreSQL 16 (`DB_*` in `.env`). App at
`http://127.0.0.1:8088/`, admin at `/admin/`.

**Test data:**

- `python manage.py seed_data` — 100 tickets / 30 days in a random weighted
  mix, all severities, plus **seven** role users (`seed_t1`, `seed_t2`,
  `seed_manager`, `seed_sysadmin`, `seed_sysowner`, `seed_forensic`,
  `seed_redteam`). Rows carry the `seed_` username prefix so they can be wiped
  cleanly (`--flush`). **It predates the four newer states and does not
  generate them** — use `seed_uat_states` for those.
- `python manage.py seed_uat_states` — deterministic: one ticket parked in
  **each of the 12** states, so every screen and button can be exercised
  without walking the whole workflow. Tagged with a `uat_` prefix (not `seed_`)
  so its `--flush` removes exactly its own rows and nothing a live tester made.
- `python manage.py seed_response_demo` — tickets with open/closed Response
  Requests, for the response-team queues and the approval gate.
- `python manage.py ingest_wazuh_alerts --fixture [--fresh]` — offline demo
  alerts for the Wazuh triage flow.
- `test_accounts.txt` — dev logins, one per role. **Dev only; never create
  these in production.**

## 6. Deployment

Production: `docker compose -f docker-compose.prod.yml up -d --build`
(nginx → gunicorn → Django + PostgreSQL). The `web` container runs
`migrate` + `collectstatic` on every start. Full runbook in operations/deployment.md
(UFW, superuser creation, team accounts, logs).

- `docker-compose.yml` (no suffix) is **local dev only** (runserver +
  bind-mount). Never deploy it.
- No public sign-up: all accounts are created via `/admin/`.
- **Ask the outgoing owner:** where production actually runs (host/IP), who
  holds the `.env` secrets (DB password, SMTP, OpenSearch credentials), and
  what backs up the PostgreSQL volume — none of this is in the repo.

## 7. Known issues, gotchas, stale docs

1. **Docs have moved twice — old paths in commits and Notion are stale.**
   First `WORKFLOW_REDESIGN.md` and `DEPLOY.md` moved from the repo root into
   `docs/`; then on 2026-07-21 everything under `docs/` was filed into category
   subfolders. Current locations:

   | Old path | Current path |
   |---|---|
   | `WORKFLOW_REDESIGN.md` | `docs/architecture/workflow-redesign.md` |
   | `DEPLOY.md` | `docs/operations/deployment.md` |
   | `docs/HANDOVER.md` | `docs/handover/HANDOVER.md` |
   | `docs/soc-ticket-flow.md` | `docs/architecture/soc-ticket-flow.md` |
   | `docs/user-guide-th.md`, `docs/ceo-brief-th.md` | `docs/user-guides/` |
   | `docs/UAT_*.md` | `docs/uat/` |
   | `docs/*.svg` | `docs/diagrams/` |

   `docs/adr/` and `docs/agents/` did **not** move — those paths are hardcoded
   in the agent skills under `.agents/skills/` and in the root `AGENTS.md`.
   See [docs/README.md](../README.md) for the full index.
2. **CSP still allows `'unsafe-inline'`** for script/style
   (`config/middleware.py`, policy string in settings). Two inline handlers
   block going nonce-based: `ticket_detail.html` (confirm) and
   `ticket_history.html` (onchange). Planned next hardening step.
3. **No file-type/magic-byte validation on uploads** (low priority — mitigated
   by forced-download serving, §8).
4. **Alert-level `escalation_queue` is vestigial** after the redesign;
   escalation is ticket-level now.
5. **`runserver-8099.*.log` files in the repo root** are stray dev logs —
   deletable.
6. **OLA breach semantics are asymmetric** (fixed triage fact vs live contain
   countdown, §3.4) — easy to "fix" incorrectly if you assume both are live.
7. **The 0030 data migration recomputed all OLA deadlines** under the new
   per-severity policy. Historical breach stats from before 2026-07-01 reflect
   the recomputation, not what dashboards showed at the time.

## 8. Security posture (hardened 2026-06-15, VibeSec audit)

- **Attachments**: served **only** via `incidents.views.download_attachment`
  (login + `visible_to` check + forced `Content-Disposition: attachment` +
  `nosniff`). **Never re-add an open `/media/` route in `config/urls.py`** —
  that exact hole previously allowed unauthenticated downloads and stored XSS
  via uploaded `.html`/`.svg`. The dev-only media route is login-gated and
  mirrors prod behaviour.
- Upload size capped at 25 MB (`MAX_ATTACHMENT_SIZE`), enforced in the form
  **and** the create-ticket evidence loop.
- HTTPS flags (`SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`,
  `SECURE_SSL_REDIRECT`, HSTS, `USE_PROXY_SSL_HEADER`) are env-driven and
  default **off** so the internal-HTTP deploy works — **turn them on in any
  TLS deployment.**
- CSP via custom middleware; everything except script/style locked to
  `'self'` + `cdn.jsdelivr.net`.
- OpenSearch ingest supports TLS verification against a self-signed cluster
  cert via `OPENSEARCH_CA_BUNDLE` (recommended over `OPENSEARCH_VERIFY_SSL=False`).
- Dashboard chart data passed via `json_script`, not `|safe`.

## 9. External dependencies & contacts

| Dependency | Detail | Owner / where |
|---|---|---|
| PostgreSQL 16 | app database | _(fill in: host, backup owner)_ |
| SMTP server | all notifications | _(fill in: provider/account owner)_ |
| Wazuh / OpenSearch cluster | alert feed, HTTP Basic creds in `.env` | _(fill in: SOC infra owner)_ |
| Notion tech docs | "SOC Ticketing System — Technical Documentation" | workspace of the outgoing maintainer |
| OLA policy | who decides the per-severity targets in `OLA_TARGETS`? | _(fill in: SOC manager?)_ |

> **To the outgoing maintainer:** the italicized blanks above, plus §6's
> production questions, are the items only you can answer. Fill them in before
> handing this over.

## 10. Suggested first week

- **Day 1** — read [CONTEXT.md](../../CONTEXT.md) for the vocabulary, then run it
  locally (§5), `seed_data` + `seed_uat_states`, and log in as each of the
  seven role accounts and click around.
- **Day 2** — read `Ticket` in `models.py` + architecture/workflow-redesign.md; trace one
  incident from Wazuh fixture alert → triage → **manager pre-containment
  review** → containment → Tier 2 verification → approval, as the appropriate
  user at each step. Then repeat down the Direct-to-Owner lane.
- **Day 3** — run the full test suite; skim `incidents/tests.py` to see the
  workflow rules as executable spec.
- **Day 4** — review the dashboard views + `ola.py`; understand the OLA
  buckets and `status_changed_at`.
- **Day 5** — review operations/deployment.md against the real production host with the
  outgoing maintainer; confirm secrets, backups, and the ingest schedule.
