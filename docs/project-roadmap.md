# SOC Ticket — Progression & Road to Go-Live

> **Audience:** you (project owner) · **Status:** Current · **Last updated:** 2026-08-27
> **Companion to:** [../PROJECT_STATUS.md](../PROJECT_STATUS.md) (this week's lanes) — this file is the *whole* arc

The short answer to "how far am I?": **the software is essentially finished; the
delivery is not.** You are roughly **two-thirds through the project**, and the
remaining third is almost entirely non-coding work — acceptance testing,
production build, cutover, and the first month of running it. That is normal.
It is also the part that most solo-built systems never finish, so it is worth
naming the pieces explicitly.

---

## 1. Where you actually are — evidence, not vibes

Verified against the repo on 2026-08-27:

| Signal | Reading |
|---|---|
| Test suite | **837 tests, all passing**; **86.3% branch coverage** |
| Application code | ~14,000 production Python lines + ~6,700 template lines across 5 Django apps |
| Lifecycle | 13-state FSM, 7 roles, transitions enforced in the model |
| Feature backlog | Core workflow **complete**; 4 deferred nice-to-haves remain |
| Reporting layer | Phases 1–3 built; 4–5 pending; nightly refresh **not scheduled** |
| Docs | 25+ documents incl. Thai user guides, ADRs, handover, runbooks |
| CI | **GitHub Actions** (`.github/workflows/ci.yml`) — Postgres 18 + Python 3.14; Ruff correctness rules, migration-drift check, the full test suite, and an 85% coverage floor, on every push + PR |
| App logging | Rotating file + console handlers configured in `config/settings.py` |
| Production | **Live** on the self-signed HTTPS IP bridge (`https://10.1.220.118`, Windows/Waitress/IIS); nightly encrypted backups + off-host pull + streaming standby; Wazuh ingest, reporting mart, and retention scheduled. Real CA cert + DNS still the long pole |
| UAT | 1 of 7 roles in progress (SOC Manager); 6 unstarted |

The remaining work is primarily UAT and operational acceptance (hypercare);
production is live on the self-signed HTTPS bridge — a real CA cert + DNS are the
last go-live gate — and the codebase refactor is delivered as behavior-preserving
phases behind CI.

---

## 2. The phase map

Standard software-delivery phases, scored against this project.

| # | Phase | State | Done |
|---|---|---|---|
| 1 | Requirements & domain design | Glossary, ADRs, state machine, change log all written | ✅ 100% |
| 2 | Application build | Full lifecycle, RBAC, Project Incidents, Response Teams, dashboards, ingest | ✅ ~95% |
| 3 | Automated testing | 837 tests green; CI + 85% coverage floor | ✅ 95% |
| 4 | Documentation | Handover (EN+TH), user guides, ADRs, runbooks | 🟢 85% |
| 5 | Reporting / analytics | `mart` schema built; Grafana still reads the Indexer directly | 🟡 60% |
| 6 | **UAT** | 1 of 7 roles started; no exit criteria or sign-off defined | 🔴 15% |
| 7 | **Production build** | Windows/Waitress/IIS runbook current; TLS/cutover remains | 🟡 70% |
| 8 | **Backup & DR** | Backups + off-host pull + restore drill + **streaming standby live (5433)**, monitored; app stack pre-staged on spare | 🟢 90% |
| 9 | **Security hardening** | Settings sound; **TLS live (self-signed IP bridge; real cert pending)**, secure cookies on; no pre-prod review | 🟡 55% |
| 10 | **Go-live cutover** | Not planned | 🔴 0% |
| 11 | **Hypercare & maintenance** | Not planned | 🔴 0% |

**Overall: ~65% of total project effort.** Phases 6–11 are the finish line.

---

## 3. What is left, phase by phase

### Phase A — Close the engineering loose ends *(~3–5 focused days)*

These are the last things that genuinely need a keyboard and the codebase.

- [x] **Close the two historical audit findings.** The dashboard has an explicit
  org-wide role allowlist and fails closed for profile-less users; hot Ticket
  indexes landed in migration `0061`.
- [x] **Configure application logging.** Rotating file and console handlers are
  active outside tests.
- [x] **Add `/healthz`.** The endpoint checks application and database health.
- [x] **Set up CI.** GitHub Actions (`.github/workflows/ci.yml`) — Ruff correctness
  rules, migration-drift check, the full test suite, and an 85% coverage floor,
  against a Postgres 18 + Python 3.14 service container on every push and PR. *(Phase 7)*
- [x] **Fix broad ignore rules.** Markdown and JavaScript are tracked by default;
  sensitive security/UAT/internal-host documents remain explicitly local.
- [ ] **Branch hygiene.** `reduce_sys_workload` (55 commits behind, 0 ahead,
  untouched since 2026-07-09) can be deleted — confirm ownership/merge status first,
  and never as part of a behavior-preserving refactor.
- [ ] *(Optional, defer without guilt)* Project Incident dashboard rollup,
  consolidated per-Project report export, `GRAFANA_DASHBOARD.md`,
  `closed_at` backfill, OLA threshold tests.

**Exit criteria:** CI green on `main`; the approved refactor phases remain
behavior-preserving; deployment warnings close only with the TLS cutover.

---

### Phase B — Finish UAT *(~2–4 weeks elapsed, mostly other people's time)*

This is the longest-elapsed phase and the one you cannot compress by working
harder. Start it now, in parallel with Phase C.

- [ ] **Repair the UAT VM.** Per the UAT operations guide, `.env` was corrected to
  `ticketdata_uat` / `ticket_uat` and PostgreSQL then rejected the stored
  password. Recover the credentials, re-run the DB checks, repeat the browser
  test from a tester PC.
- [ ] **Put HTTPS on the UAT VM.** Testers are logging in with real passwords over
  port 80 today.
- [ ] **Run the remaining 6 roles.** Tier 1, Tier 2, System Admin, System Owner,
  Forensic Analyst, Red Team Manager. One real user per role, you role-play the
  adjacent ones. Log to the Notion tracker, not the app.
- [ ] **Write UAT exit criteria before you finish, not after.** Something like:
  *every role completes its scenario set; zero open Blockers; zero open Majors
  or each has a dated, agreed workaround.* Without a written bar, UAT never
  ends — it just goes quiet.
- [ ] **Triage every feedback row** to `Fix now` / `Fix later` / `Won't fix` /
  `Retrain` / `Needs decision`.
- [ ] **Fix the `Fix now` set**, re-test just those, then stop. Resist scope creep
  here; `Fix later` items are your first maintenance sprint, not a go-live gate.
- [ ] **Get a written sign-off** from whoever owns the SOC. One page, dated, naming
  what was tested and what was accepted with known gaps. This is the artifact
  that ends the build project.

**Exit criteria:** all 7 roles tested, exit criteria met, sign-off in hand.

---

### Phase C — Build production *(~4–6 focused days)*

Run this in parallel with Phase B. Critically: **the repo's deployment docs
describe the wrong platform.** `docs/operations/production-deployment.md`,
`docker-compose.prod.yml`, `nginx.conf`, and `scripts/backup/*.sh` all assume
Linux + Docker + gunicorn + nginx. Your real target is **Windows Server + native
PostgreSQL + Waitress + IIS**, which today is documented only inside the
generated UAT `.docx`.

- [ ] **Write `docs/operations/production-deployment.windows.md`** — the real
  runbook: Python + venv, PostgreSQL install and tuning, Waitress as a Windows
  service, IIS + ARR/URL Rewrite reverse proxy, static files, `.env` layout,
  restart/rollback procedure. Mark the Docker doc as superseded (do not delete
  it; a future Linux move may want it).
- [ ] **Set PostgreSQL's Phase 0 settings at install time** — `wal_level`,
  `listen_addresses`, `max_wal_senders`, `max_slot_wal_keep_size`, TLS for
  replication. These need a restart; setting them now saves a maintenance
  window later. See §Phase 0 of the Windows backup handbook.
- [x] **HTTPS on production** — *live as of 2026-08-26 via a **self-signed IP bridge**
  (`https://10.1.220.118`)*: 443 bound, redirect works (no loop), secure cookies on,
  app SMTP sending. Deferred to real-cert cutover: the **CA/PKI cert + DNS record**
  (clears the browser warning, unlocks HSTS, needed for a wider cross-VLAN audience)
  and a **documented certificate renewal owner and date**. See deployment runbook
  Stage 13 (as-built) and the two Stage 9.3 gaps (`allowedServerVariables` unlock,
  Waitress `--trusted-proxy`).
- [x] **Harden the deployment env**: `DEBUG=False`, real `SECRET_KEY`, correct
  `ALLOWED_HOSTS`, and `SESSION_COOKIE_SECURE` / `CSRF_COOKIE_SECURE` /
  `SECURE_SSL_REDIRECT` on. `SECURE_HSTS_SECONDS` intentionally **0** on the
  self-signed bridge — ramp it at real-cert cutover.
- [ ] **Run `manage.py check --deploy`** and clear every warning you do not
  consciously accept.
- [ ] **A pre-production security pass** on the app itself — file upload handling,
  the permission matrix per role, password policy, admin exposure.
- [ ] **Smoke-test under a realistic load** — the queues and dashboards do a lot of
  per-row OLA computation. This is also what makes the L2 index decision concrete.

**Exit criteria:** production reachable over HTTPS, `check --deploy` clean,
Windows runbook written and followed end to end by you once.

---

### Phase D — Backup & DR *(~3–4 focused days)*

**Nothing is backing up anything today.** Until Phase 1 of the handbook is done,
one bad migration is unrecoverable. Do this *before* real data exists — you can
still test destructively.

Follow `docs/operations/backup-and-standby-handbook.windows.md` in order:

- [x] **Phase 1 — backups on production.** GnuPG keypair (generated on the *spare*
  VM, public key only on prod), backup service account, `New-SocBackup.ps1`,
  scheduled tiers. *(Done — nightly encrypted archives.)*
- [x] **Phase 2 — off-host pull to the spare VM.** Read-only SMB share, pull
  account, `Copy-SocArchive.ps1` + `Test-SocArchive.ps1` + `Remove-SocArchive.ps1`
  scheduled. *(Done — hourly pull, SHA-256 verified, quarantine empty.)*
- [x] **Run a real restore drill** against the separate verify instance (port 5434)
  and time it. *(Done — 2026-08-24. Drill decrypts, checksums, restores into a
  throwaway DB built `TEMPLATE template0` with the production locale asserted
  (`UTF8 / Thai_Thailand.874 / libc`) and read back, and asserts row counts vs the
  manifest. Counts matched; `restore-verify: backup is restorable`. Scheduled
  weekly as `SOC-Restore-Drill`; daily `SOC-Archive-Check`; weekly
  `SOC-Archive-Prune` — all verified `LastTaskResult 0`. Credential-break test:
  pull returns non-zero when creds are broken, `0` when restored.)*
- [x] **Phase 3 (handbook) — streaming standby** (port 5433). *(Done — 2026-08-25.
  Prod `wal_level=replica` + SSL + `max_slot_wal_keep_size=10GB`, `replicator` role
  over `hostssl` scoped to the spare; standby `postgresql-standby` on the spare
  streams continuously, `-S auto`. Verified: data propagation, reboot survival,
  daily `SOC-Archive-Check -CheckStandby` green. App stack pre-staged on the spare
  (§2.8) — Python 3.14.7, venv, IIS/ARR, `SOCTicketWaitress` Manual/stopped,
  placeholder `.env`. Promotion/failover NOT yet rehearsed — see below.)*
- [ ] **Planned failover rehearsal** — promote the standby, repoint the pre-staged
  app, log in, then rebuild the standby. This is the first test of the roles/grants
  gap the restore drill cannot reach. Quarterly once live.
- [ ] **Store the GPG private key offline** and **test the offline copy on a third
  machine.** Lose it and every archive is scrap; an untested copy is not a copy.
- [ ] **Ask infrastructure whether both VMs share a hypervisor or SAN** — and write
  the answer down. If they do, this is a warm tier, not real DR, and the CISO
  should know that.
- [x] **Commit the backup scripts.** `scripts/backup/windows/*.ps1` are tracked.

**Exit criteria:** ~~a restore drill completed and timed~~ ✅; freshness check
proven to detect a failure ✅, and the email half is now **live** — Phase 5 Track A
wired `SOC-Archive-Check` to alert `ntsoc@ntplc.co.th` over the authenticated
`mail.ntplc.co.th` relay, so a stale archive / broken pull / full disk /
non-streaming standby emails the SOC team (the manual-weekly-owner stopgap is
retired); **RPO ≈ 24 h** (nightly daily
tier) written down; **RTO** = data-restore proven in seconds, end-to-end service
RTO pending the annual full recovery rehearsal (restore + recreate roles/grants +
repoint Django + log in).

---

### Phase E — Cutover to live *(~1–2 days, plus a chosen date)*

- [ ] **Clean the production database.** `seed_all` purges legacy `uat_*` /
  `seed_*` / `mock` accounts — but verify by hand that no seed tickets, no
  `[UAT-STATE]` fixtures, and no test accounts (`sysowner1`, anything in
  `test_accounts.txt`) survive into prod.
- [ ] **Create the real user accounts** and rotate every dev/UAT password. Several
  are written down in your notes and in `test_accounts.txt` — treat all of them
  as compromised.
- [x] **Point the Wazuh ingest at production** — *done 2026-08-26.* `SOC-Ingest-Wazuh`
  runs per-minute (SYSTEM, IgnoreNew) against Indexer `10.1.220.32:9200`; first pull
  4,532 alerts, watermark advancing. **Interim:** `OPENSEARCH_VERIFY_SSL=False`
  (encrypted, unauthenticated) until the Wazuh admin sends `root-ca.pem` → CA bundle.
- [x] **Schedule `refresh_reporting` nightly** — *done 2026-08-26.* `SOC-Refresh-Reporting`
  at 00:20 (per-minute ingest guarantees ingest-before-refresh). Detection capture live
  (`detection_rows: 31`). Retention scheduled too: `SOC-Purge-Wazuh` daily 04:00, 90-day
  window (confirm with compliance within the runway). CSV historical import deferred by
  the owner (idempotent, run any time).
- [ ] **Reporting Phase 4** — create the `reporting_ro` role
  (`docs/operations/reporting-ro-setup.sql`) and repoint Grafana at `mart`
  instead of the Indexer.
- [ ] **Reporting Phase 5** — retire the superseded `socdata` prototype, salvaging
  `dashboard_views.sql`.
- [ ] **Train the users.** The Thai end-user guide and feature guide exist; book
  the session and record who attended.
- [ ] **Agree a go-live date and a rollback trigger** — the specific condition under
  which you revert to the manual process. Decide it while calm. The *technical*
  deploy/rollback mechanics are now written up:
  [deploy-and-release.windows.md](operations/deploy-and-release.windows.md)
  (cut a SemVer tag after CI is green → deploy → verify → roll back). *(Phase 7)*

**Exit criteria:** real tickets flowing, dashboards populated from `mart`,
backups running against live data.

---

### Phase F — Hypercare, then maintenance *(ongoing)*

**Hypercare — the first 2–4 weeks after go-live.** Elevated attention, a daily
15-minute check, a named person users can reach, fast turnaround on anything
that blocks work. Most systems that fail, fail here — not because they are
broken but because the first frustration goes unanswered and people quietly
return to email.

**Steady-state maintenance — the routine, once hypercare ends:**

| Cadence | Task |
|---|---|
| Daily | Backup job succeeded; ingest watermark advancing; `refresh_reporting` ran |
| Weekly | Review OLA breaches and stuck tickets; skim error logs |
| Monthly | Restore drill; Django + dependency security updates; disk headroom on both VMs |
| Quarterly | Failover rehearsal (promote the standby); review roles and accounts; revisit the deferred backlog |
| Annually | Certificate renewal; GPG key review; re-read the handover doc and fix what has drifted |

**Also plan for:**
- [ ] **A named owner other than you.** Right now the system has a bus factor of
  one. The handover doc exists — walk someone through it while you are still
  around to answer questions.
- [ ] **An intake path for change requests** so "can it also do X" becomes a triaged
  backlog, not a series of interruptions.
- [ ] **Django upgrade cadence.** You are on 6.0.7; decide now whether you track
  LTS or latest, and put the next review in a calendar.

---

## 4. Critical path — what to do in what order

Two tracks run in parallel. The left one is yours; the right one is other
people's calendars, so start it first.

```
Week 1   │ A: logging + /healthz + CI + gitignore fix   │ B: fix UAT VM creds, add HTTPS
Week 2   │ A: decide L1/L2, land index migration        │ B: UAT roles 2–4
Week 3   │ C: write Windows prod runbook, build prod    │ B: UAT roles 5–7
Week 4   │ C: HTTPS + hardening + check --deploy        │ B: triage feedback, fix "Fix now"
Week 5   │ D: backup Phases 1–2 + restore drill         │ B: sign-off
Week 6   │ D: Phase 3 standby + drill                   │
Week 7   │ E: cutover                                   │
Week 8+  │ F: hypercare                                 │
```

**Roughly 6–8 weeks to go-live** if UAT scheduling cooperates, of which maybe
**12–15 days is your own hands-on work**. UAT elapsed time and the go-live date
decision are what actually set the length.

**The three things that will hurt if left late:**
1. **No backups on a live system.** Phase D before Phase E, without exception.
2. **Detection history evaporating** at the Indexer's ~3-month retention.
3. **UAT starting late** — it is the one thing you cannot do faster by working
   harder.

---

## 5. What "finished" means

The build project ends when all of these are true:

- [ ] UAT signed off in writing, no open Blockers
- [ ] Production live over HTTPS, `check --deploy` clean
- [ ] A restore drill completed and timed; RPO/RTO written down
- [ ] Reporting refresh scheduled; dashboards fed from `mart`
- [ ] Users trained; the Thai guides match what shipped
- [ ] Handover doc walked through with a second person
- [ ] Hypercare period completed without a Blocker

After that the project is over and the **system** begins — and the table in
Phase F is the whole job.

---

## 6. Related

- [../PROJECT_STATUS.md](../PROJECT_STATUS.md) — this week's lanes and blockers
- [operations/backup-and-standby-handbook.windows.md](operations/backup-and-standby-handbook.windows.md) — the Phase D build book
- [operations/reporting-layer-operations.md](operations/reporting-layer-operations.md) — §3 is the reporting cutover checklist
- [uat/uat-test-scenarios.md](uat/uat-test-scenarios.md) · [uat/uat-feedback-log.md](uat/uat-feedback-log.md) — Phase B material
- [handover/engineering-handover.md](handover/engineering-handover.md) — the Phase F bus-factor insurance
