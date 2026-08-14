# SOC Ticket — Progression & Road to Go-Live

> **Audience:** you (project owner) · **Status:** Current · **Last updated:** 2026-07-27
> **Companion to:** [../PROJECT_STATUS.md](../PROJECT_STATUS.md) (this week's lanes) — this file is the *whole* arc

The short answer to "how far am I?": **the software is essentially finished; the
delivery is not.** You are roughly **two-thirds through the project**, and the
remaining third is almost entirely non-coding work — acceptance testing,
production build, cutover, and the first month of running it. That is normal.
It is also the part that most solo-built systems never finish, so it is worth
naming the pieces explicitly.

---

## 1. Where you actually are — evidence, not vibes

Verified against the repo on 2026-07-27:

| Signal | Reading |
|---|---|
| Test suite | **537 tests, all passing** (`manage.py test`) |
| Application code | ~23,000 lines across 5 Django apps, 33 templates |
| Lifecycle | 13-state FSM, 7 roles, transitions enforced in the model |
| Feature backlog | Core workflow **complete**; 4 deferred nice-to-haves remain |
| Reporting layer | Phases 1–3 built; 4–5 pending; nightly refresh **not scheduled** |
| Docs | 25+ documents incl. Thai user guides, ADRs, handover, runbooks |
| CI | **None** — no `.github/`, nothing runs those 537 tests but you |
| App logging | **None configured** — no `LOGGING` block in `config/settings.py` |
| Production | **Does not exist yet.** Nothing is backing anything up |
| UAT | 1 of 7 roles in progress (SOC Manager); 6 unstarted |

The gap between "537 green tests" and "no production server" is the whole
remaining project.

---

## 2. The phase map

Standard software-delivery phases, scored against this project.

| # | Phase | State | Done |
|---|---|---|---|
| 1 | Requirements & domain design | Glossary, ADRs, state machine, change log all written | ✅ 100% |
| 2 | Application build | Full lifecycle, RBAC, Project Incidents, Response Teams, dashboards, ingest | ✅ ~95% |
| 3 | Automated testing | 537 tests green — but no CI, no coverage gate | 🟢 80% |
| 4 | Documentation | Handover (EN+TH), user guides, ADRs, runbooks | 🟢 85% |
| 5 | Reporting / analytics | `mart` schema built; Grafana still reads the Indexer directly | 🟡 60% |
| 6 | **UAT** | 1 of 7 roles started; no exit criteria or sign-off defined | 🔴 15% |
| 7 | **Production build** | Nothing provisioned. Deployment docs target the wrong OS | 🔴 5% |
| 8 | **Backup & DR** | Handbook + scripts written; **zero phases executed** | 🔴 10% |
| 9 | **Security hardening** | Settings are sound; no TLS, no logging, no pre-prod review | 🟡 40% |
| 10 | **Go-live cutover** | Not planned | 🔴 0% |
| 11 | **Hypercare & maintenance** | Not planned | 🔴 0% |

**Overall: ~65% of total project effort.** Phases 6–11 are the finish line.

---

## 3. What is left, phase by phase

### Phase A — Close the engineering loose ends *(~3–5 focused days)*

These are the last things that genuinely need a keyboard and the codebase.

- [ ] **Decide the two open audit findings.** Both are blocked on you, not on code:
  - **L1** — `apps/dashboard/views.py` `dashboard()` uses `Ticket.objects.all()`, so
    Executive and profile-less users fall through to the full SOC dashboard.
    Is that intended? It is a permission-model decision.
  - **L2** — add indexes on `Ticket.status` / `severity` / `ola_contain_deadline` /
    `created_at`. Migration is written up; needs sign-off.
- [ ] **Add a `LOGGING` config.** Right now a production exception goes nowhere you
  can read. Minimum: rotating file handler for `django` + your apps, WARNING and
  above, written somewhere the backup job already captures.
- [ ] **Add a health endpoint** (`/healthz` returning DB-reachable + version). IIS,
  your monitoring, and the standby failover runbook all want one.
- [ ] **Set up CI** (GitHub Actions on `Getter939/SOC_Ticket`): run the 537 tests +
  `manage.py check --deploy` on every push. Without this, the suite decays the
  moment you stop running it by hand.
- [ ] **Fix the docs gitignore.** `.gitignore:62` is a blanket `*.md` — most of
  `docs/` is untracked. If your laptop dies, the handover disappears. Un-ignore
  `docs/` and `*.md` at the repo root, keep ignoring scratch dirs.
- [ ] **Branch hygiene.** `reduce_sys_workload` is 55 commits behind, 0 ahead,
  untouched since 2026-07-09 — delete it.
- [ ] *(Optional, defer without guilt)* Project Incident dashboard rollup,
  consolidated per-Project report export, `GRAFANA_DASHBOARD.md`,
  `closed_at` backfill, OLA threshold tests.

**Exit criteria:** CI green on `main`; L1/L2 decided and landed; logging and
`/healthz` in place.

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
- [ ] **HTTPS on production**, with a documented certificate renewal owner and date.
- [ ] **Harden the deployment env**: `DEBUG=False`, real `SECRET_KEY`, correct
  `ALLOWED_HOSTS`, and turn on `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`,
  `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`. All of these already exist as
  env-driven settings and all default to off.
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

- [ ] **Phase 1 — backups on production.** GnuPG keypair (generated on the *spare*
  VM, public key only on prod), backup service account, `New-SocBackup.ps1`,
  scheduled tiers.
- [ ] **Phase 2 — off-host pull to the spare VM.** Read-only SMB share, pull
  account, `Copy-SocArchive.ps1` + `Test-SocArchive.ps1` + `Remove-SocArchive.ps1`
  scheduled, the alert wired to something you actually read.
- [ ] **Run a real restore drill** against the separate verify instance (port 5434)
  and time it. An untested backup is not a backup.
- [ ] **Phase 3 — streaming standby** (port 5433), promoted manually.
- [ ] **Store the GPG private key offline.** Lose it and every archive is scrap.
- [ ] **Ask infrastructure whether both VMs share a hypervisor or SAN** — and write
  the answer down. If they do, this is a warm tier, not real DR, and the CISO
  should know that.
- [ ] **Commit the backup scripts.** `scripts/backup/windows/*.ps1`,
  `check_freshness.sh`, `prune_archive.sh`, `pull_archives.sh`, and
  `docker-compose.backupvm.yml` are currently untracked.

**Exit criteria:** a restore drill completed and timed; freshness alert proven to
fire; RPO/RTO written down and agreed.

---

### Phase E — Cutover to live *(~1–2 days, plus a chosen date)*

- [ ] **Clean the production database.** `seed_all` purges legacy `uat_*` /
  `seed_*` / `mock` accounts — but verify by hand that no seed tickets, no
  `[UAT-STATE]` fixtures, and no test accounts (`sysowner1`, anything in
  `test_accounts.txt`) survive into prod.
- [ ] **Create the real user accounts** and rotate every dev/UAT password. Several
  are written down in your notes and in `test_accounts.txt` — treat all of them
  as compromised.
- [ ] **Point the Wazuh ingest at production** and confirm the watermark starts
  clean.
- [ ] **Schedule `refresh_reporting` nightly** — ingest first, then refresh. History
  only starts accruing from the day you schedule it, and snapshot metrics are
  *unrecoverable* if a day is missed.
  - ⚠️ **Time-sensitive:** detection capture reads the Wazuh Indexer, whose
    retention is ~3 months. If go-live is further out than that, start detection
    capture *now* against production-adjacent data or you permanently lose that
    window of history.
- [ ] **Reporting Phase 4** — create the `reporting_ro` role
  (`docs/operations/reporting-ro-setup.sql`) and repoint Grafana at `mart`
  instead of the Indexer.
- [ ] **Reporting Phase 5** — retire the superseded `socdata` prototype, salvaging
  `dashboard_views.sql`.
- [ ] **Train the users.** The Thai end-user guide and feature guide exist; book
  the session and record who attended.
- [ ] **Agree a go-live date and a rollback trigger** — the specific condition under
  which you revert to the manual process. Decide it while calm.

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
