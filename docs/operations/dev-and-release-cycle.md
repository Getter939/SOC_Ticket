# Dev & Release Cycle — how to keep evolving this system without drowning

> **Audience:** you (and whoever helps or takes over) · **Status:** Current
> **Companion to:** [deploy-and-release.windows.md](deploy-and-release.windows.md) (the *how* of a deploy). This doc is the *when* and *why* — the loop the deploy runbook sits inside.

## Read this first

A production system is **never "finished."** The goal is not to finish it — it's to make changing it **cheap, boring, and predictable**, so a stream of coworker requests becomes a calm queue instead of a pile of interruptions. That is the whole point of a cycle: you decide *how* you work **once**, write it here, and then just follow it. No re-deciding under pressure.

One mental model carries everything:

> **Branches are for authoring. Tags are for releasing. Environments run tags.**

Your three machines are not three branches — they are three **stages that run the same code at different maturity**:

| Environment | Runs | For |
|---|---|---|
| **Dev** (your PC) | a feature branch working tree | writing + fast local testing |
| **UAT VM** | a release *candidate* tag (`vX.Y.0-rc.N`) | coworkers accept/reject against criteria |
| **Production VM** | the blessed release tag (`vX.Y.0`) | live, after UAT sign-off |

The **code is identical** across all three. Only `.env` differs (DB, secrets, `SITE_URL`, `DEBUG`). Never branch per environment.

---

## The operating rhythm — what to do, and when (start here)

Default to a **2-week release train**. Copy this calendar and just follow it; tune the interval later if two weeks feels too tight or too slow.

### The 2-week train, day by day

**Week 1 — Build**
- **Mon (~30 min) — Plan the train.** Open the backlog, pick the top items that realistically fit two weeks, put them in this train's Milestone (`v1.X.0`). That set is the plan; everything else waits.
- **Tue–Fri — Build.** One item at a time: `feat/…` branch off `main` → code **+ test** → PR → CI green → merge → delete the branch. Repeat.

**Week 2 — Stabilise & ship**
- **Mon — Cut the candidate.** Tag `v1.X.0-rc.1`, deploy it to **UAT**, and send coworkers the item list + how to test each (the acceptance criteria).
- **Tue–Wed — UAT.** They test. A bug → fix on `main` → tag `-rc.2` → redeploy UAT. Repeat until it holds.
- **Thu — Sign-off + tag the release.** Cutoff for changes. Once signed off, tag `v1.X.0` on the **exact commit UAT approved**.
- **Thu/Fri (your window) — Deploy to PROD.** Follow [deploy-and-release.windows.md](deploy-and-release.windows.md): backup → checkout tag → migrate/collectstatic → restart → verify `/healthz` → set `APP_VERSION` → bring the spare to the same tag. Watch the rest of the day.
- **Fri — Close out.** Write the deploy-log line; groom the backlog for the next train.

Next Monday it starts again. Requests that arrived mid-train simply ride the next one.

### Every day (~10 min)

Triage new requests into the backlog — each gets **acceptance criteria** + a **severity**. That's the whole obligation. You do **not** act on them now. "Added to the backlog" is a complete answer.

### "What do I do right now?" — quick reference

| Situation | Do this |
|---|---|
| A coworker asks for a change | Add to backlog (criteria + severity). Say "added." Don't touch the running train. |
| It's Monday, Week 1 | Plan the train: pick scope → Milestone. |
| An item's code is ready | `feat/…` branch → PR → CI green → merge → delete branch. |
| All train items merged & green | Tag `-rc.1` → deploy UAT → send the test list. |
| UAT finds a bug | Fix on `main` → `-rc.N` → redeploy UAT. |
| UAT signed off | Tag the release → PROD deploy via runbook → watch. |
| PROD is broken **now** | Hotfix: `fix/…` off the released tag → PR/CI → `vX.Y.1` → deploy (backup first). Jump the queue. |
| Unsure a request is worth doing | Leave it in the backlog. Decide at planning. Nice-to-haves can wait forever. |
| Mid-train, tempted to "just push a quick fix to PROD" | Don't. Unless PROD is broken, it rides the train. |

### If you only remember three things

1. **Requests go to the backlog; releases go out on the train** — never deploy PROD on demand.
2. **One `main`, short branches, ship a tag** — the tag is what moves Dev → UAT → PROD, unchanged.
3. **Back up before every PROD deploy** — that backup is the whole rollback plan.

---

## 1. Branching — trunk-based, no "dev/prod" branches

- **`main` is the only long-lived branch.** It is always green (CI passes) and always releasable.
- Every change is a **short-lived feature branch** off `main`: `feat/ola-report`, `fix/dashboard-rollup`, `chore/bump-deps`. Live hours-to-days, merge back via PR, then **delete**.
- **Do NOT keep a separate "dev" or "prod" branch.** That model (old Gitflow) is what let this repo's lanes drift apart into two CI files and contradictory docs. One trunk + short branches + frequent integration prevents it.
- Which environment is running what is told by the **tag it has checked out** (`/healthz` reports `APP_VERSION`), never by a branch.

**Golden rule:** integrate `main` into your feature branch often (at least before opening the PR). The longer a branch lives away from `main`, the worse the merge.

---

## 2. The release train — your defense against firefighting

Do **not** deploy to PROD every time a coworker asks for something. Instead, run a **release train** on a fixed cadence:

- Pick an interval that fits your load — **every 2 weeks** is a good default for a live internal tool.
- Requests accumulate in the **backlog** (your Notion *Features & Backlog* DB). They do **not** interrupt you.
- Each train = one **MINOR release** (`v1.2.0`, `v1.3.0`, …) carrying whatever was ready in time. Not ready? It rides the next train. No drama.
- Only **true emergencies** (PROD is broken / security) jump the queue as a **hotfix PATCH** (§6).

This single habit converts "endless coworker requests" into "a predictable list I ship on a schedule." It is the biggest lever you have.

---

## 3. Requirements — gather continuously, commit to a version deliberately

- **Intake (anytime):** every request → one backlog item with **acceptance criteria** ("done" = what a UAT tester can verify) and a **severity** (blocker / normal / nice-to-have).
- **Say "added to the backlog," not "yes."** Committing to a *when* happens at train-planning, not at the coffee machine.
- **Plan a train:** at the start of each cycle, pull the top items that fit the interval into the version's scope (a Notion view or a GitHub Milestone). That set is the release's contract.
- Keep releases **small and frequent** — small releases are low-risk and easy to roll back.

---

## 4. The loop (one full turn)

```
intake → plan the train → build on Dev → PR + CI → merge to main
  → tag rc → deploy rc to UAT → coworkers test → (bug? fix on main → new rc)
  → sign-off → tag release → deploy same commit to PROD → watch
```

1. **Build on Dev.** Feature branch per item. Write code **and tests**. Run locally:
   ```bash
   ruff check .
   python manage.py makemigrations --check
   python manage.py migrate
   python manage.py test
   ```
2. **PR → CI → merge.** Open a PR to `main`. CI (`.github/workflows/ci.yml`) runs Ruff + migration check + full tests + 85% coverage on Postgres 18. Merge only when green (even self-review: re-read your own diff). Delete the branch.
3. **Cut a candidate.** When the train's items are all on `main` and green:
   ```bash
   git checkout main && git pull
   git tag -a v1.2.0-rc.1 -m "v1.2.0 candidate 1"
   git push origin v1.2.0-rc.1
   ```
   Deploy that tag to **UAT** via the deploy runbook (same steps as PROD — so UAT also rehearses the deploy).
4. **UAT.** Coworkers test against the acceptance criteria on the UAT VM. A bug → fix on `main` → tag `-rc.2` → redeploy UAT. Repeat until **sign-off**.
5. **Release to PROD.** Promote the **exact commit that passed UAT** — do not rebuild or re-merge:
   ```bash
   git tag -a v1.2.0 <that-commit> -m "Release v1.2.0"
   git push origin v1.2.0
   ```
   Deploy `v1.2.0` to PROD via [deploy-and-release.windows.md](deploy-and-release.windows.md): **backup first** → checkout tag → pip/migrate/collectstatic → restart → verify `/healthz` → set `APP_VERSION` → bring the **spare** to the same tag.
6. **Watch.** Check `/healthz`, the backup alert email, and the triage queue for a day. A real problem → hotfix (§6).

---

## 5. When each machine gets updated

| Machine | Updated | With |
|---|---|---|
| **Dev** | continuously | your working branch |
| **UAT** | once per train (and per `-rc.N` fix) | the candidate tag |
| **PROD** | only after UAT sign-off, in a chosen window | the release tag |

---

## 6. Hotfix path (PROD is broken now)

1. Branch `fix/...` off the **released tag** (not off `main` if `main` has unreleased work): `git checkout -b fix/x v1.2.0`.
2. Smallest possible fix + a test that reproduces the bug. PR → CI → merge to `main`.
3. Tag `v1.2.1` on that commit; deploy to PROD (backup first, always). Fast-track UAT or skip only for a genuine emergency — and say so in the deploy log.
4. Make sure the fix is on `main` so the next train keeps it.

---

## 7. Environments & config

- **One code artifact, per-environment `.env`.** `.env` is gitignored and lives on each box. Dev/UAT/PROD differ only there (DB host/port, `SECRET_KEY`, `SITE_URL`, `DEBUG`, OpenSearch creds).
- UAT must point at a **separate UAT database** — never the production DB.
- Secrets never go in git or in these docs — only paths and role names (as in the As-Built).

---

## 8. Not alone forever — lowering the bus factor

This system currently has a **bus factor of one** (you). That is the real source of "stuck forever." Concrete ways out, cheapest first:

1. **Everything is written down** (you already do this). The runbooks + As-Built + this cycle doc mean the system is transferable, not trapped in your head.
2. **Train one backup operator.** One coworker who can run the deploy runbook and the restore drill. Have them do the next UAT deploy *with you watching*. Now you can take leave.
3. **Publish the cadence to your team and manager.** "Requests go in the backlog; a release ships every 2 weeks; emergencies are the exception." This sets expectations and stops on-demand pressure — and makes the case that a second person is needed.
4. **Guard scope.** Not every request is worth doing. "Added to the backlog, we'll prioritise at the next planning" is a complete, professional answer. Nice-to-haves can wait forever without harm.
5. **Automate the boring parts** so maintenance shrinks: CI already gates quality; the backup/standby/alert tasks already run unattended. Keep pushing repeatable work into scheduled tasks, not your calendar.

**"Getting over" this project = reaching steady state:** requests queue, a train ships them on a schedule, a second person can cover you, and nothing needs heroics. That is a finish line you can actually reach — and you are most of the way there.

---

## 9. Copy-paste checklists

**Per change**
- [ ] Short-lived branch off current `main`
- [ ] Code + test written; `ruff` / `makemigrations --check` / `test` pass locally
- [ ] PR opened; CI green; diff self-reviewed
- [ ] Merged to `main`; branch deleted

**Per release train**
- [ ] Scope chosen from backlog (a Milestone/Notion view)
- [ ] All items merged to `main`, CI green
- [ ] `-rc.N` tag cut and deployed to UAT
- [ ] Acceptance criteria tested; sign-off recorded
- [ ] Release tag cut on the signed-off commit
- [ ] PROD deploy per runbook (backup → verify → `APP_VERSION` → spare)
- [ ] Deploy-log line written; watch for a day
