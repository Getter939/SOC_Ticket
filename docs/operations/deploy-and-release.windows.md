# Deploy & Release — Windows production

> **Audience:** deployers, operators · **Status:** Current · **Last updated:** 2026-08-28

How to cut a release, deploy it to the Windows production VM, verify it, and roll
it back. This is the **repeatable** counterpart to
[production-deployment.windows.md](production-deployment.windows.md), which is the
**one-time** build of a fresh box. Once the box exists, every subsequent code
change follows this document.

The deploy model is a **git checkout on the PROD VM**: `C:\SOCTicket\app` is a
working tree, and a release is a specific annotated **tag** checked out there. CI
([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)) gates what may
become a tag; this runbook governs how a tag reaches production and how to back
out.

---

## 1. Versioning — Semantic Versioning on annotated tags

Releases are `vMAJOR.MINOR.PATCH` annotated git tags on `main`:

| Bump | When |
|---|---|
| **MAJOR** | A breaking change — a destructive/irreversible migration, a config key rename operators must act on, an incompatible API/URL change. |
| **MINOR** | A backward-compatible feature (new app, new command, new field with a default). |
| **PATCH** | A backward-compatible fix (bug fix, doc-only, dependency pin bump). |

Baseline: **`v1.0.0`** was the first production build. Phases 5–6 (HTTPS bridge,
authenticated SMTP, Wazuh ingestion, reporting mart, retention) are the first
feature release on top of it → **`v1.1.0`**.

The deployed tag is written into the PROD `.env` as `APP_VERSION` (§3, step 8) so
`/healthz` reports exactly which release is running.

---

## 2. Cut a release (on a workstation, not the VM)

Only tag a commit that CI has proven green.

```bash
git checkout main
git pull
# Confirm CI is green for this exact commit on GitHub (the "CI" check).
git tag -a v1.1.0 -m "Phase 5-6: HTTPS bridge, SMTP, Wazuh ingest, reporting mart, retention"
git push origin v1.1.0
```

An **annotated** tag (`-a`) — not a lightweight one — so `git describe` on the VM
resolves to the release name and the tag carries its own message and date.

Never tag a commit that only passed locally. CI runs `makemigrations --check`,
`migrate`, `manage.py check`, and the full test suite on a clean runner; a green
tag is the contract this runbook depends on.

---

## 3. Deploy to production

Run on the PROD VM in an elevated PowerShell. **One step at a time — never assume
a step succeeded; read its output before the next.**

```powershell
Set-Location C:\SOCTicket\app
$py = 'C:\SOCTicket\app\venv\Scripts\python.exe'
```

**Step 1 — Back up first (non-negotiable).** A deploy can run a migration that
changes data; the pre-deploy backup is the only rollback path for that case (§4).
```powershell
.\scripts\backup\windows\New-SocBackup.ps1 -Tier manual -GpgRecipient soc-backup@nt.local
# expect: a .zip.gpg + .sha256, no leftover .zip. Confirm the file exists and is non-zero.
```

**Step 2 — Fetch the release tag.**
```powershell
git fetch --tags
git checkout v1.1.0        # detached HEAD at the tag — expected, not an error
git describe --tags        # must print v1.1.0
```

**Step 3 — Sync dependencies.** Skipping this is how a new import 500s only in
production.
```powershell
& $py -m pip install -r requirements.txt
```

**Step 4 — Apply migrations.**
```powershell
& $py manage.py migrate
# read the output: note every migration applied — you need this list for rollback (§4).
```

**Step 5 — Collect static.** **Not optional** — with `DEBUG=False`, WhiteNoise
serves from `STATIC_ROOT`; skip it and every page renders unstyled.
```powershell
& $py manage.py collectstatic --noinput
```

**Step 6 — Restart the app service.** Drops pooled DB connections and loads the
new code.
```powershell
Restart-Service SOCTicketWaitress
```

**Step 7 — Verify (prove it, from the box and from a third host).**
```powershell
# App up + DB reachable + running version, direct to Waitress:
curl.exe -s -H "X-Forwarded-Proto: https" http://127.0.0.1:8000/healthz
#   want: {"status":"ok","database":"ok","version":"v1.1.0"}  (200)
& $py manage.py check --deploy   # W004/HSTS by design on the HTTP-proxy bridge; no NEW warnings
```
- From a **third host**: `curl.exe -k https://10.1.220.118/healthz` → **200** with
  the new `version`, not a 301 loop (redirect regressions hide from a localhost test).
- Log in through the browser (smoke: dashboard renders styled, a ticket opens).
- Confirm live data still flows: the `SOC-Ingest-Wazuh` task's next run is
  `LastTaskResult 0` and new alerts appear in the triage queue.

**Step 8 — Record the release.** Set `APP_VERSION` in the PROD `.env` to the tag
so `/healthz` reports it (edit in a plain text editor — ASCII, **no BOM**; a BOM
turns the first key into `\ufeffSECRET_KEY` and Django won't start), then
`Restart-Service SOCTicketWaitress` and re-check `/healthz`. Append one line to
the deploy log (§6).

**Step 9 — Keep the spare in step.** Update the pre-staged checkout on the spare
VM to the **same tag** (handbook §2.8) — `git fetch --tags; git checkout v1.1.0;
pip install -r requirements.txt; collectstatic`, service left **stopped**. A stale
pre-staged stack that won't start is discovered during the incident, which is the
worst time. See
[backup-and-standby-handbook.windows.md](backup-and-standby-handbook.windows.md).

---

## 4. Roll back

Decide by **what the bad deploy changed**. The migration list from Step 4 is the
deciding input.

### 4a. Code-only, or only reversible migrations → check out the previous tag
Most releases. A migration is reversible if its operation has a reverse — the
reporting layer is the model case: every object is `RunSQL(..., reverse_sql=...)`,
so `migrate reporting zero` (or `migrate reporting <prev>`) cleanly drops what it
made, and a plain field-add reverses by dropping the column.
```powershell
Set-Location C:\SOCTicket\app
$py = 'C:\SOCTicket\app\venv\Scripts\python.exe'
# If the bad release migrated forward, unapply those first, e.g.:
& $py manage.py migrate <app> <last_good_migration>   # only for reversible ones
git checkout v1.0.0                                    # the previous good tag
& $py -m pip install -r requirements.txt
& $py manage.py collectstatic --noinput
Restart-Service SOCTicketWaitress
# then Step 7 verify, and set APP_VERSION back to v1.0.0 (Step 8)
```

### 4b. A destructive/irreversible migration ran → restore the data from the pre-deploy backup
A `git checkout` of old code **cannot** undo a dropped column, a data-normalizing
rewrite, or a row deletion — the data is gone. Migrations of this kind in this
repo include column removals (e.g. `incidents/0024_remove_ticket_category`) and
in-place data conversions (e.g. `incidents/0018_convert_classification_and_status_values`,
`0021_unknown_severity_data`, `0026_normalize_issue_type_source_values`,
`0043_migrate_ticket_references`). This is a **logical failure** — exactly the case
the handbook's **§4.3 "Recovery from archives"** covers. Roll back the *data*, not
just the code:

1. `Stop-Service SOCTicketWaitress`.
2. Restore the **pre-deploy** backup (Step 1's `.zip.gpg`) into the real database
   with the handbook's restore script — verify its `.sha256` first, then:
   ```powershell
   .\scripts\backup\windows\Test-SocRestore.ps1 -ArchivePath <pre-deploy.zip.gpg> `
     -VerifyPort 5434 -RestoreDb ticketdata_prod -KeepRestoredDb `
     -PassphraseFile C:\ProgramData\SOCBackup\gpg-pass.txt
   ```
   The dump is `--no-owner --no-acl`, so if the restore recreates the database you
   must recreate the `ticket`/`soc_backup` roles and re-run
   [reporting-ro-setup.sql](reporting-ro-setup.sql) — follow handbook §4.3 steps 3/3a
   verbatim; do not improvise the role/grant recovery.
3. `git checkout v1.0.0`, `pip install -r requirements.txt`, `collectstatic --noinput`.
4. `Start-Service SOCTicketWaitress`, then Step 7 verify and reset `APP_VERSION`.

This is exactly why Step 1's backup is non-negotiable and why a release carrying
such a migration is a **MAJOR** bump (§1) — it flags to the deployer, before the
deploy, that plain-tag rollback is off the table.

> **When unsure which case you're in, treat it as 4b.** Restoring a fresh backup
> is always safe; assuming a migration was reversible when it wasn't is not.

---

## 5. Rollback rehearsal (no PROD change)

You can validate the mechanics without touching production:
- `git checkout v1.0.0` in a scratch clone still resolves and builds — the
  previous release is always recoverable.
- Read each pending migration's `reverse_sql` / operations before deploying; if
  any is `RunSQL` without `reverse_sql`, a column removal, or a data rewrite, plan
  for 4b **before** you deploy, not during the incident.

---

## 6. Deploy log

Keep an append-only line per deploy (a text file on the VM, or the ops Notion),
so `/healthz`'s `version` ties back to a known change:

```
2026-08-28  v1.1.0  <operator>  OK   Phases 5-6 (HTTPS+SMTP+ingest+mart+retention). Backup: soc_ticket_manual_2026-08-28.zip.gpg
```

Record: date · tag · operator · result (OK / rolled back) · one-line what · the
pre-deploy backup filename.

---

## 7. Related
- [production-deployment.windows.md](production-deployment.windows.md) — one-time box build (Stage 6 is the deploy primitive reused here).
- [backup-and-standby-handbook.windows.md](backup-and-standby-handbook.windows.md) — backup/restore + spare pre-staging (§2.8).
- [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) — the checks that gate a tag.
- [reporting-layer-operations.md](reporting-layer-operations.md) — the reversible-migration model case (`migrate reporting zero`).
