# Backup & Restore (Docker / Linux)

> ## ⚠️ Describes the Docker Compose deployment, not the current one
>
> Production runs **native PostgreSQL on Windows Server**, so the `backup` /
> `restore_verify` compose profiles and `scripts/backup/*.sh` described here do
> not run there. Concepts still apply — what an archive contains (§1), the
> restore procedure and the **roles/grants-not-in-the-dump** gap (§3.4), and the
> 3-2-1 storage strategy (§5).
>
> For build instructions, use
> [backup-and-standby-handbook.windows.md](backup-and-standby-handbook.windows.md).

> **Audience:** operators · **Status:** Partially superseded · **Last updated:** 2026-07-27

How the production backup works, what it does and does not cover, and the restore
procedure — including the step that is easy to miss. For where backup sits in the
overall data infrastructure, see
[../architecture/data-infrastructure.md](../architecture/data-infrastructure.md).

Scripts: `scripts/backup/backup.sh` and `scripts/backup/restore_verify.sh`,
wired as the `backup` / `restore_verify` compose profiles in
`docker-compose.prod.yml`.

---

## 1. What a backup contains

One archive per run (`<prefix>_<tier>_<utc-timestamp>.tar.gz`, then encrypted):

| Component | What |
|---|---|
| `database.dump` | `pg_dump --format=custom --no-owner --no-acl` of **`ticketdata`** (both the `public` operational schema **and** the `mart` reporting schema) |
| `media.tar.gz` | the `MEDIA_ROOT` tree — ticket **attachments / evidence** |
| `manifest.json` + `counts.env` | row counts for the operational tables (tickets, logs, triage, attachments, wazuh_alerts, users) + media file count, for integrity checks |
| `checksums.sha256` | SHA-256 of every component; the archive itself is also checksummed |

**Encryption:** AES-256 (`openssl`, pbkdf2/200k) or GPG to a recipient.
Unencrypted requires an explicit `BACKUP_ALLOW_UNENCRYPTED=true` opt-in.

**Retention:** the caller sets `BACKUP_TIER` per run; the script prunes only that
tier — hourly 2d · daily 30d · weekly 84d · monthly 365d (all configurable).

---

## 2. Scheduling backups

Run the `backup` profile once per tier from cron on the prod host, e.g.:
```
0 * * * *   … BACKUP_TIER=hourly  docker compose -f docker-compose.prod.yml --profile backup run --rm backup
30 0 * * *  … BACKUP_TIER=daily   docker compose -f docker-compose.prod.yml --profile backup run --rm backup
30 1 * * 0  … BACKUP_TIER=weekly  docker compose -f docker-compose.prod.yml --profile backup run --rm backup
30 2 1 * *  … BACKUP_TIER=monthly docker compose -f docker-compose.prod.yml --profile backup run --rm backup
```

---

## 3. Restore procedure

`restore_verify.sh` already exercises the mechanical restore into a throwaway DB
(`ticketdata_restoretest`) and asserts the manifest counts — run it regularly to
prove backups are restorable. A real restore to a live DB follows the same steps:

1. **Decrypt & verify** — `openssl`/`gpg` decrypt, extract, `sha256sum -c checksums.sha256`.
2. **Recreate the target database** owned by the app role: `create database ticketdata owner ticket;`.
3. **Restore the dump** — `pg_restore --no-owner --no-acl --dbname=ticketdata database.dump`.
4. **⚠ Recreate roles & grants — the step that's not in the dump.** The backup is
   `pg_dump --no-owner --no-acl` of a **single database**, not `pg_dumpall`. So
   **cluster-global roles and their GRANTs are NOT in the archive.** After the
   restore the *data* is present but *access* is not:
   - Ensure the app role (`ticket`) exists with its password (from `.env`).
   - If Grafana/BI reads the mart, re-run
     [reporting-ro-setup.sql](reporting-ro-setup.sql) as a superuser to recreate
     `reporting_ro` + its grants.
5. **Restore media** — extract `media.tar.gz` back into `MEDIA_ROOT`.
6. **Rebuild the reporting matviews** — run `manage.py refresh_reporting`. The
   `mart` matviews are in the dump but recompute from the restored operational
   tables anyway; the `snapshot_queue_daily` history and `dim_severity_map` edits
   restore as-is (they are the only non-recomputable reporting data).

---

## 4. What backup does and does not cover

Backup priority follows the **derived-vs-snapshot** line (full picture in
[../architecture/data-infrastructure.md](../architecture/data-infrastructure.md)):

- **Covered:** the operational store (`ticketdata.public`) + attachment evidence
  (media) — the irreplaceable core; and the non-recomputable reporting data
  (`snapshot_queue_daily`, `dim_severity_map`, `agg_detection_daily`), which ride
  along in the same DB dump.
- **In the dump but redundant:** the derived reporting views/matviews — they
  rebuild from the operational tables via `refresh_reporting`.
- **NOT covered — by design or gap:**
  - **Wazuh Indexer** (raw telemetry) — a separate system with its own ~3-month
    retention; not in the app dump. Raw alerts persist long-term only via the
    `agg_detection_daily` capture (then protected here) or Wazuh's own snapshots.
  - **Cluster roles/grants** — recreate on restore (§3.4).
  - **`socdata`** — the dead prototype DB is excluded (correct; retire it, Phase 5).
  - **Off-host copy** — archives land on the host volume (`BACKUP_HOST_PATH`).
    Encryption makes off-siting safe. A second VM pulling a verified copy off-box
    (the **warm** tier of 3-2-1) is built in
    [backup-vm-handbook.md](../archive/backup-vm-handbook.md); the **cold/immutable** tier
    remains open pending the governance decision.

---

## 5. Backup storage & retention strategy

Where the archives physically live matters as much as taking them. A copy on the
production VM **alone** survives only *logical* failure (bad migration, accidental
drop); it dies with the host on hardware loss, ransomware, or deletion. Apply the
**3-2-1 rule** — 3 copies, 2 storage types, **1 off-host** — by mapping the
existing retention tiers to distance:

| Tier | Location | Protects against |
|---|---|---|
| **Hot** — hourly/daily | prod VM or an adjacent backup volume | logical errors (fast restore) |
| **Warm** — daily/weekly | a separate backup server / NAS in the same data centre | loss of the prod VM |
| **Cold / DR** — weekly/monthly | a second site or object storage, **immutable (object-lock)** | site loss, ransomware, insider deletion |

Non-negotiables wherever backups land:
- **Immutability on the DR tier** — object-lock / WORM; the backup account may
  *write* but not *delete* it. Ransomware deletes reachable backups first.
- **Encryption key stored separately** from the archives (KMS or offline) and
  itself backed up — *a backup you can't decrypt is not a backup*.
- **Least-privilege access** to read or delete backups.

**Thai regulatory context** (confirm specifics with compliance — not legal advice):
- **Computer Crime Act (B.E. 2550/2560):** traffic/log data retained **≥ 90 days**
  (extendable by order). The 365-day monthly tier clears it.
- **PDPA (B.E. 2562/2019):** tickets hold personal data → appropriate security
  measures (encryption ✓, access control) and **cross-border-transfer limits →
  keep backups in Thailand**.
- **Cybersecurity Act (B.E. 2562/2019) / NCSA (สกมช.):** a national telecom is
  likely **CII**, whose codes of practice mandate DR/backup controls — obtain the
  specific code from compliance.
- Likely also **NBTC** telecom rules and an internal **ISO 27001** / data-governance
  retention schedule that may be stricter than the law.

**Recommended for NT:** keep all backups on **NT-owned infrastructure inside
Thailand** (a backup server for warm; NT object storage / a second NT site for
cold-immutable) — not a foreign public cloud. Location, residency, and retention
are governance decisions: see the
[backup-storage-decision-brief.md](backup-storage-decision-brief.md).

**RAID is not a backup.** RAID (or SAN redundancy) protects *availability* against
a single disk failing — it does **not** protect against deletion, corruption,
ransomware, or whole-host loss, because those hit every disk in the array at once,
and RAID keeps no point-in-time copy. It is therefore **not** one of the "3 copies"
in 3-2-1. A production DB needs *both*: redundant storage for uptime **and**
backups for recovery. In NT's virtualised/DC environment disk redundancy is
normally provided at the storage/hypervisor layer — **confirm** the prod DB VM and
the backup repository sit on redundant storage (it's an infra question), rather
than configuring RAID yourself.

---

## 6. Environment note

The `backup`/`restore_verify` services are **production** only (Dockerised
PostgreSQL 16). The dev/UAT localhost DB is **not** backed up — do not accrue data
in UAT that you cannot afford to lose.

---

## 7. Related
- [backup-vm-handbook.md](../archive/backup-vm-handbook.md) — build & operate the off-host backup VM (pull, verify, prune, restore drills, DR runbook).
- [backup-storage-decision-brief.md](backup-storage-decision-brief.md) — one-page brief for the governance/compliance decision on storage location & retention.
- [../architecture/data-infrastructure.md](../architecture/data-infrastructure.md) — the whole-picture diagram.
- [reporting-layer-operations.md](reporting-layer-operations.md) — running the reporting layer.
- [production-deployment.md](../archive/production-deployment.md) — overall prod deploy.
