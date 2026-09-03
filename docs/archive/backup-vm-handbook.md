# Backup VM — Build & Operate Handbook (Linux / Docker)

> ## ⚠️ SUPERSEDED — does not apply to the current deployment
>
> This handbook assumes a **Linux** backup VM pulling from a **Docker Compose**
> production stack over SSH. The actual deployment is **Windows Server with
> native PostgreSQL**, where none of these commands run.
>
> **Use [backup-and-standby-handbook.windows.md](../operations/backup-and-standby-handbook.windows.md) instead.**
>
> Kept only as a reference for a possible future Linux deployment. The companion
> scripts (`scripts/backup/pull_archives.sh`, `prune_archive.sh`,
> `check_freshness.sh`) and `docker-compose.backupvm.yml` are likewise unused.

> **Audience:** whoever builds and runs the backup VM (you) · **Status:** Superseded · **Last updated:** 2026-07-27
> **Prerequisite reading:** [backup-and-restore.md](../operations/backup-and-restore.md) §4–5

Step-by-step build of a second VM that holds an independent, verified copy of
production's backups — closing the **off-host** gap named in
[backup-and-restore.md](../operations/backup-and-restore.md) §4 and
[backup-storage-decision-brief.md](../operations/backup-storage-decision-brief.md).

Written to be followed top to bottom. Every command is meant to be run as
written after you substitute the values from §2.

---

## 1. What you are building, and what it does not give you

```
  PRODUCTION VM                              BACKUP VM
  ┌────────────────────────────┐             ┌──────────────────────────────┐
  │ nginx → gunicorn → Django  │             │  (no app, no nginx)          │
  │ postgres 16   [ticketdata] │             │                              │
  │                            │             │  postgres 16 (empty,         │
  │ backup profile             │             │   restore-drill target only) │
  │   ↓ writes                 │             │                              │
  │ /srv/soc-ticket/backups    │◄────────────┤  pull_archives.sh (systemd)  │
  │   (hot tier)               │  SSH pull   │    ↓ verifies SHA-256        │
  │                            │  read-only  │  /srv/soc-ticket/archive     │
  └────────────────────────────┘             │    (warm tier, longer keep)  │
                                             │  restore_verify (weekly)     │
                                             └──────────────────────────────┘
```

**Pull, not push.** The backup VM reaches into production; production holds no
credential for the backup VM. This is the single most important design choice
here — with push, an attacker who owns prod owns the backups too, and deleting
reachable backups is the first thing modern ransomware does.

### What this gives you

| | |
|---|---|
| **Survives** | loss of the prod VM, prod disk corruption, ransomware on prod, accidental `DROP`, bad migration |
| **RPO** | your backup tier interval (hourly tier ⇒ ≤ 1h data loss) plus up to one pull interval |
| **RTO** | 1–3 hours, manual — see the DR runbook in §8 |
| **Closes** | the "one off-host copy" leg of 3-2-1; the **warm** tier in [backup-and-restore.md](../operations/backup-and-restore.md) §5 |

### What it does NOT give you — read this before you promise anything

- **Not a hot standby.** There is no replication. The Postgres on the backup VM
  is empty and exists only to run restore drills. Failover is a manual restore.
- **Not automatic failover.** Nothing repoints traffic. See §8.
- **Not the cold/DR tier.** If both VMs sit on the same hypervisor, SAN, or
  site, one host or array failure still takes both. That is decision #6 in the
  [decision brief](../operations/backup-storage-decision-brief.md) and it is worth chasing
  down before you consider this finished.
- **Not immutable storage.** True immutability needs object-lock/WORM. §7 gets
  you a defensible approximation; it is not the same thing.
- **Does not back up the Wazuh Indexer.** Still out of scope, as in
  [backup-and-restore.md](../operations/backup-and-restore.md) §4.

---

## 2. Decide these before you touch a keyboard

Fill this in and keep it — the rest of the handbook substitutes these values.

| # | Value | Yours | Notes |
|---|---|---|---|
| 1 | Backup VM hostname / IP | `________` | |
| 2 | Prod VM hostname / IP | `________` | |
| 3 | Different physical host from prod? | `yes / no / unknown` | If *no* or *unknown*, this is warm tier only — say so in writing. |
| 4 | Archive disk size | `____ GB` | Size it with §3 |
| 5 | Archive mount point | `/srv/soc-ticket/archive` | Prefer a **separate disk/LV**, not the root filesystem |
| 6 | Prod backup dir | `/srv/soc-ticket/backups` | Your prod `BACKUP_HOST_PATH` |
| 7 | Where the encryption passphrase lives | `________` | **Must exist in ≥ 2 places, one of them off both VMs.** See §6 |
| 8 | Who gets the failure alert | `________` | A backup nobody watches is not a backup |

**Assumed OS:** Ubuntu/Debian on both VMs, Docker + Compose v2 on prod (as
[docker-compose.prod.yml](../../docker-compose.prod.yml) requires). RHEL/Rocky
differences are noted where they matter.

---

## 3. Size the archive disk

Measure rather than guess. On **prod**, after at least one backup has run:

```bash
ls -la /srv/soc-ticket/backups/ && du -sh /srv/soc-ticket/backups/
```

Take the size of one archive as `A`. Worst-case steady state on the backup VM,
using the retention defaults in [prune_archive.sh](../../scripts/backup/prune_archive.sh)
(hourly 7d · daily 90d · weekly 180d · monthly 1095d):

```
(24 × 7) + 90 + 26 + 36  ≈  320 archives  ⇒  disk ≈ 320 × A × 1.3
```

The ×1.3 is headroom for growth and for a restore drill's temporary files.

If that lands somewhere uncomfortable, the cheapest lever is **not pulling the
hourly tier** — set `FRESHNESS_CHECKS` and the pull to daily/weekly/monthly only.
Hourly exists for fast local rollback on prod, which is a different job from
surviving host loss. Cutting it typically drops the estimate to ~150 × A.

> Media (ticket attachments/evidence) is inside every archive, so archive size
> grows with evidence volume, not just ticket count. Re-measure quarterly.

---

## 4. Part A — Build the backup VM

Run on the **backup VM**.

### 4.1 Base packages

```bash
sudo apt update && sudo apt install -y rsync openssh-client coreutils findutils ca-certificates
```

Docker (for the restore drills in §7 — skip only if you will never verify, which
defeats the point):

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker
```

### 4.2 Service account and directory layout

A dedicated unprivileged user owns the pull. It must not be your admin login.

```bash
sudo useradd --system --create-home --home-dir /var/lib/socbackup --shell /bin/sh socbackup
sudo mkdir -p /srv/soc-ticket/archive
sudo chown socbackup:socbackup /srv/soc-ticket/archive
sudo chmod 700 /srv/soc-ticket/archive
```

`700` matters: these archives contain personal data and incident records. Nobody
but the service account and root reads this directory.

### 4.3 Get the scripts onto the VM

```bash
sudo mkdir -p /opt/soc-ticket
sudo git clone <your-repo-url> /opt/soc-ticket
sudo chmod +x /opt/soc-ticket/scripts/backup/*.sh
```

No repo access from this VM? Copy just what is needed:
`scripts/backup/pull_archives.sh`, `prune_archive.sh`, `check_freshness.sh`,
`restore_verify.sh`, and `docker-compose.backupvm.yml`.

### 4.4 Lock the network down

This VM should make exactly one outbound connection (SSH to prod) and accept
only your admin SSH.

```bash
sudo ufw default deny incoming
sudo ufw allow from <your-admin-subnet> to any port 22 proto tcp
sudo ufw enable
```

Do **not** publish Postgres. [docker-compose.backupvm.yml](../../docker-compose.backupvm.yml)
deliberately does not map a port for it.

---

## 5. Part B — Grant read-only pull access on production

Run on the **production VM**. The goal: a key that can do exactly one thing —
read the backup directory — and nothing else. Not a shell, not a write, not a
delete.

### 5.1 A dedicated, restricted account

```bash
sudo groupadd -f socpull
sudo useradd --system --create-home --home-dir /var/lib/socpull -g socpull -s /bin/sh socpull
```

`/bin/sh` is required — the forced command in §5.3 needs a shell to exec. The
`restrict` option is what removes the interactive capability.

### 5.2 Let it read the archives (the permissions trap)

The backup container writes as root, so the archives are `root:root 644`. Make
the directory setgid so **new** files inherit the `socpull` group, then fix the
existing ones:

```bash
sudo chgrp -R socpull /srv/soc-ticket/backups
sudo chmod 2750 /srv/soc-ticket/backups      # 2 = setgid: new files inherit the group
sudo find /srv/soc-ticket/backups -type f -exec chmod 640 {} \;
```

Verify that new archives really do inherit it — this is the step that silently
breaks the whole pipeline weeks later:

```bash
BACKUP_TIER=manual docker compose -f docker-compose.prod.yml --profile backup run --rm backup
ls -l /srv/soc-ticket/backups | tail -3     # expect: -rw-r----- root socpull
sudo -u socpull cat /srv/soc-ticket/backups/<newest>.sha256 >/dev/null && echo "socpull can read: OK"
```

### 5.3 Install the key with a forced command

On the **backup VM**, create the key (no passphrase — it is unattended; the
forced command is what constrains it):

```bash
sudo -u socbackup ssh-keygen -t ed25519 -N "" -C "socbackup-pull" -f /var/lib/socbackup/.ssh/id_ed25519
sudo cat /var/lib/socbackup/.ssh/id_ed25519.pub
```

On **prod**, find `rrsync` (it ships with rsync, but the path moved between
releases):

```bash
command -v rrsync || ls /usr/share/rsync/scripts/rrsync*
```

If it is a `.gz`, unpack it: `sudo gunzip -c /usr/share/rsync/scripts/rrsync.gz | sudo tee /usr/local/bin/rrsync >/dev/null && sudo chmod +x /usr/local/bin/rrsync`

Then install the public key with the restriction applied:

```bash
sudo -u socpull mkdir -p /var/lib/socpull/.ssh && sudo -u socpull chmod 700 /var/lib/socpull/.ssh
sudo -u socpull tee /var/lib/socpull/.ssh/authorized_keys >/dev/null <<'EOF'
command="/usr/bin/rrsync -ro /srv/soc-ticket/backups",restrict ssh-ed25519 AAAA...PASTE_THE_PUBLIC_KEY... socbackup-pull
EOF
sudo -u socpull chmod 600 /var/lib/socpull/.ssh/authorized_keys
```

- `-ro` — rrsync refuses any write or delete. Even a fully compromised backup VM
  cannot damage production's archives.
- `restrict` — no pty, no port/agent/X11 forwarding.

### 5.4 Prove the restriction actually holds

From the **backup VM**. Accept the host key once, deliberately:

```bash
sudo -u socbackup ssh -i /var/lib/socbackup/.ssh/id_ed25519 socpull@<prod-host> true
```

Then confirm all three properties:

```bash
# 1. A pull works
sudo -u socbackup rsync -n -av -e "ssh -i /var/lib/socbackup/.ssh/id_ed25519" socpull@<prod-host>:./ /srv/soc-ticket/archive/

# 2. An interactive shell is refused
sudo -u socbackup ssh -i /var/lib/socbackup/.ssh/id_ed25519 socpull@<prod-host> "cat /etc/passwd"   # must FAIL

# 3. A write-back is refused
sudo -u socbackup rsync -n -av -e "ssh -i /var/lib/socbackup/.ssh/id_ed25519" /etc/hostname socpull@<prod-host>:./   # must FAIL
```

**All three must behave as marked.** If #2 or #3 succeeds, the forced command is
not applied — recheck `authorized_keys` before continuing.

---

## 6. Part C — The encryption passphrase (do this now, not later)

Production encrypts every archive with AES-256
([backup.sh:192](../../scripts/backup/backup.sh)). If that passphrase exists only
on the prod VM, then losing prod loses the ability to decrypt every archive you
just so carefully copied. **You would hold 300 encrypted files and no key.**

Required: at least **two** copies, at least one off both VMs.

1. On the backup VM, for automated restore drills:
   ```bash
   sudo mkdir -p /etc/soc-ticket
   sudo tee /etc/soc-ticket/backup-passphrase >/dev/null   # paste, then Ctrl-D — no trailing newline issues: it must byte-match prod's
   sudo chmod 400 /etc/soc-ticket/backup-passphrase
   sudo chown root:root /etc/soc-ticket/backup-passphrase
   ```
2. Off both VMs: the team password manager, or a sealed envelope in the safe.
   This is the copy that saves you when both VMs are unavailable.

Confirm prod uses a password **file** rather than an inline value, so the
passphrase is not sitting in `.env` — in prod's `.env`:

```ini
BACKUP_ENCRYPTION=openssl
BACKUP_ENCRYPTION_PASSWORD_FILE=/run/secrets/soc_ticket_backup_password
```

> Verify the two files match byte for byte (`sha256sum` both) before you rely on
> the drill in §7. `openssl enc -pass file:` uses the file's contents verbatim,
> so a stray newline added by an editor produces a different key.

---

## 7. Part D — Automate the pull, prune, and freshness check

Run on the **backup VM**. systemd rather than cron: you get logs, exit status,
and `OnFailure=` alerting.

### 7.1 Environment file

```bash
sudo tee /etc/soc-ticket/pull.env >/dev/null <<'EOF'
REMOTE=socpull@<prod-host>
REMOTE_DIR=./
ARCHIVE_DIR=/srv/soc-ticket/archive
SSH_KEY=/var/lib/socbackup/.ssh/id_ed25519
BACKUP_PREFIX=soc_ticket
ARCHIVE_GRACE_MINUTES=30
EOF
sudo chmod 640 /etc/soc-ticket/pull.env
sudo chgrp socbackup /etc/soc-ticket/pull.env
```

`REMOTE_DIR=./` is correct **because of rrsync** — the path is relative to the
rrsync root you set in §5.3, not an absolute path on prod.

### 7.2 The pull timer

```bash
sudo tee /etc/systemd/system/soc-backup-pull.service >/dev/null <<'EOF'
[Unit]
Description=Pull SOC ticket backup archives from production
After=network-online.target
Wants=network-online.target
OnFailure=soc-backup-alert@%n.service

[Service]
Type=oneshot
User=socbackup
EnvironmentFile=/etc/soc-ticket/pull.env
ExecStart=/opt/soc-ticket/scripts/backup/pull_archives.sh
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/soc-ticket/archive
NoNewPrivileges=true
EOF

sudo tee /etc/systemd/system/soc-backup-pull.timer >/dev/null <<'EOF'
[Unit]
Description=Pull SOC ticket backups hourly

[Timer]
OnCalendar=hourly
RandomizedDelaySec=5m
Persistent=true

[Install]
WantedBy=timers.target
EOF
```

`Persistent=true` catches up a run missed while the VM was down.
`RandomizedDelaySec` keeps the pull from landing exactly on prod's hourly backup.

### 7.3 Prune and freshness timers

```bash
sudo tee /etc/systemd/system/soc-backup-prune.service >/dev/null <<'EOF'
[Unit]
Description=Prune the SOC ticket backup archive
OnFailure=soc-backup-alert@%n.service

[Service]
Type=oneshot
User=socbackup
Environment=ARCHIVE_DIR=/srv/soc-ticket/archive
Environment=BACKUP_PREFIX=soc_ticket
ExecStart=/opt/soc-ticket/scripts/backup/prune_archive.sh
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/soc-ticket/archive
NoNewPrivileges=true
EOF

sudo tee /etc/systemd/system/soc-backup-check.service >/dev/null <<'EOF'
[Unit]
Description=Check SOC ticket backup archive freshness
OnFailure=soc-backup-alert@%n.service

[Service]
Type=oneshot
User=socbackup
Environment=ARCHIVE_DIR=/srv/soc-ticket/archive
Environment=BACKUP_PREFIX=soc_ticket
Environment=FRESHNESS_CHECKS=daily:26 weekly:180
ExecStart=/opt/soc-ticket/scripts/backup/check_freshness.sh
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
EOF
```

Daily timers for both (prune at 03:20, check at 07:00 so a failure greets you at
the start of the day):

```bash
for unit in prune:03:20 check:07:00; do
  name="${unit%%:*}"; time="${unit#*:}"
  sudo tee /etc/systemd/system/soc-backup-${name}.timer >/dev/null <<EOF
[Unit]
Description=Daily soc-backup-${name}

[Timer]
OnCalendar=*-*-* ${time}:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
done
```

### 7.4 The alert hook — the part people skip

```bash
sudo tee /etc/systemd/system/soc-backup-alert@.service >/dev/null <<'EOF'
[Unit]
Description=Alert on %i failure

[Service]
Type=oneshot
ExecStart=/opt/soc-ticket/scripts/backup/alert.sh %i
EOF
```

Write `/opt/soc-ticket/scripts/backup/alert.sh` to match how you actually get
paged. Minimum viable version (mail to decision #8 from §2):

```bash
#!/bin/sh
UNIT="$1"
{ echo "SOC ticket backup unit failed: $UNIT"; echo; journalctl -u "$UNIT" -n 50 --no-pager; } \
  | mail -s "[SOC-BACKUP] FAILED: $UNIT on $(hostname)" "<your-alert-address>"
```

Better, if you have it: post to the SOC's existing alerting channel. The point is
that a stalled pull must reach a human within a day.

### 7.5 Enable and smoke-test

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now soc-backup-pull.timer soc-backup-prune.timer soc-backup-check.timer
sudo systemctl start soc-backup-pull.service
sudo journalctl -u soc-backup-pull.service -n 50 --no-pager
ls -la /srv/soc-ticket/archive/
```

Expect `pull-archives: N archive(s) verified, 0 quarantined`.

Dry-run the pruner before trusting it with retention:

```bash
sudo -u socbackup DRY_RUN=true ARCHIVE_DIR=/srv/soc-ticket/archive /opt/soc-ticket/scripts/backup/prune_archive.sh
```

---

## 8. Part E — Prove the archives restore (the whole point)

A copied file is not a backup until you have restored it. Do this **on the
backup VM** — it exercises the archive, the passphrase, and your own procedure
all at once, without touching production.

### 8.1 One-time setup

```bash
cd /opt/soc-ticket
sudo tee .env >/dev/null <<'EOF'
DB_NAME=ticketdata
DB_USER=ticket
DB_PASSWORD=<a-password-local-to-this-vm-only>
RESTORE_DB=ticketdata_restoretest
RESTORE_DROP_AFTER_TEST=true
ARCHIVE_HOST_PATH=/srv/soc-ticket/archive
BACKUP_PASSPHRASE_HOST_PATH=/etc/soc-ticket/backup-passphrase
BACKUP_ENCRYPTION_PASSWORD_FILE=/run/secrets/soc_ticket_backup_password
EOF
sudo chmod 600 .env
sudo docker compose -f docker-compose.backupvm.yml up -d db
```

`DB_PASSWORD` here is **not** production's. This Postgres holds only throwaway
restore targets; giving it prod's credential spreads that secret for no reason.

### 8.2 Run a drill

```bash
NEWEST=$(ls -1t /srv/soc-ticket/archive/soc_ticket_*.tar.gz.enc | head -1)
sudo BACKUP_FILE="/backups/$(basename "$NEWEST")" \
  docker compose -f docker-compose.backupvm.yml --profile verify run --rm restore_verify
```

Success looks like the row counts from
[restore_verify.sh](../../scripts/backup/restore_verify.sh) matching the
manifest, ending in `restore-verify: backup is restorable`. A count mismatch or
checksum failure is a **real incident** — the backup you were relying on is not
sound.

### 8.3 Schedule it weekly

Same systemd pattern as §7.3, running a small wrapper that picks the newest
archive and invokes the compose profile. Weekly is the right cadence: often
enough that a broken backup is caught within one retention window, rare enough
that the drill cost is negligible.

> **Regarding real data:** a successful drill puts real ticket data, personal
> data, and evidence on this VM. That is exactly why §4.2 sets `700` and §4.4
> firewalls it. Treat this VM at the same classification as production — because
> after the first drill, it holds the same data.

---

## 9. Part F — DR runbook: production is gone

Rehearse this once. An untested runbook is a wish.

**Realistic RTO: 1–3 hours.** Most of it is standing up the app, not the restore.

1. **Decide where the app runs.** Fastest is on the backup VM itself. Accept that
   you are then running production with no backup target until you rebuild one —
   which is a decision to make consciously, not by drift.
2. **Pick the archive** — newest verified `monthly`/`weekly`/`daily`/`hourly`,
   and confirm its checksum before trusting it:
   ```bash
   cd /srv/soc-ticket/archive && sha256sum -c <archive>.sha256 2>/dev/null || \
     [ "$(sha256sum <archive> | awk '{print $1}')" = "$(awk '{print $1}' <archive>.sha256)" ] && echo OK
   ```
   The fallback matters: the `.sha256` files record production's *container*
   path (`/backups/...`), so plain `sha256sum -c` cannot find the file here.
3. **Decrypt, extract, verify** — [backup-and-restore.md](../operations/backup-and-restore.md) §3.1.
4. **Recreate the database** owned by the app role — §3.2.
5. **Restore the dump** — §3.3.
6. **⚠ Recreate roles and grants** — §3.4. *This is the step that bites.* The
   archive is a single-database `pg_dump --no-owner --no-acl`, so cluster-global
   roles and GRANTs are **not** in it. Data restores; access does not. Recreate
   the `ticket` role, and re-run
   [reporting-ro-setup.sql](../operations/reporting-ro-setup.sql) if Grafana reads the mart.
7. **Restore media** (attachments/evidence) — §3.5.
8. **Rebuild reporting matviews** — `manage.py refresh_reporting` — §3.6.
9. **Repoint the service** — `.env`: `ALLOWED_HOSTS`, `SITE_URL`, `DB_HOST`; TLS
   cert paths; then DNS. Until `SITE_URL` is right, notification emails will link
   users at a dead host.
10. **Re-establish backups.** You are unprotected until the pull runs again from
    somewhere. Do not let this sit.
11. **Reconnect ingestion** — check `OPENSEARCH_*` reachability and the ingest
    watermark, so alert ingestion resumes without gaps or duplicates.

---

## 10. Go-live checklist

- [ ] Backup VM confirmed on a **different physical host** from prod (§2 #3) — or the limitation recorded in writing
- [ ] Archive directory is `700`, owned by `socbackup`, on its own disk
- [ ] `socpull` on prod can read archives; new archives inherit the group (setgid verified with a fresh backup)
- [ ] SSH key installed with `rrsync -ro` + `restrict`
- [ ] **All three tests in §5.4 behave as marked** (pull works; shell refused; write refused)
- [ ] Encryption passphrase exists in ≥ 2 places, one off both VMs, and byte-matches prod
- [ ] `soc-backup-pull.timer` enabled; a manual run verified archives with 0 quarantined
- [ ] `soc-backup-prune.timer` dry-run reviewed, then enabled
- [ ] `soc-backup-check.timer` enabled and `alert.sh` **tested by deliberately breaking something** (rename the SSH key, confirm the alert arrives)
- [ ] One full `restore_verify` drill passed on the backup VM
- [ ] DR runbook (§9) walked through end to end at least once
- [ ] Firewall: no inbound except admin SSH; Postgres not published

The alert test is the one to insist on. Everything else here fails loudly; a
broken alert path fails silently, and takes the rest of the system's
trustworthiness with it.

---

## 11. What this still does not close

For the governance conversation — this handbook implements the **warm** tier of
[backup-and-restore.md](../operations/backup-and-restore.md) §5 and no more:

| Decision brief item | Status after this build |
|---|---|
| #1 Storage location (warm) | **Closed** — second VM |
| #1 Storage location (cold/DR) | **Open** — needs a second site or object storage |
| #2 Data residency | Unchanged — both VMs in Thailand; confirm with DPO |
| #3 Retention periods | Defaults set in `prune_archive.sh`; **still needs compliance sign-off** |
| #4 CII designation / NCSA code | **Open** — unaffected by this work |
| #5 Immutability | **Partially** — pull model + `-ro` key ≠ object-lock. Still open |
| #5 Key management | Improved (§6); a KMS is still the standard |
| #6 Redundant storage under both VMs | **Open** — infra question, still worth an answer |

---

## 12. Related

- [backup-and-restore.md](../operations/backup-and-restore.md) — what a backup contains, restore procedure, the roles/grants gotcha
- [backup-storage-decision-brief.md](../operations/backup-storage-decision-brief.md) — the governance ask
- [production-deployment.md](production-deployment.md) — the prod stack this pulls from
- [../architecture/data-infrastructure.md](../architecture/data-infrastructure.md) — where backup sits overall
