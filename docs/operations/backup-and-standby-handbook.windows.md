# SOC Ticket - Backup & Standby Handbook (Windows Server)

> **Audience:** whoever builds and operates the production and spare VMs (you)
> **Status:** Current · **Last updated:** 2026-09-02 (Phases 1-3 built through 2026-08-25; restore drill passed 2026-08-24)
> **Applies to:** native PostgreSQL on Windows Server, Django served by Waitress as a Windows service

One spare VM, two jobs, in this order:

1. **Phase 1-2 - Off-host backups.** Production writes encrypted archives; the
   spare VM pulls them read-only, verifies them, and proves they restore.
2. **Phase 3 - Streaming standby.** The spare VM also runs a warm replica you
   can promote if the production database fails.

Backups come first because they cover the failure replication cannot: a
replica copies accidental deletes, bad migrations, and ransomware encryption
within seconds. If you only ever finish Phase 2, you are still protected.

---

## 0. Read this first

### If production is not built yet - you are in the best possible position

**Yes, this handbook applies. Follow it in the same order, starting from
[Phase 0](#phase-0---production-prerequisites).** Doing it before go-live is
strictly easier than retrofitting:

- The PostgreSQL settings in Phase 0 (`wal_level`, `listen_addresses`,
  `max_wal_senders`) **require a database restart**. Set them at install time and
  you never need a maintenance window for them.
- You can test destructively. Drop the database, restore it, break the pull job
  on purpose - with no real incident data at risk. After go-live you cannot.
- The first restore drill can run against seeded UAT data, which is exactly what
  you want for a rehearsal.
- Encryption keys get created once, correctly, instead of being rotated later
  across archives already written.

The only thing you cannot do before production exists is measure real database
and evidence sizes, so [§1 sizing](#1-sizing-the-150-gb-disk) says how to
proceed with an estimate and re-check after go-live.

### Two things this repo currently gets wrong about your deployment

1. [backup-and-restore.md](backup-and-restore.md) and
   [backup-vm-handbook.md](../archive/backup-vm-handbook.md) describe a **Docker Compose**
   production with Linux shell scripts. Your production is **native PostgreSQL on
   Windows**. Those documents and `scripts/backup/*.sh`,
   `docker-compose.backupvm.yml` do **not** apply here. This handbook and
   `scripts/backup/windows/*.ps1` replace them for this deployment.
2. ~~Nothing is currently backing up production.~~ ~~Superseded 2026-08-24: the
   restore is still unproven.~~ **Updated 2026-08-25:** Phases 1-3 are built and
   the **restore drill has passed** (2026-08-24 - decrypts, checksums, restores
   into a throwaway DB, row counts matched the manifest; scheduled weekly as
   `SOC-Restore-Drill`). These are proven backups, not just archives. The
   remaining gaps are the **failover rehearsal** (promoting the standby) and the
   **offline GPG-key test** - see Phase 3 and the go-live checklist (Section 6).

### Field notes from the first build (2026-08-24)

Everything below was learned the hard way while building this deployment. None
of it is theoretical.

**Deployed deviations - the script defaults were wrong for this environment and
have been corrected in-repo. Verify them before trusting any command here:**

| Reality | Script default was |
|---|---|
| Database `ticketdata_prod`, role `ticket_prod` | `ticketdata` / `ticket` |
| PostgreSQL **18** | 16 |
| `C:\Program Files\GnuPG\bin\gpg.exe` (Gpg4win 5.x is 64-bit) | the `(x86)` path |
| Spare has one **C:** volume | `D:\SOCBackup\archive` |

**The production hostname ends in a hyphen** (`EXT-TGOO-02924-`), which violates
RFC 1123 and breaks name resolution. Every cross-host setting - `-SourceUnc`,
the SMB firewall scope, `primary_conninfo` - must use the IP address, not the
name. A UNC path by name fails with "the network name cannot be found", which
looks like a firewall problem and is not.

**The database collation is `Thai_Thailand.874` with UTF8 encoding.** The
restore-verification instance must match it exactly, and its database must be
created with `TEMPLATE=template0` - you cannot specify a different collation
while cloning `template1`. This also makes the dump **Windows-only**:
`Thai_Thailand.874` does not exist on Linux PostgreSQL. Confirm collation with
`SELECT datcollate FROM pg_database WHERE datname = ...`; the `lc_collate`
server GUC was removed in PostgreSQL 16 and querying it errors.

#### Task Scheduler - five ways a task silently does nothing

1. **`Log on as a batch job`** is not granted to a plain local account by
   default. Without it the task reports `267011` (`0x41303`, "has not run")
   forever. Creation succeeds, state shows `Ready`, nothing runs.
2. **`schtasks /ru` without `/rp`** creates a *run only when user is logged on*
   task. A service account never has a session, so it never runs. Fix with
   `Set-ScheduledTask -User -Password` and confirm `LogonType` reads
   **`Password`**.
3. **`schtasks /create /f` on an existing task resets `LogonType`** back to
   interactive. Any step that recreates a task must re-apply the principal
   immediately afterwards. This caused two separate false starts.
4. **Enable the operational log first** - it is off by default, which is why
   these failures are silent:
   `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`.
   Event **332** names the logon-type problem directly.
5. **Set an `ExecutionTimeLimit`.** With `MultipleInstances: IgnoreNew`, one
   stuck run blocks every subsequent run indefinitely.

A service account's **first logon builds its Windows profile**, which can take
minutes. A task that appears hung on its first run may simply be slow.

#### icacls - how to empty a DACL by accident

- **Never use backtick line continuations.** If one breaks, PowerShell runs
  `icacls <path> /inheritance:r` alone - stripping every ACE and granting
  nothing. The result is an **empty DACL**: no access for anyone, propagated to
  every child, with even an elevated Administrator locked out. This happened
  once and took the application offline.
- **One target per command, on one line.** Grants before `/inheritance:r`.
  Read the listing after each. *A listing that prints the path and no ACE lines
  is an empty DACL - stop immediately.*
- **`icacls` prints "Successfully processed 1 files" either way.** Its exit
  message proves nothing.
- **`/remove:g` cannot remove an inherited ACE.** It reports success and the ACE
  stays. Removing inherited `BUILTIN\Users` requires `/inheritance:r`.
- Recovery is `icacls <path> /reset /T /C /Q`. Only run it if the service
  *actually* fails - running it after a successful change silently undoes the
  hardening.
- **Share permissions and NTFS permissions are separate gates.** `svc_socpull`
  had share-level read and no NTFS grant; the connection authenticated and then
  denied every file. Grant both.

#### Credentials

- **A profile-less service account has no `%APPDATA%`**, so the documented
  `pgpass.conf` location cannot exist. Do not create `C:\Users\<account>` by
  hand - Windows later builds a *second* profile alongside it and `%APPDATA%`
  resolves elsewhere. Use `PGPASSFILE` pointing outside any profile;
  `New-SocBackup.ps1` now exports it itself from `-PgPassFile`.
- **Write `pgpass.conf` as ASCII with no BOM.** PowerShell's
  `Set-Content -Encoding utf8` writes a BOM and libpq will not parse it. The
  same trap applies to `.env`: a BOM makes the first key unreadable and Django
  fails to start with `UndefinedValueError` on `SECRET_KEY`.
- **`Set-LocalUser` changes a password but does not clear a lockout.**
- **A locked account rejects every password** with "the specified network
  password is not correct" - indistinguishable from a wrong password. Check
  `([ADSI]"WinNT://./<user>,user").IsAccountLocked` *before* concluding the
  password is wrong. An hourly task holding a bad credential will re-lock the
  account faster than you can debug it: disable the task first.
- **A `\password` in a pasted psql block eats the next two lines** as the
  password and its confirmation. A `GRANT pg_read_all_data` vanished this way
  with no error, and `pg_dump` then failed on
  `LOCK TABLE ... permission denied`. Run privilege statements one at a time.
- **RDP clipboard does not reliably carry text between nested sessions.**
  Transferring a generated password by copy-paste failed repeatedly and
  silently. Use a passphrase you can type on both machines, and verify it with
  a SHA-256 fingerprint *before* spending an authentication attempt - hashing
  costs nothing and cannot lock an account.

#### These scripts had never been run before this build

Two real bugs were found in `New-SocBackup.ps1`:

- `--file=(Join-Path ...)` - PowerShell does not evaluate a parenthesised
  expression glued to an argument token. The path was passed as a **positional**
  argument, which `pg_dump` read as the *database name*, failing with
  `database "C:\SOCBackup\...staging" does not exist` (truncated at
  PostgreSQL's 63-character identifier limit). That line could never have
  produced an archive.
- The script now exports `PGPASSFILE` itself rather than relying on a
  machine-level environment variable, which the Task Scheduler service does not
  see until it restarts.

Assume the remaining scripts are equally unexercised. Run each one manually and
interactively before scheduling it.

---

### What this gives you, and what it does not

| | |
|---|---|
| **Survives** | prod VM loss, disk corruption, ransomware on prod, accidental `DROP`, bad migration, prod database process failure |
| **RPO** | backup tier interval (Phase 2); near-zero for database rows once the standby is running (Phase 3) |
| **RTO** | 1-3 hours from archives; 15-30 minutes by promoting the standby |
| **Does NOT cover** | both VMs failing, shared host/SAN/site failure, the Wazuh Indexer (separate system, own retention), automatic failover (deliberately manual) |

If both VMs sit on the same hypervisor or SAN, this is a **warm** tier only - one
host failure still takes both. Ask infrastructure and write the answer down.

---

## 1. Sizing the spare VM disk

> **Confirm the actual disk size before provisioning.** 120 GB and 150 GB have
> both been quoted. The worked example below uses **120 GB** as the conservative
> case; the formula takes whatever number is real. Check with
> `Get-Volume` on the spare VM and write the answer into §2 row 10.

Four things share the spare VM's disk. They compete, and the failure mode is
unpleasant: a runaway archive fills the volume and **stops replication**.

| Consumer | Needs |
|---|---|
| Standby data directory | database size x 1.5 (data + WAL headroom) |
| Restore-drill scratch | database size, transient - dropped after each drill |
| Pre-staged app stack (§2.8) | ~5 GB (Python, venv, IIS features, app code) |
| Archive | whatever is left, minus headroom |
| Free headroom | 15% minimum, enforced by `Test-SocArchive.ps1` |

**Measure first.** On production, once PostgreSQL is running:

```powershell
& "$PgBin\psql.exe" -U postgres -d ticketdata -c "SELECT pg_size_pretty(pg_database_size('ticketdata'));"
(Get-ChildItem 'C:\SOCTicket\app\media' -Recurse -File | Measure-Object Length -Sum).Sum / 1GB
```

Call the database size `D` and one compressed archive `A`. Measure `A` after your
first real backup in Phase 1; before that, estimate it at roughly 30% of database
size plus media size.

**The formula**, for a disk of `T` GB:

```
standby        = D x 1.5
drill scratch  = D
app stack      = 5
headroom       = T x 0.15
archive budget = T - (D x 2.5) - 5 - (T x 0.15)
```

**Worked example at T = 120, D = 10 GB, A = 4 GB:**

```
archive budget = 120 - 25 - 5 - 18 = 72 GB  ->  ~18 archives
```

Eighteen archives will **not** hold an hourly tier plus 90 daily. Choose from the
table using `archive budget / A`:

| Archives that fit | Retention to set |
|---|---|
| > 60 | Defaults are fine: hourly 7d, daily 90d, weekly 180d, monthly 3y |
| 20-60 | **Skip the hourly tier.** Daily 30d, weekly 84d, monthly 365d |
| 10-20 | Skip hourly; daily 14d, weekly 84d, monthly 365d. This is the 120 GB / D=10 case |
| < 10 | Weekly + monthly only, and go ask for a bigger disk - you are one bad week from having no usable recovery point |

Two rules regardless of what you choose:

- **Set `-MaxArchiveGB` on the prune task** (§2.4) to the archive budget. That is
  the backstop that stops the archive starving the standby. Without it, the
  interaction between these two consumers is silent until replication breaks.
- **Cut the hourly tier first.** It buys fast local rollback on production, which
  is a different job from surviving host loss. The monthly tier is the one that
  carries the statutory retention floor - never cut that to make room.

> If `D` turns out much larger than 10 GB, the standby and the archive stop
> fitting together. At `D` = 30 GB on a 120 GB disk the archive budget is only
> 32 GB. That is the point to either request more disk or decide that Phase 3
> (standby) is not affordable on this VM and stop at Phase 2.

> Re-measure quarterly. Archive size grows with evidence volume, not ticket count.

---

## 2. Fill this in before you start

| # | Value | Yours | Notes |
|---|---|---|---|
| 1 | `PROD_HOST` / `PROD_IP` | `________` | |
| 2 | `SPARE_HOST` / `SPARE_IP` | `________` | |
| 3 | Different physical host? | `yes / no / unknown` | If not "yes", record the limitation |
| 4 | PostgreSQL major version on prod | `________` | Phase 3 requires **the same major version** on both |
| 5 | Prod data directory | `C:\Program Files\PostgreSQL\16\data` | |
| 6 | Prod PG service name | `________` | `Get-Service postgresql*` |
| 7 | Prod PG service account | `________` | §Phase 0.1 |
| 8 | `MEDIA_ROOT` on prod | `________` | From the app's `.env` |
| 9 | Archive path on prod | `C:\SOCBackup\archive` | |
| 10 | Archive path on spare | `D:\SOCBackup\archive` | Ideally a different volume from the standby |
| 11 | GPG passphrase stored where (2 places) | `________` | §Phase 1.2 - one must be off both VMs |
| 12 | Alert email + SMTP relay | `________` | A backup nobody watches is not a backup |

Commands below use these names literally - substitute as you go. **Run every
PowerShell block in an elevated (Administrator) session** unless told otherwise.

### PostgreSQL version and paths

Every command below writes `$PgBin` rather than a version-specific path. Set it
once per session on each VM, matching the version you actually installed:

```powershell
$PgBin = 'C:\Program Files\PostgreSQL\18\bin'    # or 16, 17 - whatever you installed
& "$PgBin\psql.exe" --version
```

The scripts take `-PgBinPath` for the same reason; their `16` defaults are
placeholders, not a recommendation.

> **Before standardising on PostgreSQL 18, confirm a supported Windows build
> exists** with a maintained patch path. Windows packaging for recent PostgreSQL
> majors has been in flux, and finding a gap after go-live is expensive. Matching
> UAT is the right goal - just verify you can obtain and patch it on Windows
> first. If not, standardise all three environments on the newest major with
> solid Windows packaging. **Production and standby must be the same major
> version**; streaming replication will not work otherwise.

### Where this fits in the deployment order

Backup work interleaves with the application build. Follow this order - it
resolves the common mistake of listing "create the production database" both
before and after the backup phases:

| Step | What | Handbook |
|---|---|---|
| 1 | Record IPs, disk sizes, host separation, PG version, service accounts | §1, §2 |
| 2 | Build the production VM: OS hardening, Python, **PostgreSQL**, IIS + URL Rewrite/ARR, Git, Gpg4win | [production-deployment.windows.md](production-deployment.windows.md) Stages 1-2 |
| 3 | **Create the production database, `.env`/secrets, superuser, and the Waitress service.** Run the initial migrations. IIS -> Waitress on `127.0.0.1` | [production-deployment.windows.md](production-deployment.windows.md) Stages 3-11 |
| 4 | Apply the PostgreSQL replication prerequisites **at install time** | Phase 0 |
| 5 | Backups working and scheduled on production | Phase 1 |
| 6 | Off-host pull, restore drill, alerting on the spare VM | Phase 2 |
| 7 | Pre-stage the app stack on the spare VM | §2.8 |
| 8 | Streaming standby | Phase 3 |
| 9 | Operational configuration: real email, Wazuh ingestion task, 90-day cleanup, CSV import | Phase 5 |
| 10 | Launch gates, then go live | §6 |

Steps 3 and 9 are both "application configuration" but they are **not** the same
work and must not be merged. Step 3 creates the database - so it has to precede
step 5, which backs that database up. Step 9 configures behaviour against a
database that already exists and is already protected.

> **"Run migrations only after a confirmed backup"** applies from the *second*
> deployment onward. The initial migration in step 3 creates the schema; there is
> nothing to back up before it.

---

## Phase 0 - Production prerequisites

Do this at install time if production does not exist yet. If it is already
running, the marked settings need a service restart - take a maintenance window
once and set them all together.

### 0.1 Confirm what you have

```powershell
Get-Service postgresql*
Get-CimInstance Win32_Service -Filter "Name LIKE 'postgresql%'" | Select-Object Name, StartName, PathName
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c "SHOW server_version; SHOW data_directory; SHOW server_encoding;"
```

Record the service **account** (`StartName`) - the spare VM's services must run
as an equivalent account. PostgreSQL on Windows **refuses to start under an
administrator account**, so this will be something like
`NT AUTHORITY\NetworkService`, not LocalSystem.

Record the **encoding**. The restore-drill instance in Phase 2 must match it or
`pg_restore` will fail.

### 0.2 Settings needed by both phases

Edit `postgresql.conf` in the data directory. Add or change:

```ini
# Required for Phase 3 (streaming standby). RESTART REQUIRED.
listen_addresses = 'localhost,PROD_IP'
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10

# Caps how much WAL a replication slot may retain. RELOAD ONLY.
# Without this, a standby that goes offline makes production retain WAL until
# its disk fills and PRODUCTION STOPS. With it, a long-disconnected standby is
# invalidated and must be rebuilt - which is far preferable to prod going down.
max_slot_wal_keep_size = 10GB

# Encrypt replication. The stream is the entire contents of the database -
# personal data and incident records - flowing continuously across the network.
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
```

Generate a certificate for `ssl` if you do not have one from corporate PKI. Place
both files **in the data directory**:

```powershell
cd 'C:\Program Files\PostgreSQL\16\data'
& 'C:\Program Files\PostgreSQL\16\bin\openssl.exe' req -new -x509 -days 1825 -nodes -text `
  -out server.crt -keyout server.key -subj "/CN=PROD_HOST"
icacls server.key /inheritance:r /grant "NT AUTHORITY\NetworkService:(R)" /grant "Administrators:(F)"
```

> If `openssl.exe` is not in the PostgreSQL `bin` folder, use any OpenSSL build,
> or request a certificate from your PKI team. A self-signed certificate is
> acceptable here because the standby will be configured to trust this specific
> certificate, not a public CA.

Restart and confirm:

```powershell
Restart-Service postgresql-x64-16
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c "SHOW wal_level; SHOW ssl; SHOW listen_addresses;"
```

`wal_level` must read `replica` and `ssl` must read `on`.

### 0.3 Firewall - one rule, one source

```powershell
New-NetFirewallRule -DisplayName "PostgreSQL replication from SPARE" `
  -Direction Inbound -Protocol TCP -LocalPort 5432 `
  -RemoteAddress SPARE_IP -Action Allow -Profile Any
```

Confirm from a **third** machine that port 5432 is closed. Do not take the rule's
existence as proof:

```powershell
Test-NetConnection -ComputerName PROD_IP -Port 5432   # must FAIL from anywhere except SPARE_IP
```

---

## Phase 1 - Backups on production

Nothing is backing production up today. This phase fixes that, and it is
independently valuable even if you never do Phases 2-3.

### 1.1 Install GnuPG on both VMs

Download Gpg4win from https://gpg4win.org and install on **production and the
spare VM**. Confirm:

```powershell
& 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --version
```

> If you cannot install software on production, stop and tell me - the fallback
> is 7-Zip AES-256, which puts the passphrase on a command line and is a real
> downgrade. Everything else in this handbook is unchanged.

### 1.2 Create the encryption keypair - on the SPARE VM, not production

This is the important part of the design: **production gets only the public
key**. It can encrypt backups but cannot decrypt them, so an attacker who owns
production cannot read the archives it produced.

On the **spare VM**:

```powershell
New-Item -ItemType Directory -Path C:\ProgramData\SOCBackup\gnupg -Force | Out-Null
$env:GNUPGHOME = 'C:\ProgramData\SOCBackup\gnupg'
& 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --full-generate-key
```

Choose: **RSA and RSA**, **4096** bits, no expiry, real name
`SOC Ticket Backup`, email `soc-backup@nt.local`. **Set a strong passphrase.**

Store the passphrase for unattended restore drills, and export the public key:

```powershell
# Passphrase file - readable only by Administrators and SYSTEM
Set-Content C:\ProgramData\SOCBackup\gpg-pass.txt -Value 'the-passphrase-you-chose' -NoNewline -Encoding ASCII
icacls C:\ProgramData\SOCBackup\gpg-pass.txt /inheritance:r /grant "Administrators:(F)" /grant "SYSTEM:(F)"

# Public key, to carry to production
& 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --armor --export soc-backup@nt.local > C:\Temp\soc-backup-public.asc

# Private key backup, to store OFFLINE
& 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --armor --export-secret-keys soc-backup@nt.local > C:\Temp\soc-backup-private.asc
```

> **Do this now, not later. Three copies, one off both VMs:**
>
> 1. The spare VM's `GNUPGHOME` (used by the automated restore drills).
> 2. The team password manager.
> 3. Offline storage - sealed envelope in the safe.
>
> Then delete `C:\Temp\soc-backup-private.asc`.
>
> **Test copy 3 before you trust it.** On a machine that is neither VM, import
> the offline private key into a scratch keyring and decrypt one archive:
>
> ```powershell
> $env:GNUPGHOME = 'C:\Temp\keytest'
> & 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --import soc-backup-private.asc
> & 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --output test.zip --decrypt <an-archive>.zip.gpg
> Remove-Item C:\Temp\keytest -Recurse -Force
> ```
>
> If the private key exists only on the spare VM and the spare VM is lost, every
> archive you own becomes an unopenable file. An untested offline copy is not
> meaningfully better. This is the difference between having backups and having
> encrypted garbage.

Copy `soc-backup-public.asc` to production and import it:

```powershell
# On PRODUCTION
New-Item -ItemType Directory -Path C:\ProgramData\SOCBackup\gnupg -Force | Out-Null
$env:GNUPGHOME = 'C:\ProgramData\SOCBackup\gnupg'
& 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --import C:\Temp\soc-backup-public.asc
& 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --list-keys
```

### 1.3 Create the backup service account and directories

On **production**:

```powershell
$pw = Read-Host -AsSecureString "Password for svc_socbackup"
New-LocalUser -Name svc_socbackup -Password $pw -PasswordNeverExpires -AccountNeverExpires `
  -Description "SOC Ticket backup job"
Add-LocalGroupMember -Group "Backup Operators" -Member svc_socbackup

New-Item -ItemType Directory -Path C:\SOCBackup\archive -Force | Out-Null
icacls C:\SOCBackup\archive /inheritance:r `
  /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /grant "svc_socbackup:(OI)(CI)M"
```

The account needs read access to `MEDIA_ROOT` and permission to run `pg_dump`.
Give it a database login and a pgpass file so no password appears in the script
or the task definition:

```powershell
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c `
  "CREATE ROLE soc_backup WITH LOGIN PASSWORD 'a-long-random-password' IN ROLE pg_read_all_data;"
```

The pgpass file must live in **svc_socbackup's** profile. Create it as that user:

```powershell
runas /user:svc_socbackup powershell.exe
# then, inside that shell:
New-Item -ItemType Directory -Path "$env:APPDATA\postgresql" -Force
Set-Content "$env:APPDATA\postgresql\pgpass.conf" -Value "localhost:5432:ticketdata:soc_backup:a-long-random-password" -Encoding ASCII
exit
```

### 1.4 Deploy the scripts and take the first backup

On production the scripts already exist inside the application checkout - use
them there rather than copying, so they never drift from the deployed release.
Still as an administrator:

```powershell
cd C:\SOCTicket\app\scripts\backup\windows
.\New-SocBackup.ps1 -Tier manual -GpgRecipient soc-backup@nt.local `
  -MediaRoot 'C:\SOCTicket\app\media' -BackupRoot 'C:\SOCBackup\archive' -DbUser soc_backup
```

Expect it to end with `backup: completed C:\SOCBackup\archive\soc_ticket_manual_....zip.gpg`.

```powershell
Get-ChildItem C:\SOCBackup\archive
```

You should see the `.zip.gpg` and its `.sha256`. **There must be no `.zip`** - if
a plaintext package survived, encryption failed and the script would have thrown;
investigate before continuing.

Record the archive size - that is `A` for §1.

### 1.5 Schedule the tiers

Run as `svc_socbackup`, with the password stored so the task runs whether anyone
is logged on or not.

```powershell
$cred = Get-Credential -UserName "$env:COMPUTERNAME\svc_socbackup" -Message "svc_socbackup password"
$script = 'C:\SOCTicket\app\scripts\backup\windows\New-SocBackup.ps1'
$common = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -GpgRecipient soc-backup@nt.local -MediaRoot `"C:\SOCTicket\app\media`" -BackupRoot `"C:\SOCBackup\archive`" -DbUser soc_backup"

$tiers = @(
  @{ Name='SOC-Backup-Daily';   Tier='daily';   Trigger=(New-ScheduledTaskTrigger -Daily -At 00:30) },
  @{ Name='SOC-Backup-Weekly';  Tier='weekly';  Trigger=(New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 01:30) },
  @{ Name='SOC-Backup-Monthly'; Tier='monthly'; Trigger=(New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 02:30) }
)
foreach ($t in $tiers) {
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "$common -Tier $($t.Tier)"
  Register-ScheduledTask -TaskName $t.Name -Action $action -Trigger $t.Trigger `
    -User $cred.UserName -Password $cred.GetNetworkCredential().Password `
    -RunLevel Highest -Description "SOC Ticket $($t.Tier) backup"
}
```

Add the hourly tier only if §1 sizing allows it:

```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "$common -Tier hourly"
Register-ScheduledTask -TaskName 'SOC-Backup-Hourly' -Action $action `
  -Trigger (New-ScheduledTaskTrigger -Once -At 00:05 -RepetitionInterval (New-TimeSpan -Hours 1)) `
  -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Highest
```

> **Monthly runs weekly on purpose.** Task Scheduler's monthly trigger is awkward
> to express here, and `New-SocBackup.ps1` prunes only the tier it writes, so an
> extra monthly archive costs one file and nothing else. Retention still keeps
> them for the monthly window.

Verify one runs end to end:

```powershell
Start-ScheduledTask -TaskName 'SOC-Backup-Daily'
Start-Sleep -Seconds 60
(Get-ScheduledTaskInfo -TaskName 'SOC-Backup-Daily').LastTaskResult   # 0 = success
Get-ChildItem C:\SOCBackup\archive | Sort-Object LastWriteTime -Descending | Select-Object -First 3
```

**`LastTaskResult` must be 0.** If it is `0x41303`, the task has never run. If it
is non-zero, run the script interactively as `svc_socbackup` to see the error.

### 1.6 Capture the configuration, not just the data

The archive holds the database and media. It does **not** hold what you need to
*rebuild the host*: `.env` (secret key, DB password, SMTP and OpenSearch
credentials), the IIS site and URL Rewrite/ARR rules, the Waitress service
definition, the scheduled tasks, the firewall rules, or `postgresql.conf` and
`pg_hba.conf`.

Without those, a total production loss means reconstructing the deployment from
memory during an incident. `New-SocConfigBundle.ps1` captures them into a
kilobyte-sized encrypted bundle that rides along with the archives.

```powershell
cd C:\SOCTicket\app\scripts\backup\windows
.\New-SocConfigBundle.ps1 -GpgRecipient soc-backup@nt.local `
  -EnvPath 'C:\SOCTicket\app\.env' -AppServiceName 'SOCTicketWaitress' `
  -ExtraFiles @('C:\SOCTicket\certs\opensearch-ca.pem',
                'C:\SOCTicket\app\run-prod.cmd',
                'C:\inetpub\socticket\web.config')
```

Inspect the manifest inside the bundle to confirm it actually caught your IIS
site and the app service - the script warns rather than fails if it cannot find
them, so a silent miss is possible if your service name differs.

> **Capture `run-prod.cmd` and `web.config` explicitly — the service definition is
> not enough.** The bundle records the Waitress *service* (its `PathName` is just
> `cmd /c C:\SOCTicket\app\run-prod.cmd`) but **not the contents of `run-prod.cmd`**,
> which is where the HTTPS go-live added the mandatory
> `--trusted-proxy=127.0.0.1 --trusted-proxy-headers="…"` flags (Stage 9.3).
> `run-prod.cmd` is now **tracked in the repo at the app root**, so a clean clone/rebuild
> already gets the proxy-trust flags; keeping it in `-ExtraFiles` is belt-and-suspenders
> for a host that has drifted from the repo. `web.config` (the `X-Forwarded-Proto` rule)
> is captured via `applicationHost.config` only partially — include it directly to be
> safe. Both were added to the live `SOC-Config-Bundle-Weekly` task on 2026-08-26.
>
> Note: a PROD box built before this file was tracked may hold an *untracked* identical
> `run-prod.cmd`; `git stash -u` (or delete it) before pulling, or git refuses to
> overwrite the untracked file.

Schedule it weekly, after the weekly data backup:

```powershell
Register-ScheduledTask -TaskName 'SOC-Config-Bundle' `
  -Action (New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\SOCTicket\app\scripts\backup\windows\New-SocConfigBundle.ps1`" -GpgRecipient soc-backup@nt.local -EnvPath `"C:\SOCTicket\app\.env`"") `
  -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 02:00) `
  -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Highest
```

> **Re-run it after any configuration change** - a new IIS rule, a changed
> `.env`, a new scheduled task. The weekly run limits how stale it can get, but
> it will happily capture a configuration you have since changed.
>
> The bundle contains `.env` in plaintext *inside* the encryption. It is
> encrypted to the same GPG recipient as the data archives, so production can
> write it but cannot read it back. Never store an unencrypted copy.

---

## Phase 2 - Off-host copy on the spare VM

### 2.1 The read-only share on production

Create the account the spare VM will authenticate as, and share the archive
**read-only**. The share permission is what makes this pull-only: even a fully
compromised spare VM cannot delete production's archives.

```powershell
# On PRODUCTION
$pw = Read-Host -AsSecureString "Password for svc_socpull"
New-LocalUser -Name svc_socpull -Password $pw -PasswordNeverExpires -AccountNeverExpires `
  -Description "Read-only archive pull for the spare VM"

New-SmbShare -Name 'SOCArchive$' -Path 'C:\SOCBackup\archive' -ReadAccess 'svc_socpull'
icacls C:\SOCBackup\archive /grant "svc_socpull:(OI)(CI)R"
Get-SmbShareAccess -Name 'SOCArchive$'
```

The `$` suffix hides the share from browsing. `-ReadAccess` grants Read at the
share level; the `icacls` line grants Read at the NTFS level. **Both** must be
read-only - NTFS Modify would let a compromised spare VM delete files regardless
of the share permission.

Allow SMB from the spare VM only:

```powershell
New-NetFirewallRule -DisplayName "SMB from SPARE (archive pull)" `
  -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress SPARE_IP -Action Allow
```

### 2.2 The pull account on the spare VM

```powershell
# On the SPARE VM
$pw = Read-Host -AsSecureString "Password for svc_socbackup"
New-LocalUser -Name svc_socbackup -Password $pw -PasswordNeverExpires -AccountNeverExpires

New-Item -ItemType Directory -Path D:\SOCBackup\archive -Force | Out-Null
New-Item -ItemType Directory -Path C:\ProgramData\SOCBackup -Force | Out-Null
icacls D:\SOCBackup /inheritance:r `
  /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" /grant "svc_socbackup:(OI)(CI)M"
```

Now store production's credential. **This must be done while logged on as
`svc_socbackup`** - the file is DPAPI-encrypted to that account on that machine
and cannot be decrypted by anyone else:

```powershell
runas /user:svc_socbackup powershell.exe
# inside that shell:
$c = Get-Credential -UserName "PROD_HOST\svc_socpull" -Message "svc_socpull password"
$c | Export-Clixml C:\ProgramData\SOCBackup\prod-cred.xml
exit
```

### 2.3 First pull

Copy `scripts\backup\windows\` to `C:\SOCTicket\scripts` on the spare VM, then,
as `svc_socbackup`:

```powershell
runas /user:svc_socbackup powershell.exe
cd C:\SOCTicket\scripts\backup\windows
.\Copy-SocArchive.ps1 -SourceUnc '\\PROD_HOST\SOCArchive$' -ArchiveDir 'D:\SOCBackup\archive'
```

Expect `pull: N archive(s) verified, 0 quarantined`.

**Now prove the restriction holds.** Still as `svc_socbackup`, all three must
behave as marked:

```powershell
# 1. Read works
Get-ChildItem '\\PROD_HOST\SOCArchive$'

# 2. Write is refused
'test' | Set-Content '\\PROD_HOST\SOCArchive$\writetest.txt'      # must FAIL

# 3. Delete is refused
Remove-Item '\\PROD_HOST\SOCArchive$\<some-archive>.sha256'       # must FAIL
```

If #2 or #3 succeeds, the share or NTFS permission is wrong. Fix it before
continuing - the pull-only property is the main security benefit of this design.

### 2.4 Schedule the pull, prune, and health check

```powershell
$cred = Get-Credential -UserName "$env:COMPUTERNAME\svc_socbackup" -Message "svc_socbackup password"
$dir  = 'C:\SOCTicket\scripts\backup\windows'

$tasks = @(
  @{ Name='SOC-Archive-Pull'
     Arg="-NoProfile -ExecutionPolicy Bypass -File `"$dir\Copy-SocArchive.ps1`" -SourceUnc `"\\PROD_HOST\SOCArchive$`" -ArchiveDir D:\SOCBackup\archive"
     Trigger=(New-ScheduledTaskTrigger -Once -At 00:20 -RepetitionInterval (New-TimeSpan -Hours 1)) },
  @{ Name='SOC-Archive-Prune'
     Arg="-NoProfile -ExecutionPolicy Bypass -File `"$dir\Remove-SocArchive.ps1`" -ArchiveDir D:\SOCBackup\archive -MaxArchiveGB 100"
     Trigger=(New-ScheduledTaskTrigger -Daily -At 03:20) },
  @{ Name='SOC-Archive-Check'
     Arg="-NoProfile -ExecutionPolicy Bypass -File `"$dir\Test-SocArchive.ps1`" -ArchiveDir D:\SOCBackup\archive -AlertEmail you@nt.local -SmtpServer smtp.nt.local"
     Trigger=(New-ScheduledTaskTrigger -Daily -At 07:00) }
)
```

> **As-built (this deployment).** The live `SOC-Archive-Check` runs against an
> **authenticated STARTTLS relay** and also checks the standby, so its argument
> string is:
>
> ```
> -ArchiveDir D:\SOCBackup\archive -CheckStandby -StandbyUser soc_backup
> -AlertEmail ntsoc@ntplc.co.th -SmtpServer mail.ntplc.co.th -SmtpPort 25 -UseSsl
> -MailFrom ntsoc@ntplc.co.th -SmtpCredentialPath C:\ProgramData\SOCBackup\smtp-cred.xml
> ```
>
> `-SmtpPort 25 -UseSsl` is opportunistic STARTTLS on the submission port;
> `-MailFrom` must equal an envelope sender the relay accepts (here it equals
> `-AlertEmail`). See §2.5 for the credential and the silent-send fix.

```powershell
foreach ($t in $tasks) {
  Register-ScheduledTask -TaskName $t.Name `
    -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $t.Arg) `
    -Trigger $t.Trigger -User $cred.UserName `
    -Password $cred.GetNetworkCredential().Password -RunLevel Highest
}
```

Set `-MaxArchiveGB` to the archive budget you calculated in §1.

> **The trap that silently breaks this.** In Task Scheduler, the task must be set
> to *"Run whether user is logged on or not"* **with the password stored** (which
> `Register-ScheduledTask -Password` does). If you later edit the task and tick
> *"Do not store password"*, Windows switches to an S4U logon, DPAPI keys become
> unavailable, and `Import-Clixml` fails with a decryption error - the pull stops
> and only the health check will tell you. Never tick that box on these tasks.

### 2.5 Make the alert real

The health check exits non-zero and mails `-AlertEmail`. Also make Task Scheduler
itself visible - a task that fails to *start* never reaches the script:

```powershell
# Confirm each task's last result is 0
Get-ScheduledTask -TaskName 'SOC-*' | Get-ScheduledTaskInfo |
  Select-Object TaskName, LastRunTime, LastTaskResult, NextRunTime
```

**Test the alert path by breaking something on purpose:**

```powershell
Rename-Item C:\ProgramData\SOCBackup\prod-cred.xml prod-cred.xml.bak
Start-ScheduledTask -TaskName 'SOC-Archive-Pull'      # must fail
Start-ScheduledTask -TaskName 'SOC-Archive-Check'     # must email you
Rename-Item C:\ProgramData\SOCBackup\prod-cred.xml.bak prod-cred.xml
```

Everything else in this system fails loudly. A broken alert path fails silently
and takes the rest of the system's trustworthiness with it. **Do not skip this.**

#### As-built — authenticated SMTP alerting (this deployment)

The alert path is **live and proven**, which retires the interim "named owner
reviews the check weekly" arrangement. Details, because the traps here are all
silent:

- **Relay + auth.** `mail.ntplc.co.th` on **port 25 with STARTTLS** (`-UseSsl`)
  and a login. The port is forced: **587 timed out** and **465 is implicit-TLS,
  which `Send-MailMessage` cannot speak** — 25 + STARTTLS is the only combination
  PowerShell can use. Both sender and recipient are `ntsoc@ntplc.co.th`; the relay
  **rejects a non-`@ntplc.co.th` From** (the old default `soc-backup@<host>` was
  refused as "failed to route the address"), so `-MailFrom` is mandatory.
  `Test-SocArchive.ps1` takes `-SmtpPort`, `-UseSsl`, `-MailFrom`, and
  `-SmtpCredentialPath` for exactly this.
- **Credential.** A `PSCredential` saved to `C:\ProgramData\SOCBackup\smtp-cred.xml`
  and loaded with `Import-Clixml`. `Export-Clixml` encrypts with **per-account
  DPAPI**, so the file was written **under the SYSTEM account** and only decrypts
  under the *same* account that runs `SOC-Archive-Check`. Export it as whatever
  account the task runs as, or `Import-Clixml` fails with a decryption error — the
  same S4U/DPAPI trap noted for `prod-cred.xml` in §2.4. The repo and config bundles
  hold the **path and role name only, never the password**.
- **The silent-send bug and its fix.** `Send-MailMessage` reports SMTP rejections
  as *non-terminating* errors, so a failed send left the check exiting `0` and
  looking healthy. `Test-SocArchive.ps1` now passes **`-ErrorAction Stop`** on the
  send, making a rejection terminating so the `try/catch` reports it. This was the
  fix that stopped alerts from silently not being sent.
- **Proof of delivery.** Forced a failure with **`-MinFreePercent 100`** (no drive
  can be 100% free, so the free-space check trips) and confirmed a
  **`[SOC-BACKUP] FAILED`** email arrived at `ntsoc@ntplc.co.th`. That exercised the
  full path — auth, STARTTLS, credential decrypt, terminating-error handling — not
  just the setting being present.

### 2.6 The restore-drill instance

A streaming standby is read-only for its entire life and **cannot** accept a
restore. So the spare VM needs a second, separate PostgreSQL instance for drills.
Build it now, before the standby exists.

Install the **same PostgreSQL major version as production** on the spare VM
(here: **18**), then create a scratch cluster on port 5434. **First read the real
locale off production** - do not assume it:

```powershell
# On PRODUCTION, as the read-only backup role (no superuser password needed)
$env:PGPASSFILE = 'C:\ProgramData\SOCBackup\pgpass.conf'
& 'C:\Program Files\PostgreSQL\18\bin\psql.exe' -h localhost -p 5432 -U soc_backup -d ticketdata_prod -X -x -c `
  "select pg_encoding_to_char(encoding) enc, datcollate, datctype, datlocprovider from pg_database where datname = 'ticketdata_prod';"
```

For this deployment that returns `UTF8 / Thai_Thailand.874 / Thai_Thailand.874 /
c` (libc provider). **The provider matters**: PostgreSQL 18 changed `initdb`'s
default locale provider, so an `initdb` that does not name it can silently come up
`builtin`/`C.UTF-8`, restore every table at the right row count, and still sort
and case-fold Thai differently from production. State it explicitly.

Create and lock the data directory (single **C:** volume on this spare; one
`icacls` target per line, grants first, no backtick continuations - see the empty-DACL
field note):

```powershell
New-Item -ItemType Directory -Path 'C:\PostgreSQL\verify' -Force | Out-Null
icacls 'C:\PostgreSQL' /grant 'NT AUTHORITY\NetworkService:(OI)(CI)(F)' /grant 'Administrators:(OI)(CI)(F)' /grant 'SYSTEM:(OI)(CI)(F)' /inheritance:r
icacls 'C:\PostgreSQL'   # read it back: path + three ACE lines = good; path with no ACE lines = empty DACL, STOP
```

**`initdb` refuses an administrative token on Windows, but `pg_ctl register`
*requires* one** (it creates a service). If your RDP shell runs elevated (the
built-in Administrator always does), run `initdb` **as the service account** via a
one-shot scheduled task - which also makes the data directory owned by the exact
account the service will run under - and keep `register` in the elevated shell:

```powershell
# De-elevate initdb by running it as NetworkService; -A trust = passphraseless,
# loopback-only (initdb writes host entries for 127.0.0.1/32 and ::1/128 only).
# No pwfile, no password on a command line - satisfies the no-plaintext-password rule.
$bin = 'C:\Program Files\PostgreSQL\18\bin'; $data = 'C:\PostgreSQL\verify'
$wrapper = 'C:\PostgreSQL\run-initdb.cmd'
@"
@echo off
"$bin\initdb.exe" -D "$data" -U postgres -E UTF8 --lc-collate=Thai_Thailand.874 --lc-ctype=Thai_Thailand.874 --locale-provider=libc -A trust 1> "C:\PostgreSQL\initdb.log" 2>&1
echo EXITCODE=%ERRORLEVEL%>> "C:\PostgreSQL\initdb.log"
"@ | Out-File $wrapper -Encoding ascii
$pr = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\NetworkService' -LogonType ServiceAccount -RunLevel Limited
Register-ScheduledTask -TaskName 'SOC-VerifyInitdb-TEMP' -Action (New-ScheduledTaskAction -Execute $wrapper) -Principal $pr -Force | Out-Null
Start-ScheduledTask -TaskName 'SOC-VerifyInitdb-TEMP'
do { Start-Sleep 2 } while ((Get-ScheduledTask -TaskName 'SOC-VerifyInitdb-TEMP').State -eq 'Running')
Get-Content 'C:\PostgreSQL\initdb.log'                              # must end EXITCODE=0
"PG_VERSION: " + (Get-Content "$data\PG_VERSION" -ErrorAction SilentlyContinue)   # the real proof
Unregister-ScheduledTask -TaskName 'SOC-VerifyInitdb-TEMP' -Confirm:$false; Remove-Item $wrapper -Force
```

Then register and start it on port 5434, **from the elevated shell**:

```powershell
& "$bin\pg_ctl.exe" register -N 'postgresql-verify' -U 'NT AUTHORITY\NetworkService' -D "$data" -S demand -o '-p 5434'
Start-Service postgresql-verify
# Prove the cluster's locale matches production BEFORE trusting any drill it runs:
& "$bin\psql.exe" -h localhost -p 5434 -U postgres -d postgres -X -c `
  "select datname, pg_encoding_to_char(encoding) enc, datcollate, datctype, datlocprovider from pg_database order by 1;"
```

All three of `template0` / `template1` / `postgres` must read `UTF8 /
Thai_Thailand.874 / Thai_Thailand.874 / c`. Because `Test-SocRestore.ps1` builds
its restore database `TEMPLATE template0` with the locale stated explicitly (and
reads it back), this is what makes a passing drill *mean* something.

> **Why `-A trust` and not a password.** `initdb` can only take a superuser
> password interactively or from a plaintext `--pwfile`; a scheduled drill would
> then also need that secret stored to reconnect. Trust scoped to loopback, on an
> instance that listens on localhost only, on a host whose firewall blocks
> inbound, thrown away each drill, is passwordless by construction. `-S demand`
> (manual start) keeps a cluster holding restored production data from listening
> 24/7; the weekly task starts it, drills, and stops it.
>
> PostgreSQL will **not** run under an administrator account on Windows - which is
> why `initdb` and the running server are de-elevated to NetworkService above.

### 2.7 Run the first drill

```powershell
# The scripts ship inside the repo checkout, so they live under \app\.
# Defaults are already correct for this deployment (PG18, C:\SOCBackup\archive,
# C:\Program Files\GnuPG\bin\gpg.exe, gpg-pass.txt) - do NOT pass -DbName/-DbUser:
# Test-SocRestore.ps1 has neither and restores into its own throwaway database.
cd C:\SOCTicket\app\scripts\backup\windows
.\Test-SocRestore.ps1 -VerifyPort 5434 -PassphraseFile C:\ProgramData\SOCBackup\gpg-pass.txt
```

Success ends with `restore-verify: backup is restorable` after a
`... - matches production` locale line and the row counts. A count mismatch,
checksum failure, or a locale that does **not** match production is a **real
incident**: the backup you were relying on is not sound, or the verify cluster was
built wrong. Investigate before trusting anything else here.

Schedule it weekly - starting the demand-start verify instance first and stopping
it after, so it is not left listening between drills:

```powershell
$drill = 'C:\SOCTicket\app\scripts\backup\windows\Test-SocRestore.ps1'
Register-ScheduledTask -TaskName 'SOC-Restore-Drill' `
  -Action (New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Start-Service postgresql-verify; & '$drill' -VerifyPort 5434 -PassphraseFile 'C:\ProgramData\SOCBackup\gpg-pass.txt'; Stop-Service postgresql-verify`"") `
  -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 04:00) `
  -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Highest
```

Weekly is the right cadence: often enough that a broken backup is caught inside
one retention window, rare enough that the cost is negligible. **After changing
the task, confirm `LogonType` reads `Password`** (`schtasks /create /f` and the
GUI both silently reset it to interactive - see the Task Scheduler field notes),
or the drill will never run.

> **After the first successful drill, this VM holds real ticket data, personal
> data, and evidence.** That is why §2.2 restricts the ACLs. Classify and treat
> the spare VM exactly as you treat production from this point on.

#### What the drill does NOT prove

A passing drill means the *data* restores. It does **not** mean the application
would work, because the archive is `pg_dump --no-owner --no-acl` of a **single
database**: cluster-global roles and their GRANTs are not in it.

At real recovery time the rows are all present and the app cannot log in,
because the `ticket` role does not exist on the new cluster. The drill cannot
catch this - it connects as `postgres` and only counts rows.

Two things follow:

1. §4.3 step 3 (recreate roles and grants) is **not optional**, and it is the
   step most likely to be skipped under pressure.
2. Once a year, run a *full* recovery rehearsal rather than a drill: restore,
   recreate the roles, point a real Django instance at it, and log in. That is
   the only test that exercises the whole path.

A full custom-format `pg_restore` carries sequence state, so a clean restore
needs no extra step. But if prod data ever arrives another way — a Django
`loaddata` fixture, a data-only/single-table load, or a cross-environment copy —
the id sequences stay parked below `MAX(id)` and reads keep working while the
next INSERT (closing a ticket) throws a duplicate-key 500. After any such load,
finish with `python manage.py check_sequences --fix` (idempotent; reports drift
and resets it). Observed once in production, 2026-09-03.

**Phase 2 is the stopping point that matters.** If you go no further, you have
verified off-host backups. Everything after this reduces downtime, not data loss.

#### Field notes from the first drill

Every one of these reported success while doing nothing useful, or failed for a
reason unrelated to what was being tested. They cost hours on the first build.

- **gpg-agent caches the passphrase and makes a passphrase-file test lie.** After
  any interactive decrypt, gpg-agent holds the unlocked key (~10 min default), so
  a `--passphrase-file` test moments later passes *from cache* regardless of the
  file's contents. **Kill the agent before validating the file** and again before
  the real drill: `gpgconf --kill gpg-agent`. Only a decrypt against a cold agent
  proves `gpg-pass.txt`.
- **`Read-Host -AsSecureString` captured exactly one character on this RDP
  console** - typed or pasted, every time - because its masked reader takes raw
  per-keystroke input the console does not deliver reliably. Plain `Read-Host`
  (line-buffered) worked fine. Fix: read the line with echo suppressed at the API
  layer (`SetConsoleMode` clearing `ENABLE_ECHO_INPUT`, then `[Console]::ReadLine()`),
  which uses the line-buffered path. Always print the captured **length** and
  compare it to the real passphrase before spending it - a length of 1 is the tell.
- **Write `gpg-pass.txt` with `[IO.File]::WriteAllText(..., ASCIIEncoding)`** - no
  BOM, no trailing newline. `--passphrase-file` reads the whole first line; a BOM
  or CR/LF changes the passphrase. Verify the first three bytes are not
  `239 187 191`.
- **PostgreSQL 18 changed `initdb`'s default locale provider.** Build the verify
  cluster with `--locale-provider=libc` explicitly (production here is `datlocprovider
  = c`). Otherwise it comes up builtin, restores every row correctly, and orders
  Thai text differently - a silent false pass. The drill now creates its restore DB
  `TEMPLATE template0` with encoding/collate/ctype/provider stated and **reads them
  back**, so a wrong cluster fails loudly instead.
- **`initdb` refuses an admin token; `pg_ctl register` needs one.** Only `initdb`
  and the running server must be non-admin - run `initdb` as NetworkService (a
  one-shot ServiceAccount scheduled task), keep `register` in the elevated shell.
  Prove the cluster by the `PG_VERSION` file and a live `SELECT datcollate`, not by
  the task's exit code.
- **Do not drive the spare from two sessions at once.** `gpg-pass.txt` reached an
  unknown state because two sessions wrote it blind to each other - the same
  collision class as the `svc_socpull` password resets. One session owns the host
  through a step.

The rule under all of these: a scheduled backup task inherits every one of these
silent-success traps. Validate the *artifact* (a decrypt against a cold agent, a
`PG_VERSION` file, a byte count, a locale readback), never the exit code alone.

### 2.8 Pre-stage the application stack on the spare VM

The "1-3 hour recovery" figure assumes restore time only. If the spare VM has no
Python, no IIS features, no URL Rewrite/ARR, and no virtualenv, a cold rebuild
during an outage is closer to a day - most of it spent downloading installers
while the SOC has no ticketing system.

Install the full stack now, **configured but stopped**:

1. IIS with URL Rewrite and ARR, same features as production.
2. Python, matching production's version.
3. The application from the same release tag, with its virtualenv built.
4. An IIS site and Waitress service definition mirroring production's, **set to
   Manual start and left stopped**.
5. A placeholder `.env` - the real values come from the config bundle at
   recovery time, so no production secret sits on this VM in advance.

Budget about 5 GB (already in the §1 sizing formula).

> **Keep it in step with production.** After each production release, update the
> spare VM's checkout to the same tag. A stale pre-staged stack that will not
> start is worse than none, because you find out during the incident. Add it to
> the deployment routine in Phase 5.

This converts DR from *install, restore, configure, start* into *restore,
repoint, start* - and makes the stated RTO real rather than aspirational.

---

## Phase 3 - Streaming standby

Only start this once Phase 2 is running and one drill has passed.

### 3.1 Replication role on production

```powershell
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c `
  "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'a-long-random-password';"
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c `
  "SELECT rolname, rolreplication FROM pg_roles WHERE rolname = 'replicator';"
```

Add **one** line to `pg_hba.conf` in production's data directory - `hostssl`, not
`host`, so an unencrypted replication connection is refused outright:

```
hostssl  replication  replicator  SPARE_IP/32  scram-sha-256
```

```powershell
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c "SELECT pg_reload_conf();"
```

Store that password only on the spare VM. Do not put it in `.env`, Git, or a
scheduled task.

### 3.2 Base backup onto the spare VM

```powershell
# On the SPARE VM, elevated
New-Item -ItemType Directory -Path D:\PostgreSQL\standby -Force | Out-Null
icacls D:\PostgreSQL\standby /inheritance:r `
  /grant "NT AUTHORITY\NetworkService:(OI)(CI)F" /grant "Administrators:(OI)(CI)F"

$env:PGPASSWORD = Read-Host "replicator password"
& 'C:\Program Files\PostgreSQL\16\bin\pg_basebackup.exe' `
  --host=PROD_IP --port=5432 --username=replicator `
  --pgdata=D:\PostgreSQL\standby --format=plain --wal-method=stream `
  --slot=soc_ticket_standby --create-slot --write-recovery-conf --progress
Remove-Item Env:\PGPASSWORD
```

The target directory must be **empty**. If this fails partway, delete its
contents before retrying.

`--write-recovery-conf` writes `postgresql.auto.conf` with `primary_conninfo` and
marks the cluster as a standby. Add the certificate trust and the password so it
can reconnect unattended - open `D:\PostgreSQL\standby\postgresql.auto.conf` and
ensure `primary_conninfo` contains `sslmode=verify-full` (or at minimum
`sslmode=require`) **and** `password=...`:

```ini
primary_conninfo = 'host=PROD_IP port=5432 user=replicator password=... sslmode=require application_name=soc_standby'
primary_slot_name = 'soc_ticket_standby'
```

Then lock the file down - it now contains a password:

```powershell
icacls D:\PostgreSQL\standby\postgresql.auto.conf /inheritance:r `
  /grant "NT AUTHORITY\NetworkService:(R)" /grant "Administrators:(F)"
```

### 3.3 Register and start the standby

```powershell
& 'C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe' register -N 'postgresql-standby' `
  -U 'NT AUTHORITY\NetworkService' -D 'D:\PostgreSQL\standby' -S auto -o '-p 5433'
Start-Service postgresql-standby

& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h localhost -p 5433 -U postgres -d postgres `
  -c "SELECT pg_is_in_recovery();"
```

**Must return `t`.** If it returns `f`, stop - you have an independent writable
database, not a standby, and it is already diverging.

On **production**, confirm the stream and the slot:

```powershell
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c `
  "SELECT application_name, client_addr, state, sync_state, replay_lag FROM pg_stat_replication;"
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c `
  "SELECT slot_name, active, pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal FROM pg_replication_slots;"
```

You need one row with `state = streaming`, the spare VM's address, and
`active = t`.

### 3.4 The restart test - do not skip

The most common silent failure is a standby that streams perfectly until its
first restart, then stops because it cannot re-authenticate.

```powershell
Restart-Service postgresql-standby
Start-Sleep -Seconds 20
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h localhost -p 5433 -U postgres -d postgres `
  -c "SELECT pg_is_in_recovery(), now() - pg_last_xact_replay_timestamp() AS replay_delay;"
```

`pg_is_in_recovery` must still be `t` and `replay_delay` must be small and
shrinking. Then re-check `pg_stat_replication` on production and confirm the row
came back. If it did not, `primary_conninfo` is missing the password.

### 3.5 Monitor it

Add the standby to the daily health check by editing the `SOC-Archive-Check`
task's arguments to include `-CheckStandby`. It will then also alert if the
standby stops streaming, falls behind, or - importantly - if
`pg_is_in_recovery()` ever becomes false, which means something promoted it and
it is silently diverging from production.

Watch the replication slot on production. `max_slot_wal_keep_size` (Phase 0.2)
caps the damage, but a standby that stays offline past that cap is **invalidated
and must be rebuilt** from §3.2. That is the intended trade: rebuild the standby
rather than fill production's disk.

### 3.6 Two things that silently invalidate the standby

**A PostgreSQL major-version upgrade.** Streaming replication requires *identical
major versions*. The moment you upgrade production from 18 to 19, the standby
stops replicating and cannot be repaired - it must be rebuilt from a fresh base
backup (§3.2) after the spare VM is upgraded to match. Plan any major upgrade as:
upgrade production -> upgrade the spare -> rebuild the standby -> re-verify. Put
it in the maintenance routine in Phase 5, because nothing in the system will warn
you in advance.

**Anything that promotes the standby.** If `pg_is_in_recovery()` becomes false
outside a deliberate failover, the standby has become an independent writable
database and is diverging from production - every minute after that widens the
gap. The `-CheckStandby` health check catches this daily. Treat it as an incident,
not a warning: the standby must be rebuilt, and you need to know what promoted it.

### 3.7 Field notes from the standby build

More silent-success traps, in the order they bit on the first build:

- **A prior blanket firewall Block rule beats your new Allow rule.** Stage 10's
  hardening leaves an enabled inbound **Block** on 5432 scoped to `Any`. Windows
  Firewall evaluates Block before Allow, so adding a narrow "allow the spare"
  rule does nothing - the spare's connection **times out** (silent drop), not
  "refused". Fix: `Disable-NetFirewallRule` the blanket 5432 block (default-deny
  plus your narrow Allow still closes it to everyone else); confirm with
  `Test-NetConnection <spare> -Port 5432` = `TcpTestSucceeded: True`. A
  `Get-NetFirewallPortFilter` join can miss program-scoped rules - list
  `Get-NetFirewallRule -Action Block -Enabled True` and map filters explicitly.
- **`replication=1` (physical) is mandatory when testing with psql, and it is NOT
  the same as `replication=database`.** The pg_hba `replication` keyword matches
  ONLY physical replication. `psql "... dbname=replication"` with no replication
  parameter opens an ordinary connection; `replication=database` opens a *logical*
  one. Neither matches a `hostssl replication` rule, and both produce the
  misleading `no pg_hba.conf entry ... database "replication"` - which looks like a
  rule or reload problem but is a wrong-connection-type problem. Use
  `replication=1`. `pg_basebackup` sets physical mode itself, so it always matches.
- **`pg_hba_file_rules` reads the file, not the running rules.** A rule can show
  there with `error` empty while the server still rejects it - do not conclude
  "reload failed, must restart" from a failing *connection test* alone. Confirm
  the connable path with the correct `replication=1` test before touching the
  server; the earlier `pg_reload_conf()` was almost certainly fine.
- **Match the replication password by SHA-256 fingerprint across both hosts.**
  Echo-suppressed entry hides typos, and the two 13-char values silently diverged
  once. Print `SHA256(pw)` (first 16 hex) on prod after `ALTER ROLE` and on the
  spare after writing the passfile; proceed only when they match. Postgres roles do
  **not** lock on failed auth, so `IDENTIFY_SYSTEM` is a free correctness probe -
  a `password authentication failed ... retrieved from file` there means pg_hba is
  already fine and only the passfile value is wrong.
- **The idle-primary lag false positive.** `-CheckStandby`'s time-based lag
  (`now() - pg_last_xact_replay_timestamp()`) grows without bound on a primary with
  no writes, so a perfectly caught-up standby fails the daily check on a not-yet-live
  system. `Test-SocArchive.ps1` now treats `pg_last_wal_receive_lsn() =
  pg_last_wal_replay_lsn()` (caught up) as healthy and only applies the time
  threshold when WAL is genuinely unreplayed.
- **The standby holds a full copy of production data.** From the first successful
  base backup, classify and ACL the spare exactly as production - same as the
  restore-drill note in §2.7.

---

## Phase 4 - Failover and disaster recovery

Rehearse this. An untested runbook is a wish.

### 4.1 Planned failover drill - quarterly

1. Announce a maintenance window. Stop writes:
   ```powershell
   Stop-Service SOCTicketWaitress    # your Waitress service name
   ```
2. Confirm `state = streaming` and replay lag within your RPO.
3. Stop production's database: `Stop-Service postgresql-x64-16`
4. **Promote the standby:**
   ```powershell
   & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h localhost -p 5433 -U postgres -d postgres `
     -c "SELECT pg_promote();"
   & 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -h localhost -p 5433 -U postgres -d postgres `
     -c "SELECT pg_is_in_recovery();"
   ```
   Must now return `f`.

   > Use `pg_promote()`, not `pg_ctl promote`. `pg_ctl` must run as the account
   > that owns the data directory; from an elevated shell it will refuse or fail
   > confusingly. `pg_promote()` runs inside the server and avoids the problem.

5. Point the app at the promoted database. In the app's `.env`:
   `DB_HOST=SPARE_IP` (or `localhost` if you are also running the app there),
   `DB_PORT=5433`. Restart the Waitress service. `CONN_MAX_AGE=300` means old
   pooled connections must be dropped by the restart.
6. Verify: log in, create a ticket, update it, upload an attachment, open an
   existing attachment.
7. Record the **actual** RPO and RTO. Keep the old primary stopped, then rebuild
   it as a fresh standby of the promoted server (§3.2, new slot name).

### 4.2 Emergency failover - production is gone

1. Stop the Waitress service if it is still reachable.
2. **Fence the old primary** - power it off or block its network. Never promote
   while the old primary might still accept writes; two writable databases
   diverge and you will lose data reconciling them.
3. Check the standby's replay position and logs; note the recovery point.
4. Promote as in §4.1 step 4.
5. Stand the app up on the spare VM: Python, virtualenv, repo, `.env` (with
   `DB_HOST=localhost`, `DB_PORT=5433`, correct `ALLOWED_HOSTS` and `SITE_URL`),
   TLS certificate, OpenSearch CA, then register Waitress as a service.
6. **Take an encrypted backup from the promoted database immediately.** You are
   running without any standby and, until the pull is re-pointed, without a
   current off-host copy.
7. Communicate the recovery point to the SOC team - tickets created in the gap
   are gone and need re-entering.

### 4.3 Recovery from archives - when the standby is unusable too

Use this if both databases are lost, or if the failure is logical (bad migration,
`DROP`, ransomware) and the standby faithfully replicated the damage.

1. Pick the newest archive from **before** the damage and verify it:
   ```powershell
   $a = 'D:\SOCBackup\archive\soc_ticket_daily_....zip.gpg'
   (Get-FileHash $a -Algorithm SHA256).Hash.ToLower()
   (Get-Content "$a.sha256" -First 1).Split(' ')[0]      # must match
   ```
2. Restore it into a real database (not the drill database):
   ```powershell
   .\Test-SocRestore.ps1 -ArchivePath $a -VerifyPort 5434 -RestoreDb ticketdata -KeepRestoredDb `
     -PassphraseFile C:\ProgramData\SOCBackup\gpg-pass.txt
   ```
   This verifies checksums and asserts counts as it goes.
3. **Recreate roles and grants - the step that is not in the archive.** The dump
   is `pg_dump --no-owner --no-acl` of a single database, so cluster-global roles
   and their GRANTs are **not** included. After restore the *data* is present but
   *access* is not - the restore looks like a complete success and the
   application still cannot connect:
   - Recreate the app role (`ticket`) with the password from `.env` (which comes
     from the config bundle, step 3a).
   - Recreate the backup role (`soc_backup`) so backups resume.
   - If Grafana or BI reads the `mart` schema, re-run
     [reporting-ro-setup.sql](reporting-ro-setup.sql) as a superuser.

   3a. **Restore the configuration bundle** (§1.6) to get `.env`, the IIS site
   and rewrite rules, the Waitress service definition, the scheduled tasks, and
   `postgresql.conf` / `pg_hba.conf`:
   ```powershell
   $env:GNUPGHOME = 'C:\ProgramData\SOCBackup\gnupg'
   $bundle = Get-ChildItem D:\SOCBackup\archive -Filter 'soc_ticket_config_*.zip.gpg' |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1
   & 'C:\Program Files (x86)\GnuPG\bin\gpg.exe' --batch --pinentry-mode loopback `
     --passphrase-file C:\ProgramData\SOCBackup\gpg-pass.txt `
     --output C:\Temp\config.zip --decrypt $bundle.FullName
   Expand-Archive C:\Temp\config.zip -DestinationPath C:\Temp\config
   ```
   Check `manifest.json` for what it contains, and its timestamp against when
   you last changed production's configuration.
4. Restore media: extract `media.zip` from the archive back into `MEDIA_ROOT`.
5. Rebuild reporting matviews: `python manage.py refresh_reporting`.
6. Repoint the app (`.env`: `DB_HOST`, `DB_PORT`, `ALLOWED_HOSTS`, `SITE_URL`),
   start the pre-staged IIS site and Waitress service (§2.8), then update DNS.
7. **Reconnect ingestion and fix the watermark.** Check `OPENSEARCH_*`
   reachability, then inspect `wazuh_ingest_ingestwatermark`. A restore rolls the
   watermark back to the archive's point in time, so the per-minute ingestion
   task will re-process everything since then - producing duplicate alerts - or,
   if you advance it too far, skip a window entirely. Decide deliberately which
   you prefer and set it before re-enabling the task, rather than letting it run
   and discovering the result afterwards.

---

## Phase 5 - Operational configuration and the update routine

This is step 9 of the deployment order: behaviour configured against a database
that already exists and is already protected. Do **not** merge it with step 3.

### 5.1 Before launch

- **Real email delivery.** Half the workflow is notifications; test that one
  actually arrives, not just that the setting is present.
- **Wazuh ingestion task, every minute**, with Task Scheduler set to *"Do not
  start a new instance"* if the prior run is still active. At under ~100
  qualifying Level-10+ alerts/day, one minute is comfortable.
- **The 90-day cleanup for non-ticket Wazuh alerts.** Ticket-linked and actively
  triaged alerts must be retained regardless of age. Test it against seeded data
  before pointing it at real alerts - a cleanup job that gets the exclusion wrong
  destroys evidence.

  > **Confirm the retention floor with compliance before setting 90 days.** The
  > Computer Crime Act's ≥90-day requirement is a *floor*, and deleting at exactly
  > 90 leaves no margin for a late request. Establish which system is the record
  > of retention for that obligation - the Wazuh Indexer with its own retention,
  > or this application's alert table. If it is this application, set the cleanup
  > to ~100 days. Either way, note that the monthly archive tier preserves alerts
  > for a year, but retrieving a specific one then requires a full restore -
  > document that as the retrieval path rather than discovering it under a
  > deadline. This is decision #3 in
  > [backup-storage-decision-brief.md](backup-storage-decision-brief.md).

- **CSV historical import - last, and dry-run first.** Use the importer's
  dry-run mode against an approved field mapping. Confirm specifically how
  `Closed Date` should map; the current importer may not consume it directly.
  Import after the first verified backup, never before, so a bad mapping is
  recoverable.

### 5.2 Updating production after launch

1. Develop and test in UAT.
2. Cut a fixed release tag.
3. **Take a backup and confirm it completed** - check for the `.zip.gpg` and its
   `.sha256`, not just that the task exited 0.
4. Deploy during a planned maintenance window.
5. Run migrations only when needed. The pre-deployment backup matters most here:
   **the standby replicates a bad migration within seconds**, so it is not a
   recovery path for this failure mode. The archive is.
6. Smoke-test production.
7. Roll back code, or restore from the backup, if needed.
8. **Update the pre-staged stack on the spare VM to the same release tag** (§2.8),
   and re-run `New-SocConfigBundle.ps1` if any configuration changed.

### 5.3 Recurring maintenance

| Cadence | Task |
|---|---|
| Daily | Health-check alert reviewed (automated; confirm it is being read) |
| Weekly | Restore drill result checked; config bundle produced |
| Quarterly | Failover drill (§4.1); re-measure `D` and `A` against the §1 budget |
| Yearly | **Full recovery rehearsal** - restore, recreate roles, log in to a real Django instance |
| On PG major upgrade | Upgrade prod -> upgrade spare -> rebuild standby -> re-verify (§3.6) |

---

## 6. Go-live checklist

> **Status 2026-09-02:** Phases 1-3 are built and proven - nightly encrypted
> archives, hourly off-host pull, a **passed restore drill** (2026-08-24, weekly),
> and a **streaming standby** (reboot-survival verified), with the app stack
> pre-staged on the spare. Boxes below are ticked accordingly. The **three
> remaining launch gates** are: the **offline GPG private-key test**, the
> **planned failover rehearsal**, and the **separate-physical-host / shared-SAN
> question** to infrastructure. Items left unticked are genuinely open or
> unverified, not merely un-updated.

**Foundations**
- [ ] Spare VM disk size **confirmed** (120 vs 150 GB resolved) and written into §2
- [ ] `D` and `A` measured; retention and `-MaxArchiveGB` chosen from the §1 table
- [ ] PostgreSQL major version identical on production and spare, with a verified Windows patch path
- [ ] Separate physical host confirmed - or the limitation recorded in writing

**Phase 0-1 - production**
- [x] `wal_level=replica`, `ssl=on`, `listen_addresses`, `max_slot_wal_keep_size` set and verified after restart
- [ ] Port 5432 confirmed **closed** from a third machine
- [ ] GPG public key imported on prod; private key in **three** places *(public key on prod done; three-places storage tied to the offline-key gate below)*
- [ ] **Offline private key tested** - a decrypt performed on a machine that is neither VM  ← **OPEN launch gate**
- [x] `New-SocBackup.ps1` produces a `.zip.gpg` with a `.sha256` and no leftover `.zip`
- [x] Backup tasks scheduled; `LastTaskResult` is 0 for each
- [ ] `New-SocConfigBundle.ps1` run and scheduled; manifest inspected and contains IIS config, `.env`, and the app service

**Phase 2 - spare VM**
- [x] Share is read-only at **both** share and NTFS level
- [x] All three tests in §2.3 behave as marked (read works, write refused, delete refused)
- [x] Pull, prune, and check tasks scheduled with **stored passwords**, not S4U
- [x] `-MaxArchiveGB` set to the archive budget
- [x] **Alert path tested by deliberately breaking something** — proven via
  `-MinFreePercent 100`; a `[SOC-BACKUP] FAILED` email arrived over the
  authenticated STARTTLS relay (§2.5 as-built)
- [x] Verify instance running on 5434; one restore drill passed *(2026-08-24)*
- [x] Weekly drill scheduled *(`SOC-Restore-Drill`)*
- [x] **App stack pre-staged on the spare VM** (§2.8), configured and stopped
- [ ] Role/grant recreation steps (§4.3 step 3) written down where someone else can find them

**Phase 3 - standby**
- [x] Same PostgreSQL major version on both VMs *(PostgreSQL 18)*
- [x] `pg_hba.conf` uses `hostssl`, restricted to `SPARE_IP/32`
- [x] `pg_is_in_recovery()` returns `t`; `pg_stat_replication` shows `streaming`
- [x] **Restart test passed** - standby resumes streaming after a service restart
- [x] Health check running with `-CheckStandby` (and now with authenticated SMTP
  alerting — §2.5 as-built)

**Phase 4-5 and launch gates**
- [ ] Planned failover drill completed end to end at least once
- [ ] Actual RPO and RTO recorded (measured, not estimated)
- [ ] Someone other than you has read §4.2 and knows where the GPG passphrase lives
- [x] **Backup-alert** email delivery tested — a `[SOC-BACKUP] FAILED` alert
  actually arrived (§2.5 as-built). *App* notification email is live too (Track B
  HTTPS go-live, 465 + implicit SSL — deployment runbook Stage 13).
- [ ] Wazuh ingestion task set to *"Do not start a new instance"*
- [ ] 90-day cleanup tested against seeded data; ticket-linked alerts confirmed retained
- [ ] Retention floor confirmed with compliance (§5.1)
- [ ] CSV import deferred until after the first verified backup, dry-run first
- [ ] Production smoke test passed
- [ ] Rollback release identified and its backup verified
- [ ] Supervisor approval for go-live

> **The RTO decision.** Phase 2 alone supports a 1-3 hour recovery *provided
> §2.8 is done*. If the business needs 15-30 minutes, Phase 3 must be complete
> and its failover drill passed before launch - not scheduled for after.

---

## 7. What this still does not close

For the governance conversation - see
[backup-storage-decision-brief.md](backup-storage-decision-brief.md):

| Decision brief item | After this build |
|---|---|
| #1 Storage location - warm | **Closed** (spare VM) |
| #1 Storage location - cold/DR | **Open** - needs a second site or object storage |
| #2 Data residency | Both VMs in Thailand; confirm with DPO |
| #3 Retention periods | Set in the prune task; **needs compliance sign-off** |
| #4 CII designation / NCSA code | **Open** - unaffected by this work |
| #5 Immutability | **Partial** - pull model + read-only share is not object-lock |
| #5 Key management | Improved (GPG, private key off production); a KMS is still the standard |
| #6 Redundant storage under both VMs | **Open** - infrastructure question |

---

## 8. Related

- [backup-storage-decision-brief.md](backup-storage-decision-brief.md) - the governance ask
- [production-deployment.windows.md](production-deployment.windows.md) - **steps 2-3 of the deployment order**: building the production VM
- [production-deployment.md](../archive/production-deployment.md) - **superseded**; Docker/Linux only
- [../architecture/data-infrastructure.md](../architecture/data-infrastructure.md) - the whole data picture
- [backup-and-restore.md](backup-and-restore.md) - **Docker/Linux variant; does not apply to this deployment**
