# Production Deployment — Windows Server

> **Audience:** whoever builds the production VM · **Status:** Current · **Last updated:** 2026-07-27
> **Applies to:** Windows Server + native PostgreSQL + Waitress + IIS — **the actual production platform**
> **Supersedes** [production-deployment.md](production-deployment.md) (Docker/nginx/gunicorn — Linux only)

This runbook is **steps 2 and 3** of the deployment order in
[backup-and-standby-handbook.windows.md §2](backup-and-standby-handbook.windows.md#where-this-fits-in-the-deployment-order):
build the VM, then create the database, secrets, superuser, and the Waitress
service. The handbook owns everything from step 4 (PostgreSQL replication
prerequisites) onward. Neither document repeats the other.

**Where you stop.** This runbook ends at a production VM that works, reachable
**only from the VM itself**. It does not go live. Users get nothing, the LAN
gets nothing, Wazuh ingestion stays off, no data is imported. Go-live gates live
in [handbook §6](backup-and-standby-handbook.windows.md#6-go-live-checklist).

---

## Canonical paths and names

The backup scripts and the handbook already hardcode these as defaults. Use them
unless you have a reason not to — every deviation is something you must
remember to pass as a parameter later.

| Thing | Value |
|---|---|
| Application root | `C:\SOCTicket\app` (the git checkout) |
| Backup scripts | `C:\SOCTicket\app\scripts\backup\windows` |
| Virtualenv | `C:\SOCTicket\app\venv` |
| `.env` | `C:\SOCTicket\app\.env` |
| `MEDIA_ROOT` | `C:\SOCTicket\app\media` |
| Logs | `C:\SOCTicket\logs` |
| Archive output | `C:\SOCBackup\archive` |
| Database / role | `ticketdata` / `ticket` — **the first production build used `ticketdata_prod` / `ticket_prod`; see the deviation note below** |
| App service name | `SOCTicketWaitress` |
| Scheduled task prefix | `SOC-*` |
| Firewall rule pattern | `*SOC*` |

> Handbook §1.6 shows `cd C:\SOCTicket\scripts\backup\windows`. That path is
> wrong — the scripts ship inside the repo, so they land at
> `C:\SOCTicket\app\scripts\backup\windows`. The script *defaults*
> (`MediaRoot = C:\SOCTicket\app\media`) assume the layout in this table.

> ### ⚠ Deployed deviation — now folded into the script defaults
>
> The first production build created the database as **`ticketdata_prod`** owned
> by **`ticket_prod`**, not the canonical names above; PostgreSQL is **18**, not
> 16; Gpg4win 5.x is 64-bit; and the spare VM has a single **C:** volume.
>
> **The script defaults have been corrected in-repo for all of these.** As of
> this build the deployed values are the defaults:
>
> ```
> New-SocBackup.ps1:   $PgBinPath = 'C:\Program Files\PostgreSQL\18\bin'
>                      $DbName    = 'ticketdata_prod'
>                      $DbUser    = 'soc_backup'      # read-only backup role
>                      $GpgExe    = 'C:\Program Files\GnuPG\bin\gpg.exe'
> Test-SocRestore.ps1: $PgBinPath  = 'C:\Program Files\PostgreSQL\18\bin'
>                      $ArchiveDir = 'C:\SOCBackup\archive'
>                      $GpgExe     = 'C:\Program Files\GnuPG\bin\gpg.exe'
> ```
>
> **Do not pass `-DbName` or `-DbUser` to `Test-SocRestore.ps1`.** It has neither
> parameter — it restores into its own throwaway `ticketdata_restoretest` and
> connects as `-VerifyUser`. Passing them fails the command outright.
>
> Verify the defaults rather than trusting this table; a restore drill that
> silently targets the wrong database name is the worst possible place to
> discover a drift between the two.

---

## Stage 0 — Start these before you touch the VM

Each of these sits in someone else's queue. Filing them on day 1 costs nothing
and they are the most likely cause of a delayed go-live.

- [ ] **Internal DNS A record** for the final hostname → `PROD_IP`. You will not
      enable it yet, but the request takes days.
- [ ] **TLS certificate** for that hostname from corporate PKI.
- [ ] **SMTP relay**: host, port, from-address, and `PROD_IP` allowlisted.
      Half the workflow is email notification.
- [ ] **Confirm the spare VM is on a different physical host / SAN.** If it is
      not, this is a warm tier, not DR — write that down
      ([handbook §0](backup-and-standby-handbook.windows.md#0-read-this-first)).
- [ ] **Confirm the PostgreSQL major version has a maintained Windows patch
      path** before standardising on it. Production and standby must match
      ([handbook §2](backup-and-standby-handbook.windows.md#postgresql-version-and-paths)).
- [ ] **Fill in the handbook §2 table** — IPs, versions, paths, service accounts.

Release prerequisites — **all now in the repo**, no longer hand-fixed on the server:

- [x] **Waitress pinned in `requirements.txt`** (`waitress==3.0.2`); `gunicorn`
      removed. It does not run on Windows.
- [x] **Wazuh retention command written** —
      `apps/wazuh_ingest/management/commands/purge_wazuh_alerts.py`. Building it
      is done; *running* it on production is still a go-live gate and needs a
      retention period agreed with compliance.
- [x] **`LOGGING` config** in `config/settings.py`, writing a rotating
      `django.log` to `LOG_DIR`.
- [x] **`/healthz`** — returns DB reachability plus `APP_VERSION`, 503 when the
      database is unreachable.

Set `LOG_DIR=C:\SOCTicket\logs` in the server `.env`. It **must** be outside
`C:\SOCTicket\app`: Stage 3 makes the app tree read-execute only for the service
account, so the default (`<BASE_DIR>/logs`) leaves `RotatingFileHandler` unable
to open its file and settings import fails at service start.

---

## Stage 1 — OS baseline

```powershell
# 1.1 Patch to clean, then reboot. Repeat until nothing is pending.
Install-Module PSWindowsUpdate -Force -Scope AllUsers   # if not present
Get-WindowsUpdate -Install -AcceptAll -AutoReboot
```

```powershell
# 1.2 Record the IP and confirm it is static. Write it into handbook §2.
Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway
Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress, PrefixOrigin
#   PrefixOrigin must be 'Manual', not 'Dhcp'.
```

```powershell
# 1.3 Timezone — this matters more than it looks.
Set-TimeZone -Id 'SE Asia Standard Time'    # UTC+7, Bangkok
Get-TimeZone
w32tm /query /status
```

The app runs `TIME_ZONE = 'Asia/Bangkok'` with `USE_TZ=True`. Task Scheduler
fires on **local** time, so OLA clocks, the nightly reporting snapshot, and the
backup tiers all depend on this being right. A drifting clock also corrupts OLA
breach calculations silently.

```powershell
# 1.4 Storage — record volumes and free space into handbook §1/§2.
Get-Volume | Select-Object DriveLetter, FileSystemLabel, `
    @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}}, `
    @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}}
```

> **RAID is not a backup.** It survives a disk failure. It does not survive a
> bad migration, a `DROP TABLE`, ransomware, or a deleted VM — all of which
> replicate to every disk in the array instantly. The backup phases are not
> optional because the storage is redundant.

**Service accounts.** Create these now; several stages need them:

| Account | Purpose | Notes |
|---|---|---|
| PostgreSQL service account | Runs the DB | Set by the installer. PostgreSQL on Windows **refuses to start under an administrator account** — expect `NT AUTHORITY\NetworkService` |
| App service account | Runs Waitress | Dedicated, low-privilege, non-admin. **Do not use LocalSystem** — UAT did, do not carry it forward |
| Backup service account | Handbook Phase 1.3 | Created later, by the handbook |

---

## Stage 2 — Install the software

Install everything in one change window. Gpg4win is not needed until handbook
Phase 1, but installing it now saves a second window.

**2.1 Git** — default options, no shell integration needed.

**2.2 Python — pin the exact minor version.** Development runs **3.14.4**.
Install the same `3.14.x` on production. "A supported Python" is too loose;
a minor-version gap between dev and prod is a classic source of bugs that only
appear in production.

- Install **for all users**, to `C:\Python314`.
- Do **not** add it to the system PATH. Call the interpreter by full path so
  there is never ambiguity about which Python a scheduled task used.

> ### "For all users" is not a preference. It is the whole thing.
>
> A per-user install lands in `C:\Users\<you>\AppData\Local\Programs\Python\`.
> A virtualenv built from it records that path in `pyvenv.cfg`, and
> `venv\Scripts\python.exe` is only a redirector to it. `svc_socticket` cannot
> read another account's profile, so the service dies in milliseconds with
>
> ```
> did not find executable at 'C:\Users\...\python.exe': Access is denied.
> ```
>
> and NSSM parks the service at `Paused`. It works perfectly when *you* run it
> and fails only as a service, which is what makes it expensive to diagnose.
> This cost two days on the first build.
>
> **Worse:** if a per-user install of the same version already exists, running
> the installer again with `InstallAllUsers=1` is treated as a *modify*. It
> honours `TargetDir` and copies only the executables, leaving `C:\Python314`
> with `python.exe` and no `Lib\`. Python then silently borrows the standard
> library from the profile and you are back where you started, with a
> `Could not find platform independent libraries <prefix>` warning as the only
> hint. **Uninstall any existing Python first**, then install once.

Silent install:

```powershell
Start-Process -FilePath .\python-3.14.7-amd64.exe -Wait -ArgumentList @(
  '/quiet','InstallAllUsers=1','TargetDir=C:\Python314',
  'PrependPath=0','AssociateFiles=0','Shortcuts=0',
  'Include_launcher=1','Include_test=0','Include_doc=0'
)
```

Verify all four, not just the version:

```powershell
& 'C:\Python314\python.exe' --version                      # must match dev exactly
Test-Path 'C:\Python314\Lib\os.py'                         # True — stdlib present
(Get-ChildItem 'C:\Python314\Lib' | Measure-Object).Count  # a few hundred, not 0
& 'C:\Python314\python.exe' -c "import sys; print(sys.base_prefix); print([p for p in sys.path if 'Users' in p])"
#   base_prefix must be C:\Python314 and the list must be empty.
```

**2.3 PostgreSQL** — same major version as the spare VM will run.

- Record the **encoding** and **locale** you install with. The restore-drill
  instance in handbook Phase 2.6 must match them or `pg_restore` fails.
- Use `UTF8`.
- Record the service name and the service account (`StartName`).

```powershell
$PgBin = 'C:\Program Files\PostgreSQL\18\bin'   # match what you installed
& "$PgBin\psql.exe" -U postgres -c "SHOW server_version; SHOW server_encoding; SHOW lc_collate;"
Get-CimInstance Win32_Service -Filter "Name LIKE 'postgresql%'" |
    Select-Object Name, StartName, State
```

**2.4 Apply the replication prerequisites NOW.**
Go to [handbook Phase 0.2](backup-and-standby-handbook.windows.md#02-settings-needed-by-both-phases)
and set `wal_level`, `listen_addresses`, `max_wal_senders`,
`max_replication_slots`, `max_slot_wal_keep_size`, and `ssl` — plus generate the
server certificate. **These require a database restart.** Setting them at
install time means you never take a maintenance window for them later. Then
return here.

Do **not** apply handbook Phase 0.3 (the firewall rule for `SPARE_IP`) yet — it
opens 5432 to another host, and nothing needs that until Phase 3.

**2.5 IIS with URL Rewrite and ARR**

```powershell
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name Web-Http-Redirect, Web-Http-Logging, Web-Stat-Compression
```

Then install, in this order — ARR's installer depends on URL Rewrite:
1. **URL Rewrite 2.1**
2. **Application Request Routing 3.0**

**2.6 Gpg4win** — needed by handbook Phase 1. Install now, configure later.

---

## Stage 3 — Code and virtualenv

```powershell
New-Item -ItemType Directory -Path C:\SOCTicket -Force
git clone https://github.com/Getter939/SOC_Ticket.git C:\SOCTicket\app
Set-Location C:\SOCTicket\app
git checkout <release-tag>
git rev-parse HEAD        # RECORD THIS. It is what you smoke-tested.
```

> **The release tension.** "Final approved release" is a go-live gate, but you
> need code now to build the VM. Resolve it explicitly: check out a named tag
> for the build, record the SHA, and schedule a deliberate re-pull and re-verify
> at go-live. Do not leave it ambiguous which code is deployed.

Confirm Waitress is pinned before building the venv:

```powershell
Select-String -Path requirements.txt -Pattern 'waitress|gunicorn'
#   Expect a pinned waitress==X.Y.Z and NO active gunicorn line.
```

```powershell
& 'C:\Python314\python.exe' -m venv C:\SOCTicket\app\venv
& C:\SOCTicket\app\venv\Scripts\python.exe -m pip install --upgrade pip
& C:\SOCTicket\app\venv\Scripts\python.exe -m pip install -r requirements.txt
& C:\SOCTicket\app\venv\Scripts\python.exe -m pip freeze > C:\SOCTicket\logs\pip-freeze-deploy.txt
```

Lock down the tree — the app account reads code, writes only `media` and `logs`:

> ### Three rules for `icacls`, each learned the hard way
>
> 1. **Never use backtick line continuations.** If one breaks, PowerShell runs
>    `icacls <path> /inheritance:r` on its own — which strips every inherited
>    ACE and grants nothing. The result is an **empty DACL**: no access for
>    anyone, propagated to every child, and even an elevated Administrator can
>    no longer read the files. One command per line.
> 2. **Grants before `/inheritance:r`, one target per command**, and read the
>    listing after each. *A listing that prints the path and no ACE lines is an
>    empty DACL — stop immediately.* `icacls` prints
>    "Successfully processed 1 files" either way, so its exit message proves
>    nothing.
> 3. **`/remove:g` cannot remove an inherited ACE.** It reports success and the
>    ACE stays. Removing inherited `BUILTIN\Users` requires `/inheritance:r`.
>
> Recovery from an empty DACL: `icacls <path> /reset /T /C /Q` restores
> inheritance from the parent. Only run it if the service actually fails —
> running it after a *successful* change silently undoes the hardening.

Well-known SIDs avoid locale and renamed-account surprises: `*S-1-5-32-544` is
Administrators, `*S-1-5-18` is SYSTEM.

```powershell
New-Item -ItemType Directory -Path C:\SOCTicket\logs -Force
$svc = "$env:COMPUTERNAME\svc_socticket"   # or DOMAIN\svc_socticket
```

Confirm the name resolves *before* granting anything — an unresolvable name is
how a bogus `BUILTIN\BUILTIN` ACE ended up on the logs directory on the first
build:

```powershell
(New-Object System.Security.Principal.NTAccount($svc)).Translate([System.Security.Principal.SecurityIdentifier]).Value
```

Then, one at a time, checking the listing after each:

```powershell
icacls 'C:\SOCTicket\app' /grant:r "${svc}:(OI)(CI)(RX)" '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' /inheritance:r
icacls 'C:\SOCTicket\app'
```

```powershell
icacls 'C:\SOCTicket\app\media' /grant:r "${svc}:(OI)(CI)(M)" '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' /inheritance:r
icacls 'C:\SOCTicket\app\media'
```

```powershell
icacls 'C:\SOCTicket\logs' /grant:r "${svc}:(OI)(CI)(M)" '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' /inheritance:r
icacls 'C:\SOCTicket\logs'
```

```powershell
icacls 'C:\Python314' /grant:r "${svc}:(OI)(CI)(RX)" '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-18:(OI)(CI)(F)' /inheritance:r
icacls 'C:\Python314'
```

`C:\Python314` matters as much as the app tree: it inherits `C:\` defaults, so
without this any local user can write into the directory the service executes
its interpreter from. Note this also removes `Users` access, so `svc_socbackup`
and `svc_socpull` lose Python — they don't need it, but remember it if a future
scheduled task does.

`.env` is done in Stage 5, after it exists.

---

## Stage 4 — Database and role

```powershell
$PgBin = 'C:\Program Files\PostgreSQL\18\bin'
& "$PgBin\psql.exe" -U postgres
```

```sql
CREATE ROLE ticket WITH LOGIN PASSWORD 'a-long-random-password';
CREATE DATABASE ticketdata OWNER ticket ENCODING 'UTF8';
\c ticketdata
GRANT ALL ON SCHEMA public TO ticket;
\q
```

**Why `ticket` owns the database:** the reporting layer's migrations create a
`mart` schema. Ownership is the simplest way to grant that without a second
round of privilege debugging later. The read-only `reporting_ro` role for
Grafana is created separately, at reporting Phase 4 — see
[reporting-ro-setup.sql](reporting-ro-setup.sql). Do not create it now.

Confirm the app can connect, and that nothing else can:

```powershell
& "$PgBin\psql.exe" -U ticket -h localhost -d ticketdata -c "SELECT current_user, current_database();"
```

---

## Stage 5 — `.env` and the secret key

Generate a real secret key — never reuse dev's, never invent one by hand:

```powershell
& C:\SOCTicket\app\venv\Scripts\python.exe -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Create `C:\SOCTicket\app\.env`. **Do not copy `.env.example` verbatim** — it is
written for the Docker stack and contains Linux paths, a `web` hostname, and
backup variables the PowerShell scripts do not read.

```ini
SECRET_KEY='<the generated key>'
DEBUG=False

# VM-local only for now. The DNS hostname is added at go-live, not before.
ALLOWED_HOSTS=localhost,127.0.0.1,PROD_HOSTNAME

# HTTPS: ALL OFF until the certificate is installed and bound. See Stage 13.
SESSION_COOKIE_SECURE=False
CSRF_COOKIE_SECURE=False
SECURE_SSL_REDIRECT=False
SECURE_HSTS_SECONDS=0
PASSWORD_RESET_USE_HTTPS=False
USE_PROXY_SSL_HEADER=True
TRUST_X_FORWARDED_FOR=True

DB_NAME=ticketdata
DB_USER=ticket
DB_PASSWORD='<the role password>'
DB_HOST=localhost
DB_PORT=5432
DB_CONN_MAX_AGE=300
DB_SSLMODE=prefer

# Email — real SMTP if the relay is ready; console backend if it is not.
# Do NOT leave a half-configured SMTP host: a 10s timeout on every ticket
# write is worse than no email.
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
EMAIL_HOST=
EMAIL_PORT=587
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=SOC Notifications <noreply@example.com>

# Rewritten to the DNS hostname at go-live. Embedded in every notification link.
SITE_URL=http://localhost:8000

# Wazuh ingestion stays OFF. Left blank deliberately.
OPENSEARCH_HOST=
OPENSEARCH_PORT=9200
OPENSEARCH_USER=
OPENSEARCH_PASSWORD=
OPENSEARCH_VERIFY_SSL=True
```

`USE_PROXY_SSL_HEADER=True` is safe to set now: it only takes effect when IIS
sends `X-Forwarded-Proto: https`, which it will not until Stage 13.

Lock the file — it holds the secret key, the DB password, and later the SMTP
and OpenSearch credentials:

```powershell
icacls C:\SOCTicket\app\.env /inheritance:r `
  /grant "Administrators:F" /grant "SYSTEM:F" /grant "NT_DOMAIN\svc_socticket:R"
```

---

## Stage 6 — Migrate, collect static, create the superuser

```powershell
Set-Location C:\SOCTicket\app
$py = 'C:\SOCTicket\app\venv\Scripts\python.exe'

& $py manage.py migrate
& $py manage.py collectstatic --noinput
& $py manage.py createsuperuser
```

**`collectstatic` is not optional.** With `DEBUG=False`, WhiteNoise serves from
`STATIC_ROOT`. Skip this and every page renders unstyled — which people
misdiagnose as an IIS problem for an hour.

**The superuser is what you smoke-test with.** Without it you have a working
server and no way to log in.

> ### Never run a seeder on production
>
> `seed_all`, `seed_data`, `seed_uat_states`, `seed_dashboard_mockup`,
> `seed_ceo_demo`, `seed_response_demo`, `seed_ola_demo_buckets`.
>
> `seed_all` **purges user accounts** matching legacy prefixes. On production
> that is data loss, not test setup. The production database stays empty until
> real tickets arrive.

---

## Stage 7 — Logging

Confirm the release contains a `LOGGING` block in `config/settings.py` writing
to `C:\SOCTicket\logs`. If it does not, **add it to the release and redeploy** —
do not hand-edit `settings.py` on the server, or the next `git pull` silently
reverts it and the config bundle captures a file that does not match the repo.

Two separate log paths, both needed:

| Path | What it captures |
|---|---|
| Django `LOGGING` handler | Application exceptions, warnings, audit events |
| Waitress stdout/stderr redirect (Stage 8) | Startup failures, worker crashes, anything before Django initialises |

A Windows service discards stdout unless you redirect it. Without the second
path, a Waitress process that dies on startup leaves no trace anywhere.

---

## Stage 8 — Waitress as a Windows service

> **Alignment note.** Your plan says "Scheduled Task", which is what UAT used.
> The handbook assumes a **service**: §1.6 passes
> `-AppServiceName 'SOCTicketWaitress'` and §4.2 runs
> `Stop-Service SOCTicketWaitress`. Use a service. It gives you automatic
> restart on failure, a real dependency on PostgreSQL, and it makes the config
> bundle and the failover runbook work as written. A scheduled task gives you
> none of those.

**`sc.exe create` pointing directly at `waitress-serve.exe` will not work.**
Waitress does not implement the Windows service control protocol, so the
Service Control Manager reports *"The service did not respond to the start or
control request in a timely fashion"* (error 1053). You need a wrapper —
**NSSM** or **WinSW**. Both are single executables; pick whichever your
organisation will accept.

Create the launcher:

```powershell
@'
@echo off
cd /d C:\SOCTicket\app
venv\Scripts\waitress-serve.exe --listen=127.0.0.1:8000 --threads=8 config.wsgi:application
'@ | Set-Content -Encoding ascii C:\SOCTicket\app\run-prod.cmd
```

Register with NSSM, including the stdout/stderr redirect from Stage 7:

```powershell
nssm install SOCTicketWaitress C:\SOCTicket\app\run-prod.cmd
nssm set SOCTicketWaitress AppDirectory       C:\SOCTicket\app
nssm set SOCTicketWaitress DisplayName        "SOC Ticket (Waitress)"
nssm set SOCTicketWaitress Start              SERVICE_AUTO_START
nssm set SOCTicketWaitress DependOnService    postgresql-x64-18
nssm set SOCTicketWaitress ObjectName         NT_DOMAIN\svc_socticket <password>
nssm set SOCTicketWaitress AppStdout          C:\SOCTicket\logs\waitress-out.log
nssm set SOCTicketWaitress AppStderr          C:\SOCTicket\logs\waitress-err.log
nssm set SOCTicketWaitress AppRotateFiles     1
nssm set SOCTicketWaitress AppRotateBytes     10485760
nssm set SOCTicketWaitress AppExit Default    Restart
nssm set SOCTicketWaitress AppRestartDelay    5000

Start-Service SOCTicketWaitress
Get-Service SOCTicketWaitress
```

`DependOnService` is the fix for the boot race: without it, Waitress starts
before PostgreSQL is accepting connections, fails, and — depending on your
restart policy — either recovers noisily or stays down until someone notices.

Verify it is bound to loopback **only**:

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess
#   LocalAddress MUST be 127.0.0.1 — never 0.0.0.0.
```

```powershell
Invoke-WebRequest http://127.0.0.1:8000/ -UseBasicParsing | Select-Object StatusCode
```

---

## Stage 9 — IIS reverse proxy

**9.1 Enable ARR proxying, and preserve the Host header:**

```powershell
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
  -Filter 'system.webServer/proxy' -Name 'enabled' -Value 'True'
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
  -Filter 'system.webServer/proxy' -Name 'preserveHostHeader' -Value 'True'
```

> **`preserveHostHeader` is off by default and it will cost you an afternoon.**
> Without it Django receives `Host: 127.0.0.1:8000`, which is not in
> `ALLOWED_HOSTS`, and every request returns a bare HTTP 400 with no useful
> message. It also breaks CSRF once HTTPS is on, because the origin no longer
> matches. Set it now, before you debug anything else.

**9.2 Bind the site to loopback only**, so "no LAN access" is enforced by
configuration rather than by remembering:

```powershell
Import-Module WebAdministration
Remove-WebSite -Name 'Default Web Site' -ErrorAction SilentlyContinue

New-WebSite -Name 'SOCTicket' -Port 80 -IPAddress 127.0.0.1 `
  -PhysicalPath 'C:\inetpub\socticket' -Force
```

**9.3 The rewrite rule** — everything inward, nothing served by IIS:

```xml
<!-- C:\inetpub\socticket\web.config -->
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="ProxyToWaitress" stopProcessing="true">
          <match url="(.*)" />
          <action type="Rewrite" url="http://127.0.0.1:8000/{R:1}" />
        </rule>
      </rules>
    </rewrite>
    <security>
      <requestFiltering>
        <!-- App limit is 25 MB per attachment. 35 MB here leaves room for
             multipart overhead so Django's validator produces the friendly
             error, instead of IIS returning a bare 404.13. -->
        <requestLimits maxAllowedContentLength="36700160" />
      </requestFiltering>
    </security>
    <directoryBrowse enabled="false" />
    <httpProtocol>
      <customHeaders>
        <remove name="X-Powered-By" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

> ### Do not add a static handler for `/media/`
>
> Uploaded evidence is served **only** through the authenticated,
> authorization-checked download view. `config/urls.py` records why: exposing
> `MEDIA_ROOT` through an open static route previously allowed unauthenticated
> downloads and let an uploaded `.html`/`.svg` execute as same-origin script
> (stored XSS). An IIS virtual directory over `C:\SOCTicket\app\media` reopens
> that hole silently, and it will not show up in any smoke test.
>
> IIS proxies everything and serves nothing. Static files are WhiteNoise's job,
> inside Django.

```powershell
iisreset /restart
Invoke-WebRequest http://127.0.0.1/ -UseBasicParsing | Select-Object StatusCode
```

---

## Stage 10 — Lock the host down

```powershell
# Nothing inbound. The site is loopback-bound; this is the second layer.
New-NetFirewallRule -DisplayName "SOC-Block-Inbound-HTTP"  -Direction Inbound `
  -Protocol TCP -LocalPort 80,443 -Action Block -Profile Any
New-NetFirewallRule -DisplayName "SOC-Block-Inbound-App"   -Direction Inbound `
  -Protocol TCP -LocalPort 8000  -Action Block -Profile Any
New-NetFirewallRule -DisplayName "SOC-Block-Inbound-PGSQL" -Direction Inbound `
  -Protocol TCP -LocalPort 5432  -Action Block -Profile Any
```

Then **prove it from a different machine.** A firewall rule's existence is not
evidence that it works:

```powershell
# Run from a THIRD machine, not from prod and not from the spare VM.
Test-NetConnection -ComputerName PROD_IP -Port 80    # must fail
Test-NetConnection -ComputerName PROD_IP -Port 8000  # must fail
Test-NetConnection -ComputerName PROD_IP -Port 5432  # must fail
```

Handbook Phase 0.3 later adds a single narrow allow for 5432 from `SPARE_IP`.
Until then, closed to everyone.

---

## Stage 11 — VM-local smoke test

Run every one of these **from the VM's own browser or shell**. Record the result.

**Platform**
- [ ] `Get-Service SOCTicketWaitress` — Running
- [ ] `Get-Service postgresql*` — Running
- [ ] Port 8000 listening on `127.0.0.1` only
- [ ] `http://127.0.0.1/` returns 200 through IIS

**Application**
- [ ] Log in as the superuser
- [ ] **CSS and JS load** — an unstyled page means `collectstatic` did not run
- [ ] Create a ticket end to end
- [ ] **Upload an attachment, then download it back.** This exercises
      `MEDIA_ROOT` permissions and the authenticated download view together
- [ ] Upload a file over 25 MB — expect Django's Thai size error, **not** an IIS
      404.13. If you get 404.13, `maxAllowedContentLength` is too low
- [ ] Every dashboard renders without error
- [ ] Trigger a notification — console backend prints it, or a real email arrives
- [ ] Django admin loads

**Operations**
- [ ] `C:\SOCTicket\logs\waitress-out.log` exists and has content
- [ ] The Django log file is being written
- [ ] `Restart-Service SOCTicketWaitress` — comes back cleanly
- [ ] **Reboot the whole VM.** PostgreSQL and Waitress both return with no
      manual step. This is the test people skip and regret

**Configuration**
```powershell
& C:\SOCTicket\app\venv\Scripts\python.exe manage.py check --deploy
```
- [ ] Every warning either resolved or consciously accepted and written down.
      The HTTPS warnings are expected right now — they close at Stage 13

---

## Stage 12 — Hand off to the backup handbook

The VM is built. **Do not go live.** Continue with
[backup-and-standby-handbook.windows.md](backup-and-standby-handbook.windows.md):

| Next | What |
|---|---|
| Phase 0.3 | Firewall allow for `SPARE_IP` on 5432 |
| Phase 1 | GPG keypair, backup account, first backup, scheduled tiers |
| Phase 1.6 | `New-SocConfigBundle.ps1` — captures `.env`, IIS config, the service definition. **This is why the service is named `SOCTicketWaitress`** |
| Phase 2 | Read-only share, off-host pull, restore drill, alerting |
| Phase 2.8 | Pre-stage the app stack on the spare VM — Stages 2, 3 and 8 of *this* runbook, configured and stopped |
| Phase 3 | Streaming standby |
| Phase 4.1 | Planned failover drill |
| Phase 5 | Real email, Wazuh ingestion task, 90-day cleanup, CSV import |
| §6 | Go-live checklist |

**§2.8 is this runbook run a second time**, on the spare VM, with a placeholder
`.env` and everything set to Manual start. It is what makes the 1–3 hour RTO
real rather than aspirational.

---

## Stage 13 — HTTPS (deferred until the certificate exists)

Do this only when the DNS hostname resolves and the certificate is installed.

1. Import the certificate into `LocalMachine\My`.
2. Add an HTTPS binding on the real hostname; keep or redirect port 80.
3. Add the hostname to `ALLOWED_HOSTS`.
4. Set `SITE_URL=https://<hostname>` — it is baked into every notification link.
5. Flip the security flags:

```ini
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
SECURE_SSL_REDIRECT=True
PASSWORD_RESET_USE_HTTPS=True
SECURE_HSTS_SECONDS=300      # start small — see below
```

> **Ramp HSTS; do not start at a year.** `SECURE_HSTS_SECONDS=31536000` (the
> value in `.env.example`) is cached by **every browser that sees it**. If the
> hostname or certificate turns out to be wrong, you cannot take it back —
> users are locked out until the header expires or each one clears their own
> HSTS state. Start at 300, confirm HTTPS is solid for a few days, then raise
> it in steps.

6. Restart the service, re-run `manage.py check --deploy` — the HTTPS warnings
   should now be gone.
7. **Re-run `New-SocConfigBundle.ps1`** — you just changed `.env` and the IIS
   configuration, and the bundle captures whatever was true when it last ran.

---

## Still held back after this runbook

Everything on the original hold list stays held, for the reasons the handbook
and [project-roadmap.md](../project-roadmap.md) give:

| Held | Released by |
|---|---|
| The production URL to users | Handbook §6, supervisor approval |
| LAN exposure | Stage 13 + supervisor approval |
| Live Wazuh ingestion | Handbook Phase 5.1 |
| Historical CSV import | Handbook Phase 5.1 — dry run, approved mapping, **after** the first verified backup |
| UAT data, accounts, secrets | Permanently. Treat every UAT credential as compromised and rotate it |

---

## Related

- [backup-and-standby-handbook.windows.md](backup-and-standby-handbook.windows.md) — steps 4–10 of the deployment order
- [../project-roadmap.md](../project-roadmap.md) — where this sits in the whole project
- [reporting-layer-operations.md](reporting-layer-operations.md) §3 — the reporting cutover, after go-live
- [production-deployment.md](production-deployment.md) — **superseded**; Docker/Linux only
