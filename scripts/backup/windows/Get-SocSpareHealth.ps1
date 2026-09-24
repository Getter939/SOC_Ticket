#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only health snapshot of the SOC spare VM. Runs on the SPARE VM.

.DESCRIPTION
    Answers "is the backup working" in one pass, across the three layers that
    can fail independently:

      1. Scheduled tasks    - did the pull / prune / check / drill actually RUN?
      2. Archives           - is a fresh archive present, nothing quarantined,
                              disk not full?
      3. Standby (5433)     - still in recovery, still caught up?
      4. Verify instance    - present and demand-start (stopped is CORRECT)
      5. Restore drill      - did the weekly drill pass recently?

    This script CHANGES NOTHING. It starts no service, writes no file, and
    connects with -w so it can never sit waiting for a password prompt. It is
    safe to run at any time, including during an incident.

    It is a diagnostic, not a replacement for SOC-Archive-Check: the scheduled
    check is what alerts by email. This is what you run when you want to look.

.EXAMPLE
    .\Get-SocSpareHealth.ps1

.EXAMPLE
    .\Get-SocSpareHealth.ps1 -ArchiveDir D:\SOCBackup\archive -StandbyUser postgres

.NOTES
    See docs/operations/backup-and-standby-handbook.windows.md
#>
[CmdletBinding()]
param(
    # Left empty, this is read from the registered SOC-Archive-Check task, so
    # the script reports on what is REALLY configured, not on a default.
    [string]$ArchiveDir,

    [string]$Prefix = 'soc_ticket',

    # tier = maximum age in hours, matching Test-SocArchive.ps1.
    [hashtable]$FreshnessHours = @{ daily = 26; weekly = 180 },

    [int]$MinFreePercent = 15,

    [int]$StandbyPort = 5433,
    [int]$VerifyPort  = 5434,

    # The as-built SOC-Archive-Check runs -StandbyUser soc_backup.
    [string]$StandbyUser = 'soc_backup',

    # Left empty, the newest installed PostgreSQL is used.
    [string]$PgBinPath,

    # Left empty, this is read from the SOC-Archive-Check task's own command line
    # (which sets PGPASSFILE), then falls back to the known candidates. The
    # as-built file is pgpass-STANDBY.conf, not pgpass.conf.
    [string]$PgPassFile,

    [int]$MaxReplayLagSec = 300,

    # The drill is weekly; 8 days allows one run to slip a day.
    [int]$DrillMaxAgeDays = 8
)

$ErrorActionPreference = 'Continue'

$script:Problems = New-Object System.Collections.Generic.List[string]
$script:Warnings = New-Object System.Collections.Generic.List[string]

function Write-Head { param([string]$Text)
    Write-Host ''
    Write-Host "== $Text " -ForegroundColor Cyan
}
function Write-Ok   { param([string]$Text) Write-Host "  [ OK ] $Text" -ForegroundColor Green }
function Write-Warn { param([string]$Text)
    Write-Host "  [WARN] $Text" -ForegroundColor Yellow
    $script:Warnings.Add($Text)
}
function Write-Fail { param([string]$Text)
    Write-Host "  [FAIL] $Text" -ForegroundColor Red
    $script:Problems.Add($Text)
}
function Write-Info { param([string]$Text) Write-Host "         $Text" -ForegroundColor DarkGray }

Write-Host ''
Write-Host "SOC spare-VM health snapshot - $($env:COMPUTERNAME) - $(Get-Date -Format 'u')" -ForegroundColor White

# --------------------------------------------------------------------------
# Resolve the real configuration before checking anything against it.
# --------------------------------------------------------------------------
$checkTask = Get-ScheduledTask -TaskName 'SOC-Archive-Check' -ErrorAction SilentlyContinue
if (-not $ArchiveDir) {
    if ($checkTask -and $checkTask.Actions.Arguments -match '-ArchiveDir\s+"?([A-Za-z]:\\[^"\s]+)"?') {
        $ArchiveDir = $Matches[1]
    }
    else {
        $ArchiveDir = 'C:\SOCBackup\archive'
    }
}

# The scheduled check authenticates to the standby somehow; whatever PGPASSFILE
# it sets is the credential that is KNOWN to work, so prefer it over a guess.
if (-not $PgPassFile) {
    if ($checkTask -and $checkTask.Actions.Arguments -match "PGPASSFILE\s*=\s*['`"]([^'`"]+)['`"]") {
        $PgPassFile = $Matches[1]
    }
    else {
        $PgPassFile = @(
            'C:\ProgramData\SOCBackup\pgpass-standby.conf',
            'C:\ProgramData\SOCBackup\pgpass.conf'
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }
}

if (-not $PgBinPath) {
    $pgDir = Get-ChildItem 'C:\Program Files\PostgreSQL' -Directory -ErrorAction SilentlyContinue |
             Where-Object { Test-Path (Join-Path $_.FullName 'bin\psql.exe') } |
             Sort-Object { [int]($_.Name -replace '\D', '0') } -Descending |
             Select-Object -First 1
    if ($pgDir) { $PgBinPath = Join-Path $pgDir.FullName 'bin' }
}
$psql = if ($PgBinPath) { Join-Path $PgBinPath 'psql.exe' } else { $null }

Write-Info "archive dir : $ArchiveDir"
Write-Info "psql        : $(if ($psql) { $psql } else { 'NOT FOUND' })"
Write-Info "pgpass      : $(if ($PgPassFile) { $PgPassFile } else { 'none found - the standby query will be skipped' })"

# psql helper. -w never prompts, so a missing password fails fast instead of
# hanging this script forever behind an invisible prompt.
function Invoke-Psql {
    param([int]$Port, [string]$User, [string]$Sql)

    if (-not $psql -or -not (Test-Path -LiteralPath $psql)) {
        return [pscustomobject]@{ Ok = $false; Text = 'psql.exe not found' }
    }
    if ($PgPassFile -and (Test-Path -LiteralPath $PgPassFile)) { $env:PGPASSFILE = $PgPassFile }
    $env:PGCONNECT_TIMEOUT = '5'

    # Capture stderr to a file rather than discarding it: "no password supplied"
    # (this ACCOUNT cannot authenticate) and "could not connect" (the INSTANCE is
    # down) are completely different findings and must not be reported alike.
    $errFile = Join-Path $env:TEMP "soc-health-$PID.err"
    $out = & $psql -X -q -t -A -F '|' -w -h localhost -p $Port -U $User -d postgres -c $Sql 2>$errFile
    $ok  = ($LASTEXITCODE -eq 0)
    $err = ''
    if (Test-Path -LiteralPath $errFile) {
        $err = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue)
        if ($null -eq $err) { $err = '' }
        Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{ Ok = $ok; Text = (($out | Out-String).Trim()); Err = $err.Trim() }
}

# --------------------------------------------------------------------------
# 1. Scheduled tasks - a task that never STARTS never reaches its script.
# --------------------------------------------------------------------------
Write-Head 'Scheduled tasks'

$tasks = Get-ScheduledTask -TaskName 'SOC-*' -ErrorAction SilentlyContinue
if (-not $tasks) {
    Write-Fail 'No SOC-* scheduled tasks found on this host.'
}
else {
    foreach ($t in $tasks) {
        $i    = $t | Get-ScheduledTaskInfo
        $last = if ($i.LastRunTime -and $i.LastRunTime.Year -gt 1999) { $i.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { 'never' }
        $line = "{0,-20} last={1,-16} result={2} next={3}" -f $t.TaskName, $last, $i.LastTaskResult,
                $(if ($i.NextRunTime) { $i.NextRunTime.ToString('yyyy-MM-dd HH:mm') } else { 'none' })

        # 267009 = currently running, 267011 = has not run yet. Neither is a failure.
        if ($i.LastTaskResult -eq 0)           { Write-Ok $line }
        elseif ($i.LastTaskResult -eq 267009)  { Write-Ok "$line (running now)" }
        elseif ($i.LastTaskResult -eq 267011)  { Write-Warn "$line (has not run yet)" }
        else                                   { Write-Fail $line }

        # Only S4U is the trap: "Do not store password" makes DPAPI keys
        # unavailable, Import-Clixml fails, and the job stops silently.
        # 'Password' (stored credential, needed to reach the prod share) and
        # 'ServiceAccount' (SYSTEM / NETWORK SERVICE, which is how the
        # SYSTEM-exported smtp-cred.xml is decrypted) are both correct here.
        switch ($t.Principal.LogonType) {
            'S4U'              { Write-Fail "$($t.TaskName): LogonType is S4U - DPAPI credentials cannot be decrypted, this task will fail silently" }
            'InteractiveToken' { Write-Fail "$($t.TaskName): LogonType is InteractiveToken - runs only while that user is logged on" }
            default            { Write-Info "$($t.TaskName): LogonType $($t.Principal.LogonType) (runs as $($t.Principal.UserId))" }
        }
        if ($last -eq 'never') {
            Write-Warn "$($t.TaskName): has never run"
        }
    }

    # -MaxArchiveGB defaults to 0 in Remove-SocArchive.ps1, and 0 DISABLES the
    # size cap. Age rules still prune, but the backstop that stops the archive
    # filling the volume the standby's data directory lives on is then off.
    $prune = $tasks | Where-Object { $_.TaskName -like '*Prune*' }
    if ($prune) {
        $pruneArgs = ($prune.Actions.Arguments -join ' ')
        if ($pruneArgs -notmatch '-MaxArchiveGB\s+[1-9]') {
            Write-Warn 'Prune task passes no -MaxArchiveGB: the archive size cap is DISABLED (age-based retention still applies).'
        }
    }
}

# --------------------------------------------------------------------------
# 2. Archives
# --------------------------------------------------------------------------
Write-Head 'Archives'

if (-not (Test-Path -LiteralPath $ArchiveDir)) {
    Write-Fail "Archive directory not found: $ArchiveDir"
}
else {
    foreach ($tier in $FreshnessHours.Keys) {
        $maxAge = [int]$FreshnessHours[$tier]
        $newest = Get-ChildItem -LiteralPath $ArchiveDir -File -Filter "$($Prefix)_$($tier)_*" -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -notlike '*.sha256' } |
                  Sort-Object LastWriteTime -Descending |
                  Select-Object -First 1

        if ($newest) {
            $ageH = [math]::Round(((Get-Date) - $newest.LastWriteTime).TotalHours, 1)
            $size = [math]::Round($newest.Length / 1MB, 1)
            $msg  = "{0,-6} {1}  age={2}h  size={3}MB" -f $tier, $newest.Name, $ageH, $size
            if ($ageH -le $maxAge) { Write-Ok $msg } else { Write-Fail "STALE: $msg (limit ${maxAge}h)" }

            if (-not (Test-Path -LiteralPath "$($newest.FullName).sha256")) {
                Write-Warn "$($newest.Name): no matching .sha256 alongside it"
            }
        }
        else {
            Write-Fail "No '$tier' archive found in $ArchiveDir"
        }
    }

    $total = @(Get-ChildItem -LiteralPath $ArchiveDir -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -notlike '*.sha256' }).Count
    Write-Info "$total archive file(s) retained"

    $q = Join-Path $ArchiveDir '.quarantine'
    if (Test-Path -LiteralPath $q) {
        $qc = @(Get-ChildItem -LiteralPath $q -File -ErrorAction SilentlyContinue).Count
        if ($qc -gt 0) { Write-Fail "$qc file(s) in quarantine - transfers are failing verification" }
        else { Write-Ok 'quarantine empty' }
    }

    $drive = (Get-Item -LiteralPath $ArchiveDir).PSDrive
    if ($drive -and ($drive.Used + $drive.Free) -gt 0) {
        $freePct = [math]::Round(($drive.Free / ($drive.Used + $drive.Free)) * 100, 1)
        $freeGB  = [math]::Round($drive.Free / 1GB, 1)
        if ($freePct -lt $MinFreePercent) { Write-Fail "Only $freePct% free on $($drive.Name): ($freeGB GB, floor $MinFreePercent%)" }
        else { Write-Ok "disk $freePct% free on $($drive.Name): ($freeGB GB)" }
    }
}

# --------------------------------------------------------------------------
# 3. Streaming standby (5433)
# --------------------------------------------------------------------------
Write-Head "Standby (port $StandbyPort)"

$svc = Get-Service -Name 'postgresql-standby' -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Fail 'Service postgresql-standby not found.'
}
elseif ($svc.Status -ne 'Running') {
    Write-Fail "Service postgresql-standby is $($svc.Status) - it must run continuously."
}
else {
    Write-Ok 'service postgresql-standby is Running'

    $r = Invoke-Psql -Port $StandbyPort -User $StandbyUser `
         -Sql "select pg_is_in_recovery(), (pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn()), coalesce(extract(epoch from now() - pg_last_xact_replay_timestamp()), 0)::int, coalesce(pg_last_wal_replay_lsn()::text, '-');"

    if (-not $r.Ok -or -not $r.Text) {
        # Distinguish "I could not ask" from "the standby is broken". Running
        # this interactively as an admin has no pgpass entry, while the
        # scheduled SOC-Archive-Check does - that is a gap in THIS script's
        # visibility, not a fault in the standby.
        if ($r.Err -match 'no password supplied|fe_sendauth') {
            Write-Warn "Cannot authenticate to the standby as '$StandbyUser' from this account - no password available (psql -w). The standby itself was NOT checked."
            Write-Info 'The scheduled SOC-Archive-Check covers this check under its own account - see its LastTaskResult above.'
            Write-Info "To check it here: re-run without -w, or pass -StandbyUser postgres, or point -PgPassFile at a pgpass holding localhost:$StandbyPort"
        }
        elseif ($r.Err -match 'password authentication failed') {
            Write-Fail "Standby rejected the credentials for '$StandbyUser' - the password has changed or the role was altered."
        }
        elseif ($r.Err -match 'could not connect|Connection refused|server closed the connection|timeout expired') {
            Write-Fail "Standby is not accepting connections on port $StandbyPort although the service reports Running."
        }
        else {
            Write-Fail "Cannot query the standby on $StandbyPort as '$StandbyUser'."
        }
        if ($r.Err) { Write-Info "psql: $($r.Err -replace '\r?\n', ' ')" }
    }
    else {
        $p          = $r.Text -split '\|'
        $inRecovery = ($p[0].Trim() -eq 't')
        $caughtUp   = ($p[1].Trim() -eq 't')
        $lagSec     = [int]$p[2].Trim()

        if (-not $inRecovery) {
            Write-Fail 'Standby is NOT in recovery - something PROMOTED it and it is diverging from production. Treat as an incident.'
        }
        elseif ($caughtUp) {
            Write-Ok "in recovery, caught up with primary (replay_lsn $($p[3].Trim()))"
            Write-Info "time-based lag ${lagSec}s is meaningless while caught up - an idle primary inflates it"
        }
        elseif ($lagSec -gt $MaxReplayLagSec) {
            Write-Fail "Standby is BEHIND: unreplayed WAL, replay lag ${lagSec}s (limit ${MaxReplayLagSec}s)"
        }
        else {
            Write-Ok "in recovery, replay lag ${lagSec}s"
        }
    }
}

# --------------------------------------------------------------------------
# 4. Verify instance (5434) - demand-start, so STOPPED is the correct state.
# --------------------------------------------------------------------------
Write-Head "Verify instance (port $VerifyPort)"

$vsvc = Get-Service -Name 'postgresql-verify' -ErrorAction SilentlyContinue
if (-not $vsvc) {
    Write-Fail 'Service postgresql-verify not found - restore drills cannot run.'
}
else {
    Write-Ok "service postgresql-verify present, Status=$($vsvc.Status), StartType=$($vsvc.StartType)"
    if ($vsvc.StartType -eq 'Automatic') {
        Write-Warn 'postgresql-verify is Automatic - it should be demand-start so a cluster holding restored production data is not listening between drills.'
    }
    if ($vsvc.Status -eq 'Running') {
        Write-Info 'Running is expected only during a drill; if no drill is in progress, stop it.'
    }
}

# --------------------------------------------------------------------------
# 5. Restore drill recency - the only check that proves an archive RESTORES.
# --------------------------------------------------------------------------
Write-Head 'Restore drill'

$drill = Get-ScheduledTask -TaskName 'SOC-Restore-Drill' -ErrorAction SilentlyContinue
if (-not $drill) {
    Write-Fail 'SOC-Restore-Drill is not scheduled - nothing is proving the archives are restorable.'
}
else {
    $di = $drill | Get-ScheduledTaskInfo
    if ($di.LastRunTime -and $di.LastRunTime.Year -gt 1999) {
        $ageD = [math]::Round(((Get-Date) - $di.LastRunTime).TotalDays, 1)
        $msg  = "last drill $($di.LastRunTime.ToString('yyyy-MM-dd HH:mm')) ($ageD days ago), result=$($di.LastTaskResult)"
        if ($di.LastTaskResult -ne 0) { Write-Fail "Drill FAILED: $msg" }
        elseif ($ageD -gt $DrillMaxAgeDays) { Write-Fail "Drill is STALE: $msg (limit $DrillMaxAgeDays days)" }
        else { Write-Ok $msg }
    }
    else {
        Write-Fail 'SOC-Restore-Drill has never run - these are archives, not verified backups.'
    }
}

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
Write-Host ''
if ($script:Problems.Count -eq 0 -and $script:Warnings.Count -eq 0) {
    Write-Host 'RESULT: healthy - all checks passed.' -ForegroundColor Green
}
elseif ($script:Problems.Count -eq 0) {
    Write-Host "RESULT: healthy, with $($script:Warnings.Count) warning(s):" -ForegroundColor Yellow
    $script:Warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
else {
    Write-Host "RESULT: $($script:Problems.Count) PROBLEM(S):" -ForegroundColor Red
    $script:Problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    if ($script:Warnings.Count -gt 0) {
        Write-Host "plus $($script:Warnings.Count) warning(s):" -ForegroundColor Yellow
        $script:Warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
}

Write-Host ''
Write-Host 'This snapshot does NOT prove a backup restores - only SOC-Restore-Drill does,' -ForegroundColor DarkGray
Write-Host 'and even a passing drill does not prove the APP recovers (the dump carries no' -ForegroundColor DarkGray
Write-Host 'cluster roles or grants - see handbook section 4.3 step 3).' -ForegroundColor DarkGray
Write-Host ''

if ($script:Problems.Count -gt 0) { exit 1 }
exit 0
