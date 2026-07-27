#Requires -Version 5.1
<#
.SYNOPSIS
    Health check for the backup archive and the standby. Runs on the SPARE VM.

.DESCRIPTION
    The dangerous failure mode of any backup system is SILENCE: the pull job
    dies, nobody notices, and the gap is discovered during a restore. This exits
    non-zero so a Scheduled Task failure action (or the -AlertEmail parameter)
    makes that loud.

    Checks, in order:
      1. A recent archive of each required tier actually arrived.
      2. Nothing is sitting in quarantine.
      3. The archive volume has free space (a full disk stops the pull AND,
         on a shared volume, breaks replication).
      4. Optionally, that the standby PostgreSQL service is running and its
         replay lag is within tolerance.

.EXAMPLE
    .\Test-SocArchive.ps1 -ArchiveDir D:\SOCBackup\archive -CheckStandby

.NOTES
    See docs/operations/backup-and-standby-handbook.windows.md
#>
[CmdletBinding()]
param(
    [string]$ArchiveDir = 'D:\SOCBackup\archive',
    [string]$Prefix     = 'soc_ticket',

    # tier = maximum age in hours. 26 allows one missed daily run plus slack.
    [hashtable]$FreshnessHours = @{ daily = 26; weekly = 180 },

    [int]$MinFreePercent = 15,

    [switch]$CheckStandby,
    [string]$PgBinPath        = 'C:\Program Files\PostgreSQL\16\bin',
    [int]   $StandbyPort      = 5433,
    [string]$StandbyUser      = 'postgres',
    [int]   $MaxReplayLagSec  = 300,

    [string]$AlertEmail,
    [string]$SmtpServer
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$problems = New-Object System.Collections.Generic.List[string]

function Add-Problem {
    param([string]$Message)
    Write-Warning $Message
    $problems.Add($Message)
}

if (-not (Test-Path -LiteralPath $ArchiveDir)) {
    Add-Problem "Archive directory not found: $ArchiveDir"
}
else {
    foreach ($tier in $FreshnessHours.Keys) {
        $maxAge = [int]$FreshnessHours[$tier]
        $cutoff = (Get-Date).AddHours(-$maxAge)
        $newest = Get-ChildItem -LiteralPath $ArchiveDir -File -Filter "$($Prefix)_$($tier)_*" |
                  Where-Object { $_.Name -notlike '*.sha256' } |
                  Sort-Object LastWriteTime -Descending |
                  Select-Object -First 1

        if ($null -ne $newest -and $newest.LastWriteTime -ge $cutoff) {
            Write-Host "check: $tier OK ($($newest.Name))"
        }
        else {
            Add-Problem "STALE: no '$tier' archive newer than ${maxAge}h in $ArchiveDir"
        }
    }

    $quarantineDir = Join-Path $ArchiveDir '.quarantine'
    if (Test-Path -LiteralPath $quarantineDir) {
        $count = @(Get-ChildItem -LiteralPath $quarantineDir -File).Count
        if ($count -gt 0) { Add-Problem "$count file(s) in quarantine - transfers are failing verification" }
    }

    $drive = (Get-Item -LiteralPath $ArchiveDir).PSDrive
    if ($null -ne $drive -and ($drive.Used + $drive.Free) -gt 0) {
        $freePercent = [math]::Round(($drive.Free / ($drive.Used + $drive.Free)) * 100, 1)
        if ($freePercent -lt $MinFreePercent) {
            Add-Problem "Only $freePercent% free on $($drive.Name): (floor $MinFreePercent%)"
        }
        else {
            Write-Host "check: disk OK ($freePercent% free on $($drive.Name):)"
        }
    }
}

if ($CheckStandby) {
    $psql = Join-Path $PgBinPath 'psql.exe'
    if (-not (Test-Path -LiteralPath $psql)) {
        Add-Problem "psql.exe not found at $psql - cannot check the standby"
    }
    else {
        # pg_is_in_recovery() must stay true: if it has become false, something
        # promoted this standby and it is silently diverging from production.
        $inRecovery = & $psql -X -q -t -A -h localhost -p $StandbyPort -U $StandbyUser `
                              -d postgres -c 'select pg_is_in_recovery();' 2>$null
        if ($LASTEXITCODE -ne 0) {
            Add-Problem "Cannot query the standby on port $StandbyPort - is the service running?"
        }
        elseif ($inRecovery.Trim() -ne 't') {
            Add-Problem 'Standby is NOT in recovery - it appears to have been promoted. Investigate immediately.'
        }
        else {
            $lag = & $psql -X -q -t -A -h localhost -p $StandbyPort -U $StandbyUser -d postgres `
                   -c "select coalesce(extract(epoch from now() - pg_last_xact_replay_timestamp()), 0)::int;" 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($lag)) {
                $lagSec = [int]($lag.Trim())
                if ($lagSec -gt $MaxReplayLagSec) {
                    Add-Problem "Standby replay lag is ${lagSec}s (limit ${MaxReplayLagSec}s)"
                }
                else {
                    Write-Host "check: standby OK (in recovery, replay lag ${lagSec}s)"
                }
            }
        }
    }
}

if ($problems.Count -gt 0) {
    $body = "SOC Ticket backup health check FAILED on $($env:COMPUTERNAME) at $(Get-Date -Format 'u'):`n`n" +
            (($problems | ForEach-Object { " - $_" }) -join "`n")

    if ($AlertEmail -and $SmtpServer) {
        try {
            Send-MailMessage -To $AlertEmail -From "soc-backup@$($env:COMPUTERNAME)" `
                             -Subject "[SOC-BACKUP] FAILED on $($env:COMPUTERNAME)" `
                             -Body $body -SmtpServer $SmtpServer
        }
        catch {
            Write-Warning "Could not send alert email: $($_.Exception.Message)"
        }
    }

    Write-Host $body
    throw "$($problems.Count) problem(s) found."
}

Write-Host 'check: all checks passed'
