#Requires -Version 5.1
<#
.SYNOPSIS
    Prunes the pulled archive by tier. Runs on the SPARE (backup) VM.

.DESCRIPTION
    Retention here is deliberately INDEPENDENT of, and longer than, production's.
    Production's pruning must never propagate to this copy - that propagation is
    exactly what ransomware or a bad script on production would exploit.

    Defaults assume the archive shares a disk with the standby database, so the
    -MaxArchiveGB cap exists as a hard backstop: if the archive would otherwise
    fill the volume and stop replication, the oldest archives are removed first,
    newest tiers last.

.EXAMPLE
    .\Remove-SocArchive.ps1 -ArchiveDir D:\SOCBackup\archive -WhatIfOnly

.NOTES
    See docs/operations/backup-and-standby-handbook.windows.md
#>
[CmdletBinding()]
param(
    [string]$ArchiveDir = 'D:\SOCBackup\archive',
    [string]$Prefix     = 'soc_ticket',

    [int]$RetentionHourlyDays  = 7,
    [int]$RetentionDailyDays   = 90,
    [int]$RetentionWeeklyDays  = 180,
    [int]$RetentionMonthlyDays = 1095,
    [int]$RetentionManualDays  = 90,
    # Config bundles are kilobytes and are what you rebuild the host from.
    # Keep them far longer than the data they accompany.
    [int]$RetentionConfigDays  = 730,
    [int]$QuarantineDays       = 14,

    # 0 disables the size cap. When set, pruning continues past the age rules
    # until the archive fits, oldest first.
    [int]$MaxArchiveGB = 0,

    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $ArchiveDir)) { throw "ArchiveDir not found: $ArchiveDir" }

function Remove-Target {
    param([System.IO.FileInfo]$File, [string]$Reason)
    if ($WhatIfOnly) {
        Write-Host "prune: WOULD REMOVE $($File.Name) ($Reason)"
    }
    else {
        Write-Host "prune: removing $($File.Name) ($Reason)"
        Remove-Item -LiteralPath $File.FullName -Force
    }
}

$tiers = @(
    @{ Name = 'hourly';  Days = $RetentionHourlyDays  },
    @{ Name = 'daily';   Days = $RetentionDailyDays   },
    @{ Name = 'weekly';  Days = $RetentionWeeklyDays  },
    @{ Name = 'monthly'; Days = $RetentionMonthlyDays },
    @{ Name = 'manual';  Days = $RetentionManualDays  },
    @{ Name = 'config';  Days = $RetentionConfigDays  }
)

Write-Host "prune: pruning $ArchiveDir (WhatIfOnly=$WhatIfOnly)"

foreach ($tier in $tiers) {
    if ($tier.Days -le 0) { continue }
    $cutoff = (Get-Date).AddDays(-$tier.Days)
    Get-ChildItem -LiteralPath $ArchiveDir -File -Filter "$($Prefix)_$($tier.Name)_*" |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object { Remove-Target $_ "$($tier.Name) older than $($tier.Days)d" }
}

# Quarantined files are failed transfers, not backups. Left alone they silently
# consume the volume the standby also depends on.
$quarantineDir = Join-Path $ArchiveDir '.quarantine'
if ((Test-Path -LiteralPath $quarantineDir) -and $QuarantineDays -gt 0) {
    $cutoff = (Get-Date).AddDays(-$QuarantineDays)
    Get-ChildItem -LiteralPath $quarantineDir -File |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object { Remove-Target $_ "quarantined older than $QuarantineDays d" }
}

if ($MaxArchiveGB -gt 0) {
    $capBytes = [int64]$MaxArchiveGB * 1GB
    # Config bundles are exempt: they are kilobytes, they are what you rebuild
    # the host from, and evicting them to reclaim space would save nothing.
    $files = @(Get-ChildItem -LiteralPath $ArchiveDir -File |
               Where-Object { $_.Name -like "$Prefix`_*" -and $_.Name -notlike "$Prefix`_config_*" } |
               Sort-Object LastWriteTime)   # oldest first
    $total = ($files | Measure-Object -Property Length -Sum).Sum
    if ($null -eq $total) { $total = 0 }

    if ($total -gt $capBytes) {
        Write-Warning ("prune: archive is {0:N1} GB, over the {1} GB cap - removing oldest first" -f ($total / 1GB), $MaxArchiveGB)
        foreach ($file in $files) {
            if ($total -le $capBytes) { break }
            Remove-Target $file 'over size cap'
            $sidecar = "$($file.FullName).sha256"
            if (Test-Path -LiteralPath $sidecar) {
                Remove-Item -LiteralPath $sidecar -Force -ErrorAction SilentlyContinue
            }
            $total -= $file.Length
        }
    }
}

Write-Host 'prune: completed'
