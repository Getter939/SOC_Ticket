#Requires -Version 5.1
<#
.SYNOPSIS
    Pulls new backup archives from production. Runs on the SPARE (backup) VM.

.DESCRIPTION
    Connects to production's read-only SMB share, copies any archive not already
    held locally, verifies its SHA-256 against the sidecar file, and quarantines
    anything that fails so the next run re-fetches it.

    PULL, NOT PUSH. Production is never given a credential for this host, and the
    share is granted Read-only, so neither a compromised production VM nor a
    compromised backup VM can delete production's archives. Nothing here ever
    mirrors deletions: pruning on production does not prune this copy.

    The credential is read from a DPAPI-protected file created by the operator:
        $cred = Get-Credential          # PRODHOST\svc_socpull
        $cred | Export-Clixml C:\ProgramData\SOCBackup\prod-cred.xml
    That file can only be decrypted by the same Windows account, on the same
    machine, that created it.

.EXAMPLE
    .\Copy-SocArchive.ps1 -SourceUnc \\SOCPROD\SOCArchive$ -ArchiveDir D:\SOCBackup\archive

.NOTES
    See docs/operations/backup-and-standby-handbook.windows.md
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceUnc,

    [string]$ArchiveDir     = 'D:\SOCBackup\archive',
    [string]$CredentialPath = 'C:\ProgramData\SOCBackup\prod-cred.xml',
    [string]$Prefix         = 'soc_ticket',

    # An archive whose .sha256 sidecar has not arrived yet may simply still be
    # being written on production. Give it this long before calling it damaged.
    [int]$GraceMinutes = 30
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $CredentialPath)) {
    throw "Credential file not found: $CredentialPath. Create it as the account that runs this task."
}
foreach ($dir in @($ArchiveDir, (Join-Path $ArchiveDir '.quarantine'))) {
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}
$quarantineDir = Join-Path $ArchiveDir '.quarantine'

$lockPath = Join-Path $ArchiveDir '.pull.lock'
$lockStream = $null
try { $lockStream = [System.IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None') }
catch { throw "Another pull appears to be running (lock held on $lockPath)." }

$driveName = 'SOCPULL'
$driveCreated = $false

try {
    $credential = Import-Clixml -LiteralPath $CredentialPath

    if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
        Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
    }
    # Establishing the PSDrive authenticates the SMB session for this logon
    # session; the copy below then runs over that session.
    New-PSDrive -Name $driveName -PSProvider FileSystem -Root $SourceUnc `
                -Credential $credential -ErrorAction Stop | Out-Null
    $driveCreated = $true

    $sourceRoot = "$($driveName):\"
    Write-Host "pull: reading $SourceUnc"

    $remoteFiles = @(Get-ChildItem -LiteralPath $sourceRoot -File |
                     Where-Object { $_.Name -like "$Prefix`_*" })
    if ($remoteFiles.Count -eq 0) {
        Write-Warning "pull: no archives found on $SourceUnc - is production's backup task running?"
    }

    $copied = 0
    foreach ($remote in $remoteFiles) {
        $localPath = Join-Path $ArchiveDir $remote.Name
        # Archives are immutable once written (the UTC timestamp is in the
        # filename), so an existing local copy is never re-transferred.
        if (Test-Path -LiteralPath $localPath) { continue }

        Write-Host "pull: copying $($remote.Name) ($([math]::Round($remote.Length / 1MB, 1)) MB)"
        Copy-Item -LiteralPath $remote.FullName -Destination $localPath -Force
        $copied++
    }
    Write-Host "pull: $copied new file(s) copied"
}
finally {
    if ($driveCreated) { Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue }
}

# -- Verification ------------------------------------------------------------
# Every archive must match its sidecar hash. A file that does not is moved to
# quarantine rather than deleted, so the cause stays inspectable, and the next
# run re-fetches it because the local copy is gone.
$verified = 0
$quarantined = 0
$graceCutoff = (Get-Date).AddMinutes(-$GraceMinutes)

$archives = @(Get-ChildItem -LiteralPath $ArchiveDir -File |
              Where-Object { $_.Name -like "$Prefix`_*" -and $_.Name -notlike '*.sha256' })

foreach ($archive in $archives) {
    $sidecar = "$($archive.FullName).sha256"

    if (-not (Test-Path -LiteralPath $sidecar)) {
        if ($archive.LastWriteTime -lt $graceCutoff) {
            Write-Warning "pull: QUARANTINE $($archive.Name) - no checksum after $GraceMinutes minutes"
            Move-Item -LiteralPath $archive.FullName -Destination $quarantineDir -Force
            $quarantined++
        }
        else {
            Write-Host "pull: $($archive.Name) has no checksum yet; leaving it for the next run"
        }
        continue
    }

    $expected = ((Get-Content -LiteralPath $sidecar -First 1) -split '\s+')[0].ToLower()
    $actual   = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLower()

    if ($expected -eq $actual) {
        $verified++
    }
    else {
        Write-Warning "pull: QUARANTINE $($archive.Name) - SHA-256 mismatch"
        Move-Item -LiteralPath $archive.FullName -Destination $quarantineDir -Force
        Move-Item -LiteralPath $sidecar -Destination $quarantineDir -Force
        $quarantined++
    }
}

if ($null -ne $lockStream) {
    $lockStream.Close(); $lockStream.Dispose()
    Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
}

Write-Host "pull: $verified archive(s) verified, $quarantined quarantined"

if ($quarantined -gt 0) {
    throw "$quarantined archive(s) failed verification and were moved to $quarantineDir. They will be re-pulled on the next run."
}
Write-Host 'pull: completed'
