#Requires -Version 5.1
<#
.SYNOPSIS
    Restore drill: proves an archive is actually restorable. Runs on the SPARE VM.

.DESCRIPTION
    A copied file is not a backup until it has been restored. This decrypts an
    archive, verifies every component checksum, restores the dump into a
    throwaway database, and asserts the row counts match the manifest recorded
    at backup time.

    IMPORTANT - which PostgreSQL instance this uses:
    A streaming standby is read-only for its entire life and CANNOT accept a
    restore. If you have completed Phase 2 of the handbook, this script must
    point at the separate VERIFY instance (default port 5434), never at the
    standby (5433). Running it against the standby will fail; running it against
    production would be destructive.

.EXAMPLE
    .\Test-SocRestore.ps1 -ArchiveDir D:\SOCBackup\archive -PassphraseFile C:\ProgramData\SOCBackup\gpg-pass.txt

.NOTES
    See docs/operations/backup-and-standby-handbook.windows.md
#>
[CmdletBinding()]
param(
    # The spare VM has a single C: volume; production writes archives to
    # C:\SOCBackup\archive and the pull copies them to the same path here.
    [string]$ArchiveDir = 'C:\SOCBackup\archive',

    # Defaults to the newest archive present.
    [string]$ArchivePath,

    # Must be the same major version as production (18) — a dump taken by
    # pg_dump 18 will not restore under an older pg_restore.
    [string]$PgBinPath  = 'C:\Program Files\PostgreSQL\18\bin',
    [string]$VerifyHost = 'localhost',
    [int]   $VerifyPort = 5434,
    [string]$VerifyUser = 'postgres',
    [string]$RestoreDb  = 'ticketdata_restoretest',

    # Gpg4win 4.x/5.x is 64-bit and installs here, not under Program Files (x86).
    [string]$GpgExe         = 'C:\Program Files\GnuPG\bin\gpg.exe',
    [string]$GpgHome        = 'C:\ProgramData\SOCBackup\gnupg',
    [string]$PassphraseFile = 'C:\ProgramData\SOCBackup\gpg-pass.txt',

    [string]$WorkRoot = 'C:\SOCBackup\restore-work',

    # Keep the restored database for inspection instead of dropping it.
    [switch]$KeepRestoredDb
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($RestoreDb -notmatch '^[A-Za-z0-9_]+$') { throw "Unsafe database name: $RestoreDb" }

$psql       = Join-Path $PgBinPath 'psql.exe'
$pgRestore  = Join-Path $PgBinPath 'pg_restore.exe'
foreach ($tool in @($psql, $pgRestore, $GpgExe)) {
    if (-not (Test-Path -LiteralPath $tool)) { throw "Required tool not found: $tool" }
}
if (-not (Test-Path -LiteralPath $PassphraseFile)) { throw "GPG passphrase file not found: $PassphraseFile" }

if (-not $ArchivePath) {
    $newest = Get-ChildItem -LiteralPath $ArchiveDir -File -Filter '*.gpg' |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -eq $newest) { throw "No .gpg archives found in $ArchiveDir" }
    $ArchivePath = $newest.FullName
}
if (-not (Test-Path -LiteralPath $ArchivePath)) { throw "Archive not found: $ArchivePath" }

Write-Host "restore-verify: testing $(Split-Path -Leaf $ArchivePath)"

$env:GNUPGHOME = $GpgHome
$env:PGHOST    = $VerifyHost
$env:PGPORT    = "$VerifyPort"
$env:PGUSER    = $VerifyUser

$workDir = Join-Path $WorkRoot ("restore-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
    # -- 1. Verify the archive against its own sidecar before spending time on it
    $sidecar = "$ArchivePath.sha256"
    if (Test-Path -LiteralPath $sidecar) {
        $expected = ((Get-Content -LiteralPath $sidecar -First 1) -split '\s+')[0].ToLower()
        $actual   = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLower()
        if ($expected -ne $actual) { throw 'Archive SHA-256 does not match its sidecar - the archive is damaged.' }
        Write-Host 'restore-verify: archive checksum OK'
    }
    else {
        Write-Warning 'restore-verify: no .sha256 sidecar for this archive; skipping the outer integrity check'
    }

    # -- 2. Decrypt
    Write-Host 'restore-verify: decrypting'
    $zipPath = Join-Path $workDir 'backup.zip'
    & $GpgExe --batch --yes --pinentry-mode loopback --passphrase-file $PassphraseFile `
              --output $zipPath --decrypt $ArchivePath
    if ($LASTEXITCODE -ne 0) { throw "gpg decryption failed with exit code $LASTEXITCODE." }

    # -- 3. Extract and check every component
    $extractDir = Join-Path $workDir 'package'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractDir)

    foreach ($required in @('database.dump', 'media.zip', 'manifest.json', 'counts.json', 'checksums.txt')) {
        if (-not (Test-Path -LiteralPath (Join-Path $extractDir $required))) {
            throw "$required is missing from the archive."
        }
    }

    Write-Host 'restore-verify: checking component checksums'
    foreach ($line in Get-Content -LiteralPath (Join-Path $extractDir 'checksums.txt')) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts    = $line -split '\s+', 2
        $expected = $parts[0].ToLower()
        $name     = $parts[1].Trim()
        $actual   = (Get-FileHash -LiteralPath (Join-Path $extractDir $name) -Algorithm SHA256).Hash.ToLower()
        if ($expected -ne $actual) { throw "Checksum mismatch for $name - the archive is corrupt." }
    }

    # -- 4. Recreate the throwaway database
    Write-Host "restore-verify: recreating $RestoreDb on port $VerifyPort"
    & $psql -X -q -v ON_ERROR_STOP=1 -d postgres -c `
        "select pg_terminate_backend(pid) from pg_stat_activity where datname = '$RestoreDb' and pid <> pg_backend_pid();" | Out-Null
    & $psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "drop database if exists ""$RestoreDb"";" | Out-Null
    & $psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "create database ""$RestoreDb"";" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the restore target database.' }

    Write-Host 'restore-verify: restoring the dump'
    & $pgRestore --no-owner --no-acl --dbname=$RestoreDb (Join-Path $extractDir 'database.dump')
    # pg_restore returns non-zero on warnings too; the count assertions below are
    # the real gate, so a warning here is reported but not fatal.
    if ($LASTEXITCODE -ne 0) { Write-Warning "pg_restore exited with code $LASTEXITCODE (often warnings) - the count checks decide." }

    # -- 5. Assert the counts recorded at backup time
    $expectedCounts = Get-Content -LiteralPath (Join-Path $extractDir 'counts.json') -Raw | ConvertFrom-Json

    $tableMap = @{
        tickets            = 'incidents_ticket'
        ticket_logs        = 'incidents_ticketlog'
        triage_records     = 'incidents_triagerecord'
        project_incidents  = 'incidents_projectincident'
        ticket_attachments = 'incidents_ticketattachment'
        wazuh_alerts       = 'wazuh_ingest_wazuhalert'
        ingest_watermarks  = 'wazuh_ingest_ingestwatermark'
        users              = 'auth_user'
    }

    $failures = New-Object System.Collections.Generic.List[string]
    foreach ($key in $tableMap.Keys) {
        $expected = $expectedCounts.$key
        if ($null -eq $expected) {
            Write-Host "restore-verify: $key - no expected count recorded, skipping"
            continue
        }
        $raw = & $psql -X -q -t -A -v ON_ERROR_STOP=1 -d $RestoreDb -c "select count(*) from $($tableMap[$key]);" 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
            $failures.Add("$key : table missing from the restored database")
            continue
        }
        $actual = [int64]($raw.Trim())
        if ($actual -ne [int64]$expected) { $failures.Add("$key : expected $expected, restored $actual") }
        else { Write-Host "restore-verify: $key : $actual" }
    }

    # -- 6. Media
    $mediaDir = Join-Path $workDir 'media'
    [System.IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $extractDir 'media.zip'), $mediaDir)
    $mediaCount = @(Get-ChildItem -LiteralPath $mediaDir -Recurse -File -Force).Count
    if ($null -ne $expectedCounts.media_files) {
        if ($mediaCount -ne [int]$expectedCounts.media_files) {
            $failures.Add("media_files : expected $($expectedCounts.media_files), restored $mediaCount")
        }
        else { Write-Host "restore-verify: media_files : $mediaCount" }
    }

    if (-not $KeepRestoredDb) {
        & $psql -X -q -v ON_ERROR_STOP=1 -d postgres -c `
            "select pg_terminate_backend(pid) from pg_stat_activity where datname = '$RestoreDb' and pid <> pg_backend_pid();" | Out-Null
        & $psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "drop database if exists ""$RestoreDb"";" | Out-Null
    }

    if ($failures.Count -gt 0) {
        throw ("RESTORE VERIFICATION FAILED:`n" + (($failures | ForEach-Object { " - $_" }) -join "`n"))
    }

    Write-Host 'restore-verify: backup is restorable'
}
finally {
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
