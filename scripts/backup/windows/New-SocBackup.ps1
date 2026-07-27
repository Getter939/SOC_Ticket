#Requires -Version 5.1
<#
.SYNOPSIS
    Creates one encrypted SOC Ticket backup archive. Runs on the PRODUCTION VM.

.DESCRIPTION
    Windows-native equivalent of scripts/backup/backup.sh, for deployments where
    PostgreSQL runs as a native Windows service rather than in Docker.

    Produces  <Prefix>_<Tier>_<utc-timestamp>.zip.gpg  containing:
        database.dump   pg_dump --format=custom --no-owner --no-acl
        media.zip       the MEDIA_ROOT tree (ticket attachments / evidence)
        manifest.json   source metadata + row counts
        counts.json     row counts alone, for restore verification
        checksums.txt   SHA-256 of each component

    Encryption is GPG public-key: production holds only the PUBLIC key, so a
    compromised production host cannot decrypt its own backups, and no
    passphrase ever appears on a command line or in a config file.

    The database password is NOT taken as a parameter. Create a pgpass file for
    the account that runs this script:
        %APPDATA%\postgresql\pgpass.conf
        <host>:<port>:<database>:<user>:<password>

.EXAMPLE
    .\New-SocBackup.ps1 -Tier daily -GpgRecipient soc-backup@nt.local

.NOTES
    See docs/operations/backup-and-standby-handbook.windows.md
#>
[CmdletBinding()]
param(
    [ValidateSet('hourly', 'daily', 'weekly', 'monthly', 'manual')]
    [string]$Tier = 'manual',

    [Parameter(Mandatory = $true)]
    [string]$GpgRecipient,

    [string]$PgBinPath   = 'C:\Program Files\PostgreSQL\16\bin',
    [string]$DbName      = 'ticketdata',
    [string]$DbUser      = 'ticket',
    [string]$DbHost      = 'localhost',
    [int]   $DbPort      = 5432,
    [string]$MediaRoot   = 'C:\SOCTicket\app\media',
    [string]$BackupRoot  = 'C:\SOCBackup\archive',
    [string]$Prefix      = 'soc_ticket',
    [string]$GpgExe      = 'C:\Program Files (x86)\GnuPG\bin\gpg.exe',
    [string]$GpgHome     = 'C:\ProgramData\SOCBackup\gnupg',
    [string]$AppVersion  = 'unknown',

    # Retention is applied ONLY to the tier being written, matching backup.sh.
    [int]$RetentionHourlyDays  = 2,
    [int]$RetentionDailyDays   = 30,
    [int]$RetentionWeeklyDays  = 84,
    [int]$RetentionMonthlyDays = 365,
    [int]$RetentionManualDays  = 30,

    [switch]$SkipRetention
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-Tool {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Name not found at '$Path'. Pass the correct path or install it."
    }
    return $Path
}

# psql returns one scalar. A missing table must not abort the whole backup, so
# failures degrade to $null and are recorded as such in the manifest.
function Get-TableCount {
    param([string]$PsqlExe, [string]$Table)
    $value = & $PsqlExe -X -q -t -A -v ON_ERROR_STOP=1 -c "select count(*) from $Table;" 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)) { return $null }
    return [int64]($value.Trim())
}

$pgDump = Resolve-Tool (Join-Path $PgBinPath 'pg_dump.exe') 'pg_dump.exe'
$psql   = Resolve-Tool (Join-Path $PgBinPath 'psql.exe')    'psql.exe'
$gpg    = Resolve-Tool $GpgExe                              'gpg.exe'

if (-not (Test-Path -LiteralPath $BackupRoot)) {
    New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
}

# Connection settings for every child process. PGPASSWORD is deliberately never
# set here; authentication comes from pgpass.conf.
$env:PGHOST     = $DbHost
$env:PGPORT     = "$DbPort"
$env:PGDATABASE = $DbName
$env:PGUSER     = $DbUser
$env:GNUPGHOME  = $GpgHome

# Single-instance guard: a second run while the first is mid-dump would produce
# a torn archive and double the IO.
$lockPath = Join-Path $BackupRoot '.backup.lock'
$lockStream = $null
try {
    $lockStream = [System.IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
}
catch {
    throw "Another backup appears to be running (lock held on $lockPath)."
}

$timestamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$backupName  = "{0}_{1}_{2}" -f $Prefix, $Tier, $timestamp
$stagingDir  = Join-Path $BackupRoot ".$backupName.staging"
$packageDir  = Join-Path $stagingDir 'package'
$zipPath     = Join-Path $BackupRoot "$backupName.zip"
$finalPath   = "$zipPath.gpg"

try {
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null

    Write-Host "backup: dumping $DbName from $DbHost"
    & $pgDump --format=custom --no-owner --no-acl --file=(Join-Path $packageDir 'database.dump')
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed with exit code $LASTEXITCODE." }

    Write-Host "backup: archiving media from $MediaRoot"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $mediaZip = Join-Path $packageDir 'media.zip'
    $mediaFileCount = 0
    if (Test-Path -LiteralPath $MediaRoot) {
        $mediaFileCount = @(Get-ChildItem -LiteralPath $MediaRoot -Recurse -File -Force).Count
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $MediaRoot, $mediaZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    }
    else {
        Write-Warning "MEDIA_ROOT '$MediaRoot' does not exist; writing an empty media.zip."
        $emptyDir = Join-Path $stagingDir 'empty-media'
        New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $emptyDir, $mediaZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    }

    Write-Host 'backup: collecting row counts'
    $counts = [ordered]@{
        tickets            = Get-TableCount $psql 'incidents_ticket'
        ticket_logs        = Get-TableCount $psql 'incidents_ticketlog'
        triage_records     = Get-TableCount $psql 'incidents_triagerecord'
        project_incidents  = Get-TableCount $psql 'incidents_projectincident'
        ticket_attachments = Get-TableCount $psql 'incidents_ticketattachment'
        wazuh_alerts       = Get-TableCount $psql 'wazuh_ingest_wazuhalert'
        ingest_watermarks  = Get-TableCount $psql 'wazuh_ingest_ingestwatermark'
        users              = Get-TableCount $psql 'auth_user'
        media_files        = $mediaFileCount
    }

    $counts | ConvertTo-Json -Depth 3 |
        Set-Content -LiteralPath (Join-Path $packageDir 'counts.json') -Encoding UTF8

    [ordered]@{
        backup_name    = $backupName
        backup_tier    = $Tier
        created_at_utc = $timestamp
        source         = [ordered]@{
            pg_host     = $DbHost
            pg_database = $DbName
            pg_user     = $DbUser
            media_root  = $MediaRoot
            app_version = $AppVersion
            host        = $env:COMPUTERNAME
        }
        counts         = $counts
    } | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $packageDir 'manifest.json') -Encoding UTF8

    # Component checksums use BARE FILE NAMES so they verify from any directory
    # on any host. (The Linux script recorded container paths, which do not
    # resolve on the machine that later checks them.)
    $componentLines = foreach ($name in @('database.dump', 'media.zip', 'manifest.json', 'counts.json')) {
        $h = Get-FileHash -LiteralPath (Join-Path $packageDir $name) -Algorithm SHA256
        "{0}  {1}" -f $h.Hash.ToLower(), $name
    }
    $componentLines | Set-Content -LiteralPath (Join-Path $packageDir 'checksums.txt') -Encoding ASCII

    Write-Host "backup: packaging $zipPath"
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $packageDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

    Write-Host "backup: encrypting to $GpgRecipient"
    # --trust-model always: the recipient key is imported but not web-of-trust
    # signed, which would otherwise make --batch refuse to encrypt.
    & $gpg --batch --yes --trust-model always --recipient $GpgRecipient `
           --output $finalPath --encrypt $zipPath
    if ($LASTEXITCODE -ne 0) { throw "gpg encryption failed with exit code $LASTEXITCODE." }
    if (-not (Test-Path -LiteralPath $finalPath)) { throw 'gpg reported success but produced no output file.' }

    # The plaintext package must not survive the run.
    Remove-Item -LiteralPath $zipPath -Force

    $finalHash = (Get-FileHash -LiteralPath $finalPath -Algorithm SHA256).Hash.ToLower()
    "{0}  {1}" -f $finalHash, (Split-Path -Leaf $finalPath) |
        Set-Content -LiteralPath "$finalPath.sha256" -Encoding ASCII

    if (-not $SkipRetention) {
        $days = switch ($Tier) {
            'hourly'  { $RetentionHourlyDays }
            'daily'   { $RetentionDailyDays }
            'weekly'  { $RetentionWeeklyDays }
            'monthly' { $RetentionMonthlyDays }
            default   { $RetentionManualDays }
        }
        if ($days -gt 0) {
            $cutoff = (Get-Date).AddDays(-$days)
            Get-ChildItem -LiteralPath $BackupRoot -File -Filter "$($Prefix)_$($Tier)_*" |
                Where-Object { $_.LastWriteTime -lt $cutoff } |
                ForEach-Object {
                    Write-Host "backup: pruning $($_.Name)"
                    Remove-Item -LiteralPath $_.FullName -Force
                }
        }
    }

    Write-Host "backup: completed $finalPath"
}
finally {
    if (Test-Path -LiteralPath $stagingDir) {
        Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $lockStream) {
        $lockStream.Close()
        $lockStream.Dispose()
        Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
    }
}
