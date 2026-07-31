#Requires -Version 5.1
<#
.SYNOPSIS
    Captures production's CONFIGURATION (not data) into an encrypted bundle.
    Runs on the PRODUCTION VM.

.DESCRIPTION
    New-SocBackup.ps1 protects the database and media. It does NOT capture what
    is needed to REBUILD the host: the .env secrets, the IIS site and rewrite
    rules, the Waitress service definition, the scheduled tasks, and the
    firewall rules. Without those, a total production loss means reconstructing
    the deployment from memory while under pressure.

    This writes soc_ticket_config_<utc-timestamp>.zip.gpg into the same archive
    directory, so it is pulled to the spare VM by the same job as everything
    else. It is small (kilobytes) and safe to run weekly.

    ENCRYPTED FOR A REASON: the bundle contains .env, which holds SECRET_KEY,
    the database password, SMTP credentials, and OpenSearch credentials. It uses
    the same GPG recipient as the data backups, so production can write it but
    cannot read it back.

.EXAMPLE
    .\New-SocConfigBundle.ps1 -GpgRecipient soc-backup@nt.local -EnvPath C:\SOCTicket\app\.env

.NOTES
    See docs/operations/backup-and-standby-handbook.windows.md
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GpgRecipient,

    [string]$EnvPath          = 'C:\SOCTicket\app\.env',
    [string]$BackupRoot       = 'C:\SOCBackup\archive',
    [string]$Prefix           = 'soc_ticket',
    [string]$GpgExe           = 'C:\Program Files (x86)\GnuPG\bin\gpg.exe',
    [string]$GpgHome          = 'C:\ProgramData\SOCBackup\gnupg',

    # Windows service that runs Waitress, so its definition can be recreated.
    [string]$AppServiceName   = 'SOCTicketWaitress',

    # Scheduled tasks to capture, by name pattern.
    [string]$TaskNamePattern  = 'SOC-*',

    # Firewall rules to capture, by display-name pattern.
    [string]$FirewallPattern  = '*SOC*',

    # Extra files to include (TLS chain, OpenSearch CA, IIS web.config, ...).
    [string[]]$ExtraFiles     = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $GpgExe)) { throw "gpg.exe not found at $GpgExe" }
if (-not (Test-Path -LiteralPath $BackupRoot)) {
    New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
}
$env:GNUPGHOME = $GpgHome

$timestamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$bundleName = "{0}_config_{1}" -f $Prefix, $timestamp
$stagingDir = Join-Path $BackupRoot ".$bundleName.staging"
$zipPath    = Join-Path $BackupRoot "$bundleName.zip"
$finalPath  = "$zipPath.gpg"

New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

try {
    # -- Application secrets -------------------------------------------------
    if (Test-Path -LiteralPath $EnvPath) {
        Copy-Item -LiteralPath $EnvPath -Destination (Join-Path $stagingDir 'env.txt')
        Write-Host "config: captured $EnvPath"
    }
    else {
        Write-Warning "config: .env not found at $EnvPath - the bundle will not restore app settings"
    }

    # -- IIS -----------------------------------------------------------------
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    if (Test-Path -LiteralPath $appcmd) {
        & $appcmd list site /config /xml   | Out-File (Join-Path $stagingDir 'iis-sites.xml')     -Encoding UTF8
        & $appcmd list app /config /xml    | Out-File (Join-Path $stagingDir 'iis-apps.xml')      -Encoding UTF8
        & $appcmd list apppool /config /xml| Out-File (Join-Path $stagingDir 'iis-apppools.xml')  -Encoding UTF8
        & $appcmd list vdir /config /xml   | Out-File (Join-Path $stagingDir 'iis-vdirs.xml')     -Encoding UTF8

        # applicationHost.config carries the URL Rewrite / ARR proxy rules that
        # the per-site exports above do not fully reproduce.
        $appHost = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
        if (Test-Path -LiteralPath $appHost) {
            Copy-Item -LiteralPath $appHost -Destination (Join-Path $stagingDir 'applicationHost.config')
        }
        Write-Host 'config: captured IIS configuration'
    }
    else {
        Write-Warning 'config: appcmd.exe not found - skipping IIS capture'
    }

    # -- Waitress / app service ----------------------------------------------
    $svc = Get-CimInstance Win32_Service -Filter "Name = '$AppServiceName'" -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        $svc | Select-Object Name, DisplayName, PathName, StartMode, StartName, Description |
            ConvertTo-Json -Depth 3 |
            Set-Content (Join-Path $stagingDir 'app-service.json') -Encoding UTF8
        Write-Host "config: captured service $AppServiceName"
    }
    else {
        Write-Warning "config: service '$AppServiceName' not found - pass -AppServiceName if it is named differently"
    }

    # -- Scheduled tasks ------------------------------------------------------
    $taskDir = Join-Path $stagingDir 'scheduled-tasks'
    New-Item -ItemType Directory -Path $taskDir -Force | Out-Null
    $tasks = @(Get-ScheduledTask -TaskName $TaskNamePattern -ErrorAction SilentlyContinue)
    foreach ($task in $tasks) {
        $safe = $task.TaskName -replace '[^A-Za-z0-9_.-]', '_'
        Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath |
            Set-Content (Join-Path $taskDir "$safe.xml") -Encoding UTF8
    }
    Write-Host "config: captured $($tasks.Count) scheduled task(s)"

    # -- Firewall rules -------------------------------------------------------
    $rules = @(Get-NetFirewallRule -DisplayName $FirewallPattern -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 0) {
        $rules | ForEach-Object {
            $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            [ordered]@{
                DisplayName   = $_.DisplayName
                Direction     = "$($_.Direction)"
                Action        = "$($_.Action)"
                Enabled       = "$($_.Enabled)"
                Protocol      = "$($pf.Protocol)"
                LocalPort     = "$($pf.LocalPort)"
                RemoteAddress = "$($af.RemoteAddress)"
            }
        } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $stagingDir 'firewall-rules.json') -Encoding UTF8
    }
    Write-Host "config: captured $($rules.Count) firewall rule(s)"

    # -- PostgreSQL server configuration --------------------------------------
    # postgresql.conf and pg_hba.conf are NOT in the pg_dump archive, and both
    # are needed to rebuild a working cluster (replication settings, TLS, auth).
    $pgSvc = Get-CimInstance Win32_Service -Filter "Name LIKE 'postgresql%'" -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($null -ne $pgSvc -and $pgSvc.PathName -match '-D\s+"([^"]+)"') {
        $dataDir = $Matches[1]
        foreach ($f in @('postgresql.conf', 'pg_hba.conf', 'pg_ident.conf')) {
            $src = Join-Path $dataDir $f
            if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination (Join-Path $stagingDir $f) }
        }
        Write-Host "config: captured PostgreSQL configuration from $dataDir"
    }
    else {
        Write-Warning 'config: could not locate the PostgreSQL data directory - copy postgresql.conf and pg_hba.conf manually'
    }

    # -- Anything else the operator named -------------------------------------
    foreach ($extra in $ExtraFiles) {
        if (Test-Path -LiteralPath $extra) {
            Copy-Item -LiteralPath $extra -Destination $stagingDir
            Write-Host "config: captured $extra"
        }
        else {
            Write-Warning "config: extra file not found: $extra"
        }
    }

    [ordered]@{
        bundle_name    = $bundleName
        created_at_utc = $timestamp
        host           = $env:COMPUTERNAME
        contents       = @(Get-ChildItem -LiteralPath $stagingDir -Recurse -File |
                           ForEach-Object { $_.FullName.Substring($stagingDir.Length + 1) })
    } | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $stagingDir 'manifest.json') -Encoding UTF8

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $stagingDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

    & $GpgExe --batch --yes --trust-model always --recipient $GpgRecipient `
              --output $finalPath --encrypt $zipPath
    if ($LASTEXITCODE -ne 0) { throw "gpg encryption failed with exit code $LASTEXITCODE." }
    if (-not (Test-Path -LiteralPath $finalPath)) { throw 'gpg reported success but produced no output file.' }

    # The plaintext bundle contains secrets and must not survive the run.
    Remove-Item -LiteralPath $zipPath -Force

    $hash = (Get-FileHash -LiteralPath $finalPath -Algorithm SHA256).Hash.ToLower()
    "{0}  {1}" -f $hash, (Split-Path -Leaf $finalPath) |
        Set-Content -LiteralPath "$finalPath.sha256" -Encoding ASCII

    Write-Host "config: completed $finalPath"
}
finally {
    if (Test-Path -LiteralPath $stagingDir) {
        Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    }
}
