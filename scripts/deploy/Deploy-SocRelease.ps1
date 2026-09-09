<#
.SYNOPSIS
    Deploy a tagged SOC Ticket release to the Windows production VM.

.DESCRIPTION
    Automates section 3 of docs/operations/deploy-and-release.windows.md as one
    run, with the runbook's "read the output before the next step" discipline
    encoded as hard gates rather than left to the operator's attention:

      * every step aborts the whole deploy on a non-zero exit code
      * the backup must produce a non-empty .zip.gpg before anything changes
      * git describe must resolve to the tag actually asked for
      * -PurgeVulnerabilityAlerts deletes rows PERMANENTLY, so it refuses to
        run unless the live count equals -ExpectedVulnCount exactly

    The purge gate is the point of this script. A row deletion cannot be undone
    by checking out the previous tag (runbook 4b), so the count is verified
    against the number the operator was told to expect, and a mismatch stops the
    deploy with the data untouched.

    Pure ASCII on purpose: production is Windows Server and these files are
    edited in consoles and editors that mangle anything else.

.PARAMETER Tag
    Annotated git tag to deploy, e.g. v1.4.0.

.PARAMETER PurgeVulnerabilityAlerts
    Run purge_vulnerability_alerts after migrating. IRREVERSIBLE.

.PARAMETER ExpectedVulnCount
    The exact number of vulnerability alerts the purge must find. Required with
    -PurgeVulnerabilityAlerts. A mismatch aborts before deleting anything.

.PARAMETER GpgRecipient
    Recipient for the pre-deploy backup.

.PARAMETER SkipBackup
    Skip the pre-deploy backup. Refused when purging.

.EXAMPLE
    .\Deploy-SocRelease.ps1 -Tag v1.4.0 -PurgeVulnerabilityAlerts -ExpectedVulnCount 771

.EXAMPLE
    .\Deploy-SocRelease.ps1 -Tag v1.4.0
    Deploys the code only. The purge can be run later, on its own.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v\d+\.\d+\.\d+$')]
    [string] $Tag,

    [switch] $PurgeVulnerabilityAlerts,
    [int]    $ExpectedVulnCount = -1,

    [string] $AppRoot      = 'C:\SOCTicket\app',
    [string] $ServiceName  = 'SOCTicketWaitress',
    [string] $GpgRecipient = 'soc-backup@nt.local',
    [switch] $SkipBackup
)

$ErrorActionPreference = 'Stop'
$script:StepNumber = 0

function Write-Step {
    param([string] $Message)
    $script:StepNumber++
    Write-Host ''
    Write-Host ("=== Step {0}: {1}" -f $script:StepNumber, $Message) -ForegroundColor Cyan
}

function Assert-LastExitCode {
    param([string] $What)
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE. Deploy aborted; nothing further has run."
    }
}

# --- Preconditions ---------------------------------------------------------

if ($PurgeVulnerabilityAlerts) {
    if ($ExpectedVulnCount -lt 0) {
        throw '-PurgeVulnerabilityAlerts requires -ExpectedVulnCount. Run the dry run first and pass the number it reports.'
    }
    if ($SkipBackup) {
        throw 'Refusing to purge without a pre-deploy backup: a row deletion cannot be rolled back by checking out the previous tag.'
    }
}

if (-not (Test-Path $AppRoot)) { throw "App root not found: $AppRoot" }
Set-Location $AppRoot

$py = Join-Path $AppRoot 'venv\Scripts\python.exe'
if (-not (Test-Path $py)) { throw "Python not found: $py" }

Write-Host ("Deploying {0} to {1}" -f $Tag, $AppRoot) -ForegroundColor White

# --- 1. Backup -------------------------------------------------------------

if ($SkipBackup) {
    Write-Step 'Backup SKIPPED by request'
    Write-Warning 'No pre-deploy backup. Rollback from a data problem is not available.'
} else {
    Write-Step 'Pre-deploy backup'
    $before = Get-Date
    & .\scripts\backup\windows\New-SocBackup.ps1 -Tier manual -GpgRecipient $GpgRecipient
    Assert-LastExitCode 'Backup'

    # Trust the artifact, not the exit code: a backup that wrote nothing is the
    # failure mode that matters, and it is silent.
    $archive = Get-ChildItem -Recurse -Filter '*.zip.gpg' |
        Where-Object { $_.LastWriteTime -ge $before -and $_.Length -gt 0 } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $archive) {
        throw 'Backup produced no new non-empty .zip.gpg. Deploy aborted.'
    }
    Write-Host ("Backup OK: {0} ({1:N0} bytes)" -f $archive.Name, $archive.Length) -ForegroundColor Green
    Write-Host  'Record this filename in the deploy log.'
}

# --- 2. Check out the tag --------------------------------------------------

Write-Step "Check out $Tag"
git fetch --tags
Assert-LastExitCode 'git fetch'
git checkout $Tag
Assert-LastExitCode 'git checkout'

$described = (git describe --tags).Trim()
if ($described -ne $Tag) {
    throw "git describe reports '$described', expected '$Tag'. Deploy aborted."
}
Write-Host "Checked out $described (detached HEAD is expected)" -ForegroundColor Green

# --- 3. Dependencies -------------------------------------------------------

Write-Step 'Sync dependencies'
& $py -m pip install -r requirements.txt
Assert-LastExitCode 'pip install'

# --- 4. Migrate ------------------------------------------------------------

Write-Step 'Apply migrations'
& $py manage.py migrate
Assert-LastExitCode 'migrate'
Write-Host 'Note every migration listed above - you need it for rollback (runbook 4).' -ForegroundColor Yellow

# --- 5. Purge (irreversible, gated) ---------------------------------------

if ($PurgeVulnerabilityAlerts) {
    Write-Step 'Verify vulnerability alert count before purging'

    # Counted directly rather than scraped from the command's output: a console
    # codepage that mangles a character must not be able to change what gets
    # deleted.
    $countScript = "from apps.wazuh_ingest.models import WazuhAlert as W; print(W.objects.filter(kind=W.KIND_VULNERABILITY).count())"
    $actual = (& $py manage.py shell -c $countScript | Select-Object -Last 1).Trim()
    Assert-LastExitCode 'Vulnerability count'

    Write-Host ("Vulnerability alerts stored: {0} (expected {1})" -f $actual, $ExpectedVulnCount)
    if ([int] $actual -ne $ExpectedVulnCount) {
        throw ("Expected $ExpectedVulnCount vulnerability alerts but found $actual. " +
               'Nothing has been deleted. Investigate before purging: a mismatch means ' +
               'the classifier and the live data disagree.')
    }

    & $py manage.py purge_vulnerability_alerts --dry-run
    Assert-LastExitCode 'Purge dry run'

    Write-Step 'Purge vulnerability alerts (IRREVERSIBLE)'
    & $py manage.py purge_vulnerability_alerts
    Assert-LastExitCode 'Purge'
} else {
    Write-Step 'Purge skipped (no -PurgeVulnerabilityAlerts)'
}

# --- 6. Static + restart ---------------------------------------------------

Write-Step 'Collect static files'
& $py manage.py collectstatic --noinput
Assert-LastExitCode 'collectstatic'

Write-Step "Restart $ServiceName"
Restart-Service $ServiceName
(Get-Service $ServiceName).Status

# --- 7. Verify -------------------------------------------------------------

Write-Step 'Verify'
$health = curl.exe -s -H 'X-Forwarded-Proto: https' http://127.0.0.1:8000/healthz
Write-Host "healthz: $health"
if ($health -notmatch '"status"\s*:\s*"ok"')       { throw "healthz did not report status ok: $health" }
if ($health -notmatch '"database"\s*:\s*"ok"')     { throw "healthz did not report database ok: $health" }

& $py manage.py check --deploy

# --- 8. Record the release -------------------------------------------------

Write-Step 'Set APP_VERSION in .env'
$envPath = Join-Path $AppRoot '.env'
if (Test-Path $envPath) {
    $lines = @(Get-Content $envPath)
    if ($lines -match '^\s*APP_VERSION\s*=') {
        $lines = $lines | ForEach-Object {
            if ($_ -match '^\s*APP_VERSION\s*=') { "APP_VERSION=$Tag" } else { $_ }
        }
    } else {
        $lines += "APP_VERSION=$Tag"
    }
    # UTF8 WITHOUT a BOM. Out-File and Set-Content both get this wrong here: a
    # BOM turns the first key into \ufeffSECRET_KEY and Django will not start.
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllLines($envPath, $lines, $utf8NoBom)
    Write-Host "APP_VERSION=$Tag written" -ForegroundColor Green

    Restart-Service $ServiceName
    $health = curl.exe -s -H 'X-Forwarded-Proto: https' http://127.0.0.1:8000/healthz
    Write-Host "healthz: $health"
    if ($health -notmatch [regex]::Escape($Tag)) {
        Write-Warning "healthz does not report $Tag. Check APP_VERSION in $envPath."
    }
} else {
    Write-Warning "No .env at $envPath - set APP_VERSION manually."
}

# --- Done ------------------------------------------------------------------

Write-Host ''
Write-Host ("Deploy of {0} complete." -f $Tag) -ForegroundColor Green
Write-Host 'Still to do by hand:'
Write-Host '  1. From a third host: curl.exe -k https://10.1.220.118/healthz  (expect 200, new version)'
Write-Host '  2. Log in: dashboard renders styled, a ticket opens, triage queue looks right.'
Write-Host '  3. Append the deploy-log line (date, tag, operator, OK, what, backup filename).'
Write-Host '  4. Update the spare VM to the same tag, service left stopped.'
