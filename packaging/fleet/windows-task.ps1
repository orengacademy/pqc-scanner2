<#
.SYNOPSIS
  Register a daily pqcscan scheduled task that scans this host and reports to the fleet daemon.

.DESCRIPTION
  Downloads the pinned release binary, verifies it against SHA256SUMS.txt, writes the enrollment token to
  %ProgramData%\pqcscan\agent.env (ACL: SYSTEM + Administrators + the task account), and registers a task
  that runs `pqcscan scan --report-to` daily at 02:00 plus up to 2 hours of random delay.
  The first run enrolls and stores %ProgramData%\pqcscan\agent\agent.token. Rotate the enroll token on the
  collector after rollout and delete agent.env (or re-run this script with a new token).
  For a private CA pass -CaCert; TLS verification is never switched off.

.EXAMPLE
  .\windows-task.ps1 -Server https://pqc.internal:8765 -EnrollToken $env:ENROLL -Labels env=prod,group=web
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$EnrollToken,
    [string]$Labels = "",
    [string]$Version = "v0.10.1",
    # A dedicated service account (for example a gMSA such as 'CORP\svc-pqcscan$') is preferred over SYSTEM.
    # SYSTEM is the default because a full host inventory needs to read protected paths.
    [string]$RunAs = "NT AUTHORITY\SYSTEM",
    [string]$CaCert = "",
    [string]$Dir = (Join-Path $env:ProgramData "pqcscan")
)
$ErrorActionPreference = "Stop"
if ($Server -notmatch '^https://') { throw "-Server must be https:// (agent tokens are bearer credentials)" }

$asset = "pqcscan-windows-x86_64.exe"
$base  = "https://github.com/orengacademy/pqc-scanner2/releases/download/$Version"
$exe   = Join-Path $Dir "pqcscan.exe"
New-Item -ItemType Directory -Force -Path $Dir, (Join-Path $Dir "agent") | Out-Null

# Lock the directory down before any secret lands in it: SYSTEM, Administrators and the task account only.
$accounts = @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", $RunAs) | Select-Object -Unique
icacls $Dir /inheritance:r | Out-Null
foreach ($a in $accounts) { icacls $Dir /grant:r "${a}:(OI)(CI)F" | Out-Null }

# Download the pinned binary and verify it.
$tmp = Join-Path $Dir "download"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile (Join-Path $tmp "SHA256SUMS.txt")
$want = ((Get-Content (Join-Path $tmp "SHA256SUMS.txt")) -match [regex]::Escape($asset) | Select-Object -First 1) -split '\s+' | Select-Object -First 1
$got  = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash
if (-not $want -or $want.ToLower() -ne $got.ToLower()) { throw "SHA-256 mismatch for $asset" }
Move-Item -Force (Join-Path $tmp $asset) $exe
Remove-Item -Recurse -Force $tmp

# Enrollment token for the first run, in a file only the accounts above can read.
Set-Content -Path (Join-Path $Dir "agent.env") -Value $EnrollToken -NoNewline -Encoding ascii

# Wrapper: read the token, then `scan --report-to`. The task action itself carries no secret.
$ca = if ($CaCert) { " --ca-cert `"$CaCert`"" } else { "" }
$wrapper = @"
`$env:PQCSCAN_ENROLL_TOKEN = (Get-Content -Raw -ErrorAction SilentlyContinue "$Dir\agent.env")
& "$exe" scan --fail-on none --report-to "$Server" --labels "$Labels" --db "$Dir\pqcscan.db" --state-dir "$Dir\agent"$ca
exit `$LASTEXITCODE
"@
Set-Content -Path (Join-Path $Dir "run-agent.ps1") -Value $wrapper -Encoding utf8

$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Dir\run-agent.ps1`""
$trigger   = New-ScheduledTaskTrigger -Daily -At 02:00 -RandomDelay (New-TimeSpan -Hours 2)
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew
$principal = if ($RunAs -match 'SYSTEM$') { New-ScheduledTaskPrincipal -UserId $RunAs -LogonType ServiceAccount -RunLevel Highest }
             else { New-ScheduledTaskPrincipal -UserId $RunAs -LogonType Password -RunLevel Highest }
Register-ScheduledTask -TaskName "pqcscan-agent" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
Write-Host "Registered task pqcscan-agent (daily 02:00 + up to 2h random delay) as $RunAs. Run it now with:"
Write-Host "  Start-ScheduledTask -TaskName pqcscan-agent"
