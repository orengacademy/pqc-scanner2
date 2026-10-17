#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Register a daily pqcscan scheduled task that scans this host and reports to the fleet daemon.

.DESCRIPTION
  Layout (both folders are re-owned and re-ACL'd on every run, so a pre-existing folder planted by a
  non-admin cannot keep control of the token or the code):
    %ProgramFiles%\pqcscan   pqcscan.exe and run-agent.ps1   (code: only administrators can write here)
    %ProgramData%\pqcscan    agent.env, pqcscan.db, agent\agent.token and agent\spool   (state)
  The state folder is owned by SYSTEM, inherits nothing, and grants only SYSTEM and Administrators full
  control and the task account (-RunAs) modify. The script verifies that with Get-Acl and fails if any
  other principal has access.
  It downloads the pinned release binary, verifies it against SHA256SUMS.txt, writes the enrollment token to
  agent.env, and registers a task that runs `pqcscan scan --report-to` daily at 02:00 plus up to 2 hours of
  random delay. The first run enrolls and stores agent\agent.token. Rotate the enroll token on the collector
  after rollout and delete agent.env (or re-run this script with a new token).
  For a private CA pass -CaCert (keep the file in a folder only administrators can write); TLS verification
  is never switched off.

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
    [string]$Bin = (Join-Path $env:ProgramFiles "pqcscan"),
    [string]$Data = (Join-Path $env:ProgramData "pqcscan")
)
$ErrorActionPreference = "Stop"
if ($Server -notmatch '^https://') { throw "-Server must be https:// (agent tokens are bearer credentials)" }

$asset   = "pqcscan-windows-x86_64.exe"
$base    = "https://github.com/orengacademy/pqc-scanner2/releases/download/$Version"
$exe     = Join-Path $Bin "pqcscan.exe"
$wrapper = Join-Path $Bin "run-agent.ps1"
$envFile = Join-Path $Data "agent.env"
$state   = Join-Path $Data "agent"

function Get-AccountName([string]$Name) {
    (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier]).
        Translate([System.Security.Principal.NTAccount]).Value
}
$system = Get-AccountName "NT AUTHORITY\SYSTEM"
$admins = Get-AccountName "BUILTIN\Administrators"
$runAsName = Get-AccountName $RunAs

# Fail closed: never repair a folder somebody else may have prepared. A pre-existing folder is only reused
# if SYSTEM or Administrators own it and neither it nor anything under it is a reparse point (junction or symlink).
$trusted = @($system, $admins)
$allowed = @($system, $admins, $runAsName)

function Get-Tree([string]$Path) {
    # Walks without descending into reparse points; throws on the first one it meets.
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push((Get-Item -LiteralPath $Path -Force -ErrorAction Stop))
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "refusing to use ${Path}: pre-existing folder not owned by SYSTEM/Administrators or contains a reparse point ($($item.FullName)) - remove it and re-run"
        }
        $item
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) { $stack.Push($child) }
        }
    }
}

function Assert-Folder([string]$Path) {
    # Every item: owned by SYSTEM or Administrators, and only the expected principals on its ACL.
    foreach ($item in @(Get-Tree $Path)) {
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        if ($trusted -notcontains $acl.Owner) { throw "$($item.FullName) is owned by $($acl.Owner), not SYSTEM/Administrators" }
        foreach ($rule in $acl.Access) {
            if ($allowed -notcontains $rule.IdentityReference.Value) {
                throw "Unexpected principal $($rule.IdentityReference.Value) on $($item.FullName)"
            }
        }
    }
}

function Invoke-Icacls {
    & icacls @args | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls $($args -join ' ') failed with exit code $LASTEXITCODE" }
}

function Protect-Folder([string]$Path, [string[]]$Grants) {
    if (Test-Path -LiteralPath $Path) {
        $owner = (Get-Acl -LiteralPath $Path -ErrorAction Stop).Owner
        if ($trusted -notcontains $owner) {
            throw "refusing to use ${Path}: pre-existing folder not owned by SYSTEM/Administrators or contains a reparse point - remove it and re-run"
        }
        Get-Tree $Path | Out-Null
    } else {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
    Invoke-Icacls $Path /setowner $system /T
    Invoke-Icacls $Path /reset /T
    Invoke-Icacls $Path /inheritance:r /grant:r @Grants
    Assert-Folder $Path
}

# State: SYSTEM + Administrators full, the task account modify only.
$stateGrants = @("${system}:(OI)(CI)F", "${admins}:(OI)(CI)F")
if ($runAsName -ne $system -and $runAsName -ne $admins) { $stateGrants += "${runAsName}:(OI)(CI)M" }
Protect-Folder $Data $stateGrants
if (-not (Test-Path -LiteralPath $state)) { New-Item -ItemType Directory -Path $state | Out-Null }
Assert-Folder $state

# Code: SYSTEM + Administrators full, the task account read and execute.
$codeGrants = @("${system}:(OI)(CI)F", "${admins}:(OI)(CI)F")
if ($runAsName -ne $system -and $runAsName -ne $admins) { $codeGrants += "${runAsName}:(OI)(CI)RX" }
Protect-Folder $Bin $codeGrants

# Remove anything left from an earlier install before writing fresh copies.
foreach ($f in @($exe, $wrapper, $envFile)) { if (Test-Path $f) { Remove-Item -Force $f } }

# Download the pinned binary and verify it.
$tmp = Join-Path $Bin "download"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile (Join-Path $tmp "SHA256SUMS.txt")
$want = ((Get-Content (Join-Path $tmp "SHA256SUMS.txt")) -match [regex]::Escape($asset) | Select-Object -First 1) -split '\s+' | Select-Object -First 1
$got  = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash
if (-not $want -or $want.ToLower() -ne $got.ToLower()) { throw "SHA-256 mismatch for $asset" }
Move-Item -Force (Join-Path $tmp $asset) $exe
Remove-Item -Recurse -Force $tmp

# Enrollment token for the first run, in a file only the principals above can read.
Set-Content -Path $envFile -Value $EnrollToken -NoNewline -Encoding ascii

# Wrapper: read the token, then `scan --report-to`. The task action itself carries no secret.
$ca = if ($CaCert) { " --ca-cert `"$CaCert`"" } else { "" }
$body = @"
`$env:PQCSCAN_ENROLL_TOKEN = (Get-Content -Raw -ErrorAction SilentlyContinue "$envFile")
& "$exe" scan --fail-on none --report-to "$Server" --labels "$Labels" --db "$Data\pqcscan.db" --state-dir "$state"$ca
exit `$LASTEXITCODE
"@
Set-Content -Path $wrapper -Value $body -Encoding utf8

$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$wrapper`""
$trigger   = New-ScheduledTaskTrigger -Daily -At 02:00 -RandomDelay (New-TimeSpan -Hours 2)
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew
$principal = if ($runAsName -eq $system) { New-ScheduledTaskPrincipal -UserId $system -LogonType ServiceAccount -RunLevel Highest }
             else { New-ScheduledTaskPrincipal -UserId $RunAs -LogonType Password -RunLevel Highest }
Register-ScheduledTask -TaskName "pqcscan-agent" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
Write-Host "Registered task pqcscan-agent (daily 02:00 + up to 2h random delay) as $RunAs. Run it now with:"
Write-Host "  Start-ScheduledTask -TaskName pqcscan-agent"
