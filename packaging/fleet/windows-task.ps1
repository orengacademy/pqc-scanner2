#Requires -RunAsAdministrator
#Requires -Version 5.1
#Requires -PSEdition Desktop
<#
.SYNOPSIS
  Register a daily pqcscan scheduled task that scans this host and reports to the fleet daemon.

.DESCRIPTION
  Requires Windows PowerShell 5.1 (Desktop edition); not PowerShell 7.
  This installer refuses to run over an existing install; to upgrade, stop the task, move
  %ProgramFiles%\pqcscan and %ProgramData%\pqcscan aside, re-run.
  Layout:
    %ProgramFiles%\pqcscan   pqcscan.exe and run-agent.ps1   (code: only administrators can write here)
    %ProgramData%\pqcscan    agent.env, agent\agent.token, agent\spool and agent\agent.db   (state)
  Each folder is created fresh and locked down at once: no inherited entries, SYSTEM and Administrators full
  control, and the task account (-RunAs) modify on state or read and execute on code. The script then verifies
  the folders and every file it writes with Get-Acl and fails if any other principal has access.
  -RunAs accepts NT AUTHORITY\SYSTEM (default), a per-service virtual account (NT SERVICE\<name>, the service
  must exist) or a group managed service account (DOMAIN\name$). Anything else is refused before anything is
  written: LOCAL SERVICE, NETWORK SERVICE and other shared accounts because every service running as them could
  read agent.env, a plain user because it needs a password this script does not take.
  It downloads the pinned release binary, verifies it against SHA256SUMS.txt, writes the enrollment token to
  agent.env, and registers a task that runs `pqcscan agent --once` daily at 02:00 plus up to 2 hours of
  random delay. The first run enrolls and stores agent\agent.token. Rotate the enroll token on the collector
  after rollout and delete agent.env.
  To rotate the token on this host or upgrade: stop the task, move %ProgramData%\pqcscan and %ProgramFiles%\pqcscan
  aside (this drops the spool and agent.token, so the host re-enrolls), then re-run this script.
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
    [string]$Version = "v0.10.2",
    # SYSTEM, a virtual account such as 'NT SERVICE\pqcscan', or a gMSA such as 'CORP\svc-pqcscan$'; anything else is refused.
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

# Refuse, before anything is written, any account that is shared or that the task cannot be registered for.
# SYSTEM (S-1-5-18) and a per-service virtual account (S-1-5-80-<5 parts>, never S-1-5-80-0 "ALL SERVICES") log on
# as ServiceAccount; a gMSA logs on as Password with no password. LOCAL SERVICE, NETWORK SERVICE and the like are
# shared by many services, any of which could then read the bearer token in agent.env; a plain user needs a
# password this script does not take.
# ponytail: a trailing '$' is taken to mean gMSA; a computer account (or a user named so) also ends in '$' and would still fail at
# registration, after the writes. Check the object class with the AD module if that ever matters.
$runAsSid = (New-Object System.Security.Principal.NTAccount($runAsName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$isGmsa = $runAsName.EndsWith('$')
if ($runAsSid -ne "S-1-5-18" -and $runAsSid -notmatch '^S-1-5-80(-\d+){5}$' -and -not $isGmsa) {
    throw ("-RunAs $runAsName is not supported: use NT AUTHORITY\SYSTEM (the default), a per-service virtual " +
        'account (NT SERVICE\<name>) or a group managed service account (DOMAIN\name$). LOCAL SERVICE, NETWORK ' +
        "SERVICE and other shared accounts are refused because every service running as them could read the token " +
        "in agent.env; a plain user needs a password this script does not take. Nothing was written.")
}

# Fail closed: never reuse or repair a folder somebody else may have prepared. A fresh folder is created
# atomically with its protected ACL (no window where it exists with default permissions), and the token is
# written only after the file's ACL has been verified.
$trusted = @($system, $admins)
$allowed = @($system, $admins, $runAsName)
$fsr   = [System.Security.AccessControl.FileSystemRights]
$flags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
$noProp = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow

function Assert-Acl([string]$Path) {
    # Owned by SYSTEM or Administrators, and only the expected principals on the ACL.
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if ($trusted -notcontains $acl.Owner) { throw "$Path is owned by $($acl.Owner), not SYSTEM/Administrators" }
    foreach ($rule in $acl.Access) {
        if ($allowed -notcontains $rule.IdentityReference.Value) {
            throw "Unexpected principal $($rule.IdentityReference.Value) on $Path"
        }
    }
}

function Protect-Folder([string]$Path, $RunAsRights) {
    if (Test-Path -LiteralPath $Path) {
        throw "refusing to use ${Path}: already exists - move it aside or remove it, then re-run"
    }
    # Protected (no inheritance from the parent), SYSTEM and Administrators full control, task account limited.
    # Owner is Administrators: an elevated administrator may always assign that group as owner.
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)
    $sec.SetOwner((New-Object System.Security.Principal.NTAccount($admins)))
    $grants = @(@($system, $fsr::FullControl), @($admins, $fsr::FullControl))
    if ($runAsName -ne $system -and $runAsName -ne $admins -and $RunAsRights) { $grants += ,@($runAsName, $RunAsRights) }
    foreach ($g in $grants) {
        $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.NTAccount($g[0])), $g[1], $flags, $noProp, $allow)))
    }
    [IO.Directory]::CreateDirectory($Path, $sec) | Out-Null
    # CreateDirectory succeeds silently on a path planted since the Test-Path check; a junction or symlink, a
    # foreign owner (Assert-Acl) or any content (below) all fail closed.
    if (((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "refusing to use ${Path}: reparse point"
    }
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) { throw "$Path is not empty right after creation" }
    Assert-Acl $Path
}

function Write-ProtectedFile([string]$Path, [string]$Content, [Text.Encoding]$Encoding) {
    # CreateNew fails if the file exists; the inherited ACL is verified before any content is written.
    [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write).Close()
    Assert-Acl $Path
    [IO.File]::WriteAllText($Path, $Content, $Encoding)
}

# Check both targets before creating either, so a failure on the second never leaves a half-made first.
foreach ($path in @($Data, $Bin)) {
    if (Test-Path -LiteralPath $path) {
        throw "refusing to use ${path}: already exists - move it aside or remove it, then re-run"
    }
}

# State: SYSTEM + Administrators full, the task account modify only.
Protect-Folder $Data ($fsr::Modify)
Protect-Folder $state ($fsr::Modify)

# Code: SYSTEM + Administrators full, the task account read and execute.
Protect-Folder $Bin ($fsr::ReadAndExecute)

# Download the pinned binary and verify it.
$tmp = Join-Path $Bin "download"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile (Join-Path $tmp "SHA256SUMS.txt")
$want = ((Get-Content (Join-Path $tmp "SHA256SUMS.txt")) -match [regex]::Escape($asset) | Select-Object -First 1) -split '\s+' | Select-Object -First 1
$got  = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash
if (-not $want -or $want.ToLower() -ne $got.ToLower()) { throw "SHA-256 mismatch for $asset" }
Move-Item (Join-Path $tmp $asset) $exe
Remove-Item -Recurse -Force $tmp
Assert-Acl $exe

# Enrollment token for the first run, in a file only the principals above can read.
Write-ProtectedFile $envFile $EnrollToken ([Text.Encoding]::ASCII)

# Wrapper: read the token, then `agent --once` (one cycle; trims its own local DB). The task action itself carries no secret.
$lab = if ($Labels) { " --labels `"$Labels`"" } else { "" }
$ca = if ($CaCert) { " --ca-cert `"$CaCert`"" } else { "" }
$body = @"
`$env:PQCSCAN_ENROLL_TOKEN = (Get-Content -Raw -ErrorAction SilentlyContinue "$envFile")
& "$exe" agent --once --server "$Server"$lab --state-dir "$state"$ca
exit `$LASTEXITCODE
"@
Write-ProtectedFile $wrapper $body (New-Object System.Text.UTF8Encoding($true))

$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$wrapper`""
$trigger   = New-ScheduledTaskTrigger -Daily -At 02:00 -RandomDelay (New-TimeSpan -Hours 2)
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew
$principal = if ($isGmsa) { New-ScheduledTaskPrincipal -UserId $runAsName -LogonType Password -RunLevel Highest }
             else { New-ScheduledTaskPrincipal -UserId $runAsName -LogonType ServiceAccount -RunLevel Highest }
Register-ScheduledTask -TaskName "pqcscan-agent" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
Write-Host "Registered task pqcscan-agent (daily 02:00 + up to 2h random delay) as $RunAs. Run it now with:"
Write-Host "  Start-ScheduledTask -TaskName pqcscan-agent"
