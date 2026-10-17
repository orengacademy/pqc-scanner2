#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
  Pester 5 tests for packaging/fleet/windows-task.ps1, run AS SHIPPED against the pinned v0.10.2 release asset.

.DESCRIPTION
  Needs Windows PowerShell 5.1 (the installer is Desktop-only) and an elevated administrator. The tests install
  into the real %ProgramFiles%\pqcscan and %ProgramData%\pqcscan and register the real task "pqcscan-agent", then
  remove all three in AfterAll. They refuse to run when any of those already exists, unless GITHUB_ACTIONS is
  "true", so a developer machine with a real install is never touched.

  The installer never connects to the server, so -Server only has to be https; nothing listens on port 9.

  Run:  Invoke-Pester -Path .\packaging\fleet\windows-task.Tests.ps1 -Output Detailed
#>

BeforeDiscovery {
    $dir = Join-Path $env:ProgramFiles "pqcscan"
    $dat = Join-Path $env:ProgramData "pqcscan"
    # Everything the installer writes, for the per-path ACL checks.
    $script:AclPaths = @(
        @{ Path = $dir }
        @{ Path = $dat }
        @{ Path = (Join-Path $dat "agent") }
        @{ Path = (Join-Path $dir "pqcscan.exe") }
        @{ Path = (Join-Path $dir "run-agent.ps1") }
        @{ Path = (Join-Path $dat "agent.env") }
    )
}

BeforeAll {
    $script:Installer = Join-Path $PSScriptRoot "windows-task.ps1"
    $script:Bin       = Join-Path $env:ProgramFiles "pqcscan"
    $script:Data      = Join-Path $env:ProgramData "pqcscan"
    $script:TaskName  = "pqcscan-agent"
    $script:Server    = "https://127.0.0.1:9"
    $script:Token     = "pester-enroll-token-not-a-secret"
    $script:Allowed   = @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators")

    function Invoke-Installer {
        # A child powershell.exe, like an operator or Ansible would run it. Exit code and all output come back.
        param([string]$ServerUrl = $script:Server)
        $ErrorActionPreference = "Continue"
        $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script:Installer `
            -Server $ServerUrl -EnrollToken $script:Token -Version v0.10.2 2>&1 | Out-String
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out }
    }

    function Remove-Install {
        Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
        foreach ($p in @($script:Bin, $script:Data)) {
            $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            if (-not $item) { continue }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                cmd.exe /c rmdir "`"$p`"" | Out-Null          # drop the junction, never what it points at
            } else {
                Remove-Item -LiteralPath $p -Recurse -Force
            }
        }
    }

    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "these tests install a SYSTEM scheduled task; run them from an elevated PowerShell"
    }
    $busy = @($script:Bin, $script:Data) | Where-Object { Get-Item -LiteralPath $_ -Force -ErrorAction SilentlyContinue }
    if (($busy -or (Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue)) -and
        $env:GITHUB_ACTIONS -ne "true") {
        throw "a pqcscan install already exists on this machine; move it aside before running these tests"
    }
    Remove-Install                                             # a clean runner has nothing; make sure
}

AfterAll {
    Remove-Install
}

Describe "windows-task.ps1 on a clean host" {
    BeforeAll {
        $script:First  = Invoke-Installer
        $script:Second = Invoke-Installer
    }

    It "installs: exit code 0 and the task is announced" {
        $First.ExitCode | Should -Be 0 -Because $First.Output
        $First.Output | Should -Match "Registered task pqcscan-agent"
    }

    Context "the scheduled task" {
        BeforeAll { $script:Task = Get-ScheduledTask -TaskName "pqcscan-agent" }

        It "is registered" { $Task | Should -Not -BeNullOrEmpty }

        It "runs the wrapper under Program Files, and nothing else" {
            $a = $Task.Actions
            $a.Count | Should -Be 1
            $a[0].Execute | Should -Be "powershell.exe"
            $a[0].Arguments | Should -Match ([regex]::Escape((Join-Path $env:ProgramFiles "pqcscan\run-agent.ps1")))
            $a[0].Arguments | Should -Match "-File"
        }

        It "carries no secret in the action or the wrapper's command line" {
            ($Task.Actions | Out-String) | Should -Not -Match $Token
        }

        It "runs as SYSTEM with highest privileges, daily at 02:00" {
            $Task.Principal.UserId | Should -Match "SYSTEM"
            $Task.Principal.RunLevel | Should -Be "Highest"
            $Task.Triggers.Count | Should -Be 1
            $Task.Triggers[0].StartBoundary | Should -Match "T02:00:00"
        }
    }

    Context "files the installer wrote" {
        It "downloaded the pinned binary and removed the staging folder" {
            Test-Path -LiteralPath (Join-Path $Bin "pqcscan.exe") | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $Bin "download") | Should -BeFalse
        }

        It "installed the v0.10.2 binary" {
            (& (Join-Path $Bin "pqcscan.exe") version 2>&1 | Out-String) | Should -Match "0\.10\.2"
        }

        It "wrote the wrapper with the server URL and a one-shot agent run" {
            $w = Get-Content -Raw -LiteralPath (Join-Path $Bin "run-agent.ps1")
            $w | Should -Match "agent --once"
            $w | Should -Match ([regex]::Escape($Server))
            $w | Should -Not -Match $Token                      # the token stays in agent.env only
        }

        It "wrote agent.env with exactly the enroll token" {
            [IO.File]::ReadAllText((Join-Path $Data "agent.env")) | Should -BeExactly $Token
        }
    }

    Context "ACLs" {
        It "<Path> is owned by SYSTEM or Administrators and lists nobody else" -ForEach $AclPaths {
            $acl = Get-Acl -LiteralPath $Path
            $Allowed | Should -Contain $acl.Owner
            $acl.Access.Count | Should -BeGreaterThan 0
            foreach ($rule in $acl.Access) {
                $Allowed | Should -Contain $rule.IdentityReference.Value -Because "$Path grants $($rule.FileSystemRights) to $($rule.IdentityReference.Value)"
                $rule.AccessControlType | Should -Be "Allow"
            }
        }

        It "<Path> blocks inheritance from its parent" -ForEach @(
            @{ Path = (Join-Path $env:ProgramFiles "pqcscan") }
            @{ Path = (Join-Path $env:ProgramData "pqcscan") }
            @{ Path = (Join-Path (Join-Path $env:ProgramData "pqcscan") "agent") }
        ) {
            (Get-Acl -LiteralPath $Path).AreAccessRulesProtected | Should -BeTrue
        }
    }

    Context "agent.env ordering" {
        It "is created empty, ACL-checked, and only then given the token" {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$null)
            $fn = $ast.Find({
                param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $n.Name -eq "Write-ProtectedFile" }, $true)
            $fn | Should -Not -BeNullOrEmpty
            $text = $fn.Body.Extent.Text
            $create = $text.IndexOf("[IO.FileMode]::CreateNew")
            $check  = $text.IndexOf("Assert-Acl")
            $write  = $text.IndexOf("WriteAllText")
            $create | Should -BeGreaterOrEqual 0
            $check  | Should -BeGreaterThan $create
            $write  | Should -BeGreaterThan $check
            # and agent.env goes through that helper, not around it
            (Get-Content -Raw -LiteralPath $Installer) | Should -Match 'Write-ProtectedFile\s+\$envFile\s+\$EnrollToken'
        }
    }

    Context "a second run" {
        It "refuses over the existing install and says so" {
            $Second.ExitCode | Should -Not -Be 0
            $Second.Output | Should -Match "already exists"
        }

        It "leaves the first install untouched" {
            [IO.File]::ReadAllText((Join-Path $Data "agent.env")) | Should -BeExactly $Token
            @(Get-ScheduledTask -TaskName "pqcscan-agent").Count | Should -Be 1
        }
    }
}

Describe "windows-task.ps1 refuses a pre-planted junction" {
    BeforeAll {
        Remove-Install
        $script:Target = Join-Path ([IO.Path]::GetTempPath()) ("pqc-junction-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $Target | Out-Null
    }
    AfterAll {
        Remove-Install
        Remove-Item -LiteralPath $Target -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "refuses a junction at %ProgramData%\pqcscan that points at an existing folder, and writes nothing through it" {
        New-Item -ItemType Junction -Path $Data -Target $Target | Out-Null
        $r = Invoke-Installer
        Write-Host "installer said: $($r.Output.Trim())"
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match "already exists|reparse point"
        @(Get-ChildItem -LiteralPath $Target -Force).Count | Should -Be 0
        Test-Path -LiteralPath $Bin | Should -BeFalse
        Get-ScheduledTask -TaskName "pqcscan-agent" -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Remove-Install
    }

    It "refuses a junction whose target does not exist yet, and writes nothing through it" {
        $dangling = Join-Path ([IO.Path]::GetTempPath()) ("pqc-dangling-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dangling | Out-Null
        New-Item -ItemType Junction -Path $Data -Target $dangling | Out-Null
        Remove-Item -LiteralPath $dangling -Force                  # the junction now dangles
        try {
            $r = Invoke-Installer
            Write-Host "installer said: $($r.Output.Trim())"
            $r.ExitCode | Should -Not -Be 0
            $r.Output | Should -Match "already exists|reparse point"
            Test-Path -LiteralPath (Join-Path $Data "agent.env") | Should -BeFalse
            Test-Path -LiteralPath $Bin | Should -BeFalse
            Get-ScheduledTask -TaskName "pqcscan-agent" -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        } finally {
            Remove-Install
            Remove-Item -LiteralPath $dangling -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It "refuses a junction at %ProgramFiles%\pqcscan" {
        New-Item -ItemType Junction -Path $Bin -Target $Target | Out-Null
        $r = Invoke-Installer
        Write-Host "installer said: $($r.Output.Trim())"
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match "already exists|reparse point"
        @(Get-ChildItem -LiteralPath $Target -Force).Count | Should -Be 0
        Test-Path -LiteralPath $Data | Should -BeFalse
    }
}

Describe "windows-task.ps1 argument checks" {
    It "refuses a plain-http server before touching the disk" {
        $r = Invoke-Installer -ServerUrl "http://127.0.0.1:9"
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match "must be https"
        Test-Path -LiteralPath $Bin | Should -BeFalse
        Test-Path -LiteralPath $Data | Should -BeFalse
    }
}
