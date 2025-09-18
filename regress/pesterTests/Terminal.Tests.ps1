param(
  #skip if non-interactive session
  [bool]$Skip=$true
  )

If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force

$tC = 1
$tI = 0
$suite = "sshclientterminal"

Describe "E2E scenarios for an interactive terminal" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] $suite
        if(-not (Test-Path $testDir))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $acl = Get-Acl $testDir
        $rights = [System.Security.AccessControl.FileSystemRights]"Read, Write"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($ssouser, $rights, "ContainerInherit,Objectinherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $testDir -AclObject $acl
    }

    AfterEach {$tI++;}

    Context "$tC - Basic Scenarios" {

        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - force pseudo-terminal allocation (-t)" -Skip:$Skip {
            $o = ssh -t test_target echo 1234
            $LASTEXITCODE | Should Be 0
            $o[0].Contains("1234") | Should Be $true
        }
    }
}
