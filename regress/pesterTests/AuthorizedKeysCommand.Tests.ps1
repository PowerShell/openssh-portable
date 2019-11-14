If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$tC = 1
$tI = 0
$suite = "authorizedKeysCommand"
        
Describe "E2E scenarios for AuthorizedKeysCommand" -Tags "CI" {
    BeforeAll {        
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $server = $OpenSSHTestInfo["Target"]
        $opensshbinpath = $OpenSSHTestInfo['OpenSSHBinPath']
        $port = 47004

        $server = $OpenSSHTestInfo["Target"]
        $port = 47004
        $opensshbinpath = $OpenSSHTestInfo['OpenSSHBinPath']
        $sshdconfig = Join-Path $Global:OpenSSHTestInfo["ServiceConfigDir"] sshd_config

        $testDir = Join-Path $OpenSSHTestInfo["TestDataPath"] $suite
        if(-not (Test-Path $testDir))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        

    AfterEach {$tI++;}

    Context "$tC - basic test cases" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - keys command with %k argument" {
            #override authorizedkeysfile location to an unknown location, so AuthorizedKeysCommand gets executed
            $kcOutFile = Join-Path $testDir "$tC.$tI.kcout.txt"
            $sshdArgs = "-dd -f $sshdconfig  -E $logFile -o `"AuthorizedKeysFile .fake/authorized_keys`""
            $sshdArgs += " -o `"AuthorizedKeysCommand=$env:windir\system32\cmd /c echo ssh-ed25519 %k & whoami > $kcOutFile`""
            $sshdArgs += " -o `"AuthorizedKeysCommandUser=$env:USERNAME`""
            $sshdArgs += " -o PasswordAuthentication=no"
            Write-Host $sshdArgs
            Start-SSHDTestDaemon -WorkDir $opensshbinpath -Arguments $sshdArgs -Port $port
            $o = ssh -p $port $server echo 1234
            Stop-SSHDTestDaemon -Port $port
            $o | Should Be "1234"
            #check the command is run us AuthorizedKeysCommandUser
            (gc $kcOutFile).Contains($env:USERNAME) | Should Be $true
        }

    }
}
