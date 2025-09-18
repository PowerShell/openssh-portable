Import-Module $PSScriptRoot\CommonUtils.psm1 -Force

Describe "E2E scenarios for sshd" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $user = $OpenSSHTestInfo["PasswdUser"]
    }

    Context "SSHD scenarios" {
        BeforeAll {
            # configure logingracetime to 10 seconds and presrerve the original config
            $sshdconfig = Join-Path $Global:OpenSSHTestInfo["ServiceConfigDir"] sshd_config
            $sshdconfig_temp = Join-Path $Global:OpenSSHTestInfo["ServiceConfigDir"] sshd_config_temp
            if (Test-Path $sshdconfig_temp) {
                Remove-Item $sshdconfig_temp -Force
            }
            Copy-Item $sshdconfig $sshdconfig_temp
            $content = Get-Content -Path $sshdconfig
            $newContent = $content -replace "#LoginGraceTime 2m", "LoginGraceTime 10"
            $newContent | Set-Content -Path $sshdconfig
        }

        BeforeEach {
            Restart-Service -Name $OpenSSHTestInfo["SshdServiceName"] -Force
        }

        AfterAll {
            # restore original config
            Copy-Item $sshdconfig_temp $sshdconfig -Force
            Restart-Service -Name $OpenSSHTestInfo["SshdServiceName"] -Force
            Remove-Item $sshdconfig_temp -Force
        }

        It "sshd child process ends when LoginGraceTime is exceeded" {
            # Get a count of any sshd processes before a connection in case there's another service running on the system
            # should be at least 1 sshd process for the test service
            $sshdPidCountBefore = (Get-Process -Name sshd* | Select-Object -ExpandProperty Id).Count
            # Start ssh process (do not authenticate)
            $sshProc = Start-Process -FilePath ssh -ArgumentList "-l $user test_target" -PassThru
            Start-Sleep -Seconds 2
            $sshdPidsCountWithConn = (Get-Process -Name sshd* | Select-Object -ExpandProperty Id).Count
            # Wait for LoginGraceTime to expire
            Start-Sleep -Seconds 10
            $sshdPidsCountAfter = (Get-Process -Name sshd* | Select-Object -ExpandProperty Id).Count

            if ($sshProc -and !$sshProc.HasExited) {
                $sshProc | Stop-Process -Force
            }

            # with a connection, there should be two additional session processes
            $sshdPidsCountWithConn | Should Be (2 + $sshdPidCountBefore)
            # after LoginGraceTime expires, one of the session processes should exit
            $sshdPidsCountAfter | Should Be (1 + $sshdPidCountBefore)
        }

        It "sshd pre-auth process is spawned under runtime generated virtual account" {
            $sshProc = Start-Process -FilePath ssh -ArgumentList "-l $user test_target" -PassThru
            Start-Sleep -Seconds 2
            $sshdProcessUsers = Get-Process -Name sshd* -IncludeUsername | Select-Object -ExpandProperty UserName
            $foundVirtualAccount = $false
            foreach ($username in $sshdProcessUsers) {
                if ($username -match '^VIRTUAL USERS\\sshd_\d+$') {
                    $foundVirtualAccount = $true
                    break
                }
            }

            if ($sshProc -and !$sshProc.HasExited) {
                $sshProc | Stop-Process -Force
            }

            $foundVirtualAccount | Should Be $true
        }
    }
}
