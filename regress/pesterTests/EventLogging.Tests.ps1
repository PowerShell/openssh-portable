If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
Import-Module OpenSSHUtils -Force
$tC = 1
$tI = 0
$suite = "EventLogging"
Describe "Tests for admin and non-admin event logs" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }

        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\$suite"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }

        $server = $OpenSSHTestInfo["Target"]
        $nonadminusername = $OpenSSHTestInfo['NonAdminUser']
        $adminusername = $OpenSSHTestInfo['AdminUser']
        $opensshbinpath = $OpenSSHTestInfo['OpenSSHBinPath']
        $password = $OpenSSHTestInfo['TestAccountPW']
        $port = 47003
        $sshdDelay = $OpenSSHTestInfo["DelayTime"]

        # Register OpenSSH events in Event Viewer
        $etwman = Join-Path $opensshbinpath "openssh-events.man"
        if (-not (Test-Path $etwman -PathType Leaf)) {
            throw "openssh events manifest is not present in OpenSSH binary path"
        }
        wevtutil im "$etwman" | Out-Null
    }

    AfterEach { $tI++ }

    AfterAll {
        # Unregister etw provider
        wevtutil um "$etwman"
    }

    Context "Tests Logs for SSH connections" {
        BeforeAll {
            Add-PasswordSetting -Pass $password
            $tI=1
        }

        BeforeEach {
            # disable the OpenSSH log channels
            wevtutil sl "OpenSSH/Debug" /e:false /q:true | Out-Null
            wevtutil sl "OpenSSH/Operational" /e:false /q:true | Out-Null
            # clear any existing logs
            wevtutil cl "OpenSSH/Debug" | Out-Null
            wevtutil cl "OpenSSH/Operational" | Out-Null
            # enable the OpenSSH log channels
            wevtutil sl "OpenSSH/Debug" /e:true /q:true | Out-Null
            wevtutil sl "OpenSSH/Operational" /e:true /q:true | Out-Null
        }

        AfterAll {
            Remove-PasswordSetting
            $tC++
        }

        It "$tC.$tI-Nonadmin SSH Connection" {
            $o = ssh -l $nonadminusername test_target echo 1234
            $o | Should Be 1234
            Start-Sleep $sshdDelay
            # query the OpenSSH log channels to make sure events were captured
            $eventLogDebug = wevtutil qe "OpenSSH/Debug" /c:5 /f:text
            $eventLogDebug | Should Not Be $null
            $eventLogOperational = wevtutil qe "OpenSSH/Operational" /c:5 /f:text
            $eventLogOperational | Should Not Be $null
        }

        It "$tC.$tI-Admin SSH Connection" {
            $o = ssh -l $adminusername test_target echo 1234
            $o | Should Be 1234
            Start-Sleep $sshdDelay
            # query the OpenSSH log channels to make sure events were captured
            $eventLogDebug = wevtutil qe "OpenSSH/Debug" /c:5 /f:text
            $eventLogDebug | Should Not Be $null
            $eventLogOperational = wevtutil qe "OpenSSH/Operational" /c:5 /f:text
            $eventLogOperational | Should Not Be $null
        }
    }

    Context "Tests Logs for SFTP connections" {

        BeforeAll {

            function Setup-KeyBasedAuth
            {
                param([string] $Username, [string] $KeyFilePath, [string] $UserProfile)

                $userSSHProfilePath = Join-Path $UserProfile .ssh

                if (-not (Test-Path $userSSHProfilePath -PathType Container)) {
                    New-Item $userSSHProfilePath -ItemType directory -Force -ErrorAction Stop | Out-Null
                }

                $authorizedkeyPath = Join-Path $userSSHProfilePath authorized_keys

                if($OpenSSHTestInfo["NoLibreSSL"])
                {
                    ssh-keygen.exe -t ed25519 -f $KeyFilePath -Z -P "" aes128-ctr
                }
                else
                {
                    ssh-keygen.exe -t ed25519 -f $KeyFilePath -P ""
                }
                Copy-Item "$KeyFilePath.pub" $authorizedkeyPath -Force -ErrorAction SilentlyContinue
                Repair-AuthorizedKeyPermission -Filepath $authorizedkeyPath -confirm:$false
            }

            $AdminUserProfile = $OpenSSHTestInfo['AdminUserProfile']
            $NonAdminUserProfile = $OpenSSHTestInfo['NonAdminUserProfile']

            $KeyFileName = $nonadminusername + "_sshtest_EventLog_ed25519"
            $NonadminKeyFilePath = Join-Path $testDir $keyFileName
            Remove-Item -path "$NonadminKeyFilePath*" -Force -ErrorAction SilentlyContinue
            Setup-KeyBasedAuth -Username $nonadminusername -KeyFilePath $NonadminKeyFilePath -UserProfile $NonAdminUserProfile

            $KeyFileName = $adminusername + "_sshtest_EventLog_ed25519"
            $AdminKeyFilePath = Join-Path $testDir $keyFileName
            Remove-Item -path "$AdminKeyFilePath*" -Force -ErrorAction SilentlyContinue
            Setup-KeyBasedAuth -Username $adminusername -KeyFilePath $AdminKeyFilePath -UserProfile $AdminUserProfile

            #create batch file
            $commands =
"ls
exit"
            $batchFilePath = Join-Path $testDir "$tC.$tI.commands.txt"
            Set-Content $batchFilePath -Encoding UTF8 -value $commands

            $tI = 1
        }

        BeforeEach {
            # disable the OpenSSH log channels
            wevtutil sl "OpenSSH/Debug" /e:false /q:true | Out-Null
            wevtutil sl "OpenSSH/Operational" /e:false /q:true | Out-Null
            # clear any existing logs
            wevtutil cl "OpenSSH/Debug" | Out-Null
            wevtutil cl "OpenSSH/Operational" | Out-Null
            # enable the OpenSSH log channels
            wevtutil sl "OpenSSH/Debug" /e:true /q:true | Out-Null
            wevtutil sl "OpenSSH/Operational" /e:true /q:true | Out-Null
        }

        AfterAll {
            Remove-Item -path "$NonadminKeyFilePath*" -Force -ErrorAction SilentlyContinue
            Remove-Item -path "$AdminKeyFilePath*" -Force -ErrorAction SilentlyContinue

            $authorized_key = Join-Path '.ssh' authorized_keys
            $AdminAuthKeysPath = Join-Path $AdminUserProfile $authorized_key
            $NonAdminAuthKeysPath = Join-Path $NonAdminUserProfile $authorized_key
            Remove-Item -path "$AdminAuthKeysPath*" -Force -ErrorAction SilentlyContinue
            Remove-Item -path "$NonAdminAuthKeysPath*" -Force -ErrorAction SilentlyContinue

            $tC++
        }

        It "$tC.$tI-Nonadmin SFTP Connection" {
            sftp -i $NonadminKeyFilePath -b $batchFilePath -o User=$nonadminusername test_target
            Start-Sleep $sshdDelay
            # query the OpenSSH log channels to make sure events were captured
            $eventLogDebug = wevtutil qe "OpenSSH/Debug" /c:5 /f:text
            $eventLogDebug | Should Not Be $null
            $eventLogOperational = wevtutil qe "OpenSSH/Operational" /c:5 /f:text
            $eventLogOperational | Should Not Be $null
        }

        It "$tC.$tI-Admin SFTP Connection" {
            sftp -i $AdminKeyFilePath -b $batchFilePath -o User=$adminusername test_target
            Start-Sleep $sshdDelay
            # query the OpenSSH log channels to make sure events were captured
            $eventLogDebug = wevtutil qe "OpenSSH/Debug" /c:5 /f:text
            $eventLogDebug | Should Not Be $null
            $eventLogOperational = wevtutil qe "OpenSSH/Operational" /c:5 /f:text
            $eventLogOperational | Should Not Be $null
        }
    }
}
