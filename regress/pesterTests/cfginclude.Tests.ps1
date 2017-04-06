Describe "Tests for ssh config" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }

        if(-not (Test-Path $OpenSSHTestInfo["TestDataPath"]))
        {
            $null = New-Item $OpenSSHTestInfo["TestDataPath"] -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\cfginclude"
        $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        $fileName = "test.txt"
        $filePath = Join-Path $testDir $fileName
        $logName = "log.txt"
        $logPath = Join-Path $testDir $logName

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $script:logNum = 0

        # for the first time, delete the existing log files.
        if ($OpenSSHTestInfo['DebugMode'])
        {         
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" -Force -ErrorAction ignore         
        }
        Remove-Item -Path $filePath -Force -ErrorAction ignore
    }

    AfterAll {
        Remove-Item -Path $filePath -Force -ErrorAction ignore
    }

    AfterEach {        
        if( $OpenSSHTestInfo["DebugMode"])
        {
            Copy-Item "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\failedagent$script:logNum.log" -Force -ErrorAction ignore
            Copy-Item "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\failedsshd$script:logNum.log" -Force -ErrorAction ignore
            Copy-Item $logPath "$($script:logNum)$($logPath)" -Force -ErrorAction ignore
            Clear-Content $logPath -Force -ErrorAction ignore                    
            $script:logNum++
                    
            # clear the ssh-agent, sshd logs so that next testcase will get fresh logs.
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\sshd.log" -Force -ErrorAction ignore
        }
        Remove-Item -Path $filePath -Force -ErrorAction ignore        
    }

    Context "User SSHConfig -- ReadConfig" {
        BeforeAll {
            $userConfigFile = Join-Path $home ".ssh\config"
            Copy-item "$PSScriptRoot\sshconfig\ssh_config" $userConfigFile -force
            $oldACL = Get-ACL $userConfigFile
        }
        AfterEach {
            Set-Acl -Path $userConfigFile -AclObject $oldACL
        }

        AfterAll {        
            Remove-Item -Path $userConfigFile -Force -ErrorAction ignore
        }

        It 'User SSHConfig -- ReadConfig (positive)' {
            #setup
            $myACL = Get-ACL $userConfigFile
            $owner = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            $myACL.SetOwner($owner)
            $accessRules = $myACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            $accessRules | % {
                if (($_.IdentityReference.Value -ine "BUILTIN\Administrators") -and 
                ($_.IdentityReference.Value -ine "NT AUTHORITY\SYSTEM") -and 
                ($_.IdentityReference.Value -ine "$(whoami)"))
                {
                    f(-not $a.RemoveAccessRule($_))
                    {
                        throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
                    }
                }
            }
            Set-Acl -Path $userConfigFile -AclObject $myACL

            #Run
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str
            $LASTEXITCODE | Should Be 0

            #validate file content.
            Get-Content $filePath | Should be $env:COMPUTERNAME 
            
            #clean up
            Set-Acl -Path $userConfigFile -AclObject $oldACL
        }
        It 'User SSHConfig -- ReadConfig (wrong owner)' {
            #setup
            $myACL = Get-ACL $userConfigFile
            $owner = New-Object System.Security.Principal.NTAccount("BUILTIN", "Administrators")
            $myACL.SetOwner($owner)
            $accessRules = $myACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            $accessRules | % {
                if (($_.IdentityReference.Value -ine "BUILTIN\Administrators") -and 
                ($_.IdentityReference.Value -ine "NT AUTHORITY\SYSTEM") -and 
                ($_.IdentityReference.Value -ine "$(whoami)"))
                {
                    f(-not $a.RemoveAccessRule($_))
                    {
                        throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
                    }
                }
            }

            Set-Acl -Path $userConfigFile -AclObject $myACL

            #Run
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str

            #clean up
            $LASTEXITCODE | Should Not Be 0        
        }#>

        It 'User SSHConfig -- ReadConfig (wrong permission)' {
            #setup
            $myACL = Get-ACL $userConfigFile
            $owner = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            $myACL.SetOwner($owner)
            $accessRules = $myACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            $accessRules | % {
                if (($_.IdentityReference.Value -ine "BUILTIN\Administrators") -and 
                ($_.IdentityReference.Value -ine "NT AUTHORITY\SYSTEM") -and 
                ($_.IdentityReference.Value -ine "$(whoami)"))
                {
                    f(-not $a.RemoveAccessRule($_))
                    {
                        throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
                    }
                }
            }

            $objUser = New-Object System.Security.Principal.NTAccount($ssouser) 

            $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($objUser, "Read, Write", "None", "None", "Allow") 

            $myACL.AddAccessRule($objACE)

            Set-Acl -Path $userConfigFile -AclObject $myACL

            #Run
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str

            #clean up
            $LASTEXITCODE | Should Not Be 0        
        }
    }
}
