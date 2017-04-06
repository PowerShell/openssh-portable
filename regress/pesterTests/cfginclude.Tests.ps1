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
              
        $fileName = "test.txt"
        $filePath = Join-Path "$($OpenSSHTestInfo["TestDataPath"])\cfginclude" $fileName
        $logName = "log.txt"
        $logPath = Join-Path "$($OpenSSHTestInfo["TestDataPath"])\cfginclude" $logName

        $server = $OpenSSHTestInfo["Target"]
        $port = $OpenSSHTestInfo["Port"]
        $ssouser = $OpenSSHTestInfo["SSOUser"]

        Remove-Item -Path $filePath -Force -ErrorAction ignore
    }

    AfterAll {
        Remove-Item -Path $filePath -Force -ErrorAction ignore
    }

    AfterEach {
        Remove-Item -Path $filePath -Force -ErrorAction ignore
        Remove-Item -Path $logPath -Force -ErrorAction ignore
    }

    Context "User SSHConfig -- ReadConfig (positive)" {
        BeforeAll {
            $userConfigFile = "$($Global:OpenSSHTestInfo["SSOUserProfilePath"])\config"
            Copy-item "$PSScriptRoot\sshconfig\ssh_config" "$($Global:OpenSSHTestInfo["SSOUserProfilePath"])\config" -force
            $oldACL = Get-ACL $userConfigFile
        }
        AfterEach {
            Set-Acl -Path $userConfigFile -AclObject $oldACL
        }

        It 'User SSHConfig -- ReadConfig (positive)' {
            $myACL = Get-ACL $userConfigFile
            $owner = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            $myACL.SetOwner($owner)
            $accessRules = $myACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            $accessRules | % 
                {
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
           
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str
            $LASTEXITCODE | Should Be 0

            #validate file content.
            Get-Content $filePath | Should be $server.MachineName  
            
            #clean up
            Set-Acl -Path $userConfigFile -AclObject $oldACL
        }
        It 'User SSHConfig -- ReadConfig (wrong owner)' {
            $myACL = Get-ACL $userConfigFile
            $owner = New-Object System.Security.Principal.NTAccount("BUILTIN", "Administrators")
            $myACL.SetOwner($owner)
            $accessRules = $myACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            $accessRules | % 
                {
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
           
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str
            $LASTEXITCODE | Should Not Be 0        
        }

        It 'User SSHConfig -- ReadConfig (wrong permission)' {
            $myACL = Get-ACL $userConfigFile
            $owner = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            $myACL.SetOwner($owner)
            $accessRules = $myACL.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
            $accessRules | % 
                {
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

            $objUser = New-Object System.Security.Principal.NTAccount("$($server)\$($ssouser)") 

            $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($objUser, "Read, Write", "None", "None", "Allow") 

            $myACL.AddAccessRule($objACE)

            Set-Acl -Path $userConfigFile -AclObject $myACL
           
            $str = "ssh -p $($port) -E $logPath $($Options) $($ssouser)@$($server) hostname > $filePath"
            cmd /c $str
            $LASTEXITCODE | Should Not Be 0        
        }
    }
}
