Describe "Tests for host keys" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }

        if(-not (Test-Path $OpenSSHTestInfo["TestDataPath"]))
        {
            $null = New-Item $OpenSSHTestInfo["TestDataPath"] -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\cert-hostkey"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        
        $fileName = "test.txt"
        $filePath = Join-Path $testDir $fileName
        $logName = "log.txt"
        $logPath = Join-Path $testDir $logName        
        $ssouser = $OpenSSHTestInfo["SSOUser"]
        $script:logNum = 0

        # for the first time, delete the existing log files.
        if ($OpenSSHTestInfo['DebugMode'])
        {         
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore            
        }        

        Remove-Item -Path $filePath -Force -ErrorAction ignore

        function Set-SecureFileACL 
        {            
            param(
                [string]$FilePath,
                [System.Security.Principal.NTAccount]$Owner = $null
                )

            $myACL = Get-ACL -Path $FilePath
            $myACL.SetAccessRuleProtection($True, $True)
            Set-Acl -Path $FilePath -AclObject $myACL

            $myACL = Get-ACL $FilePath
            $actualOwner = $null
            if($owner -eq $null)
            {
                $actualOwner = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            }
            else
            {
                $actualOwner = $Owner
            }
            
            $myACL.SetOwner($actualOwner)
    
            if($myACL.Access) 
            {        
                $myACL.Access | % {                    
                    if(-not ($myACL.RemoveAccessRule($_)))
                    {
                        throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
                    }                    
                }
            }

            $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($actualOwner, "FullControl", "None", "None", "Allow")
            $myACL.AddAccessRule($objACE)

            Set-Acl -Path $FilePath -AclObject $myACL
        }
        
        function Add-PermissionToFileACL 
        {
            [CmdletBinding()]
            param(
                [string]$FilePath,
                [System.Security.Principal.NTAccount] $User,
                [System.Security.AccessControl.FileSystemRights]$Perm
            )    

            $myACL = Get-ACL $filePath
        
            $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($User, $perm, "None", "None", "Allow") 
            $myACL.AddAccessRule($objACE)    

            Set-Acl -Path $filePath -AclObject $myACL
        }

        function attempt_connect
        {
            param(
                [string]$keyname,
                [Boolean]$ExpectedSuccess = $false                
                )
        }
    }    

    AfterEach {        
        if( $OpenSSHTestInfo["DebugMode"])
        {
            Copy-Item "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\failedagent$script:logNum.log" -Force -ErrorAction ignore            
            Copy-Item $logPath "$($script:logNum)$($logPath)" -Force -ErrorAction ignore
            Clear-Content $logPath -Force -ErrorAction ignore                    
            $script:logNum++
                    
            # clear the ssh-agent so that next testcase will get fresh logs.
            Clear-Content "$($OpenSSHTestInfo['OpenSSHBinPath'])\logs\ssh-agent.log" -Force -ErrorAction ignore            
        }
        Remove-Item -Path $filePath -Force -ErrorAction ignore
    }

    Context "Host key files permission" {
        BeforeAll {
            $hostKeyFilePath = "$($OpenSSHTestInfo['OpenSSHBinPath'])\ssh_host_ed25519_key"
            #TODO: generate the key after issue 684 got fixed.
            #ssh-keygen.exe -t ed25519 -P """" -f $hostKeyFilePath

            Remove-Item $filePath -Force -ErrorAction Ignore
            Get-Process -Name sshd | % {if($_.SI -ne 0) { Stop-process $_ } }
        }

        AfterEach {
            Remove-Item -Path $filePath -Force -ErrorAction ignore
        }

        It 'Host keys -- positive (Secured private key and sshd can access to public key file)' {
            #setup to have current user as owner and grant it full control        
            Set-SecureFileACL -filepath $hostKeyFilePath
            #grant sshd Read permission to public key
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User "NT Service\sshd" -Perm "Read"            

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p 47003", "-h $hostKeyFilePath", "-E $filePath") -NoNewWindow                      
            Get-Process -Name sshd | % {if($_.SI -ne 0) { $_ } } | % { Start-Sleep 2 ; Stop-process $_; Start-Sleep 2 }
            

            #validate file content does not contain unprotected.
            $matches = Get-Content $filePath | Select-String -pattern "UNPROTECTED PRIVATE KEY FILE!"
            $matches.Count | Should Be 0
        }

        It 'Host keys -- negative (other account can access private key file)' {
            #setup to have current user as owner and grant it full control        
            Set-SecureFileACL -filepath $hostKeyFilePath
            #add ssouser to access the private key
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Add-PermissionToFileACL -FilePath $hostKeyFilePath -User $objUser -Perm "Read"
            
            #grant sshd Read permission to the public key
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User "NT Service\sshd" -Perm "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p 47003", "-h $hostKeyFilePath", "-E $filePath") -NoNewWindow
            Get-Process -Name sshd | % {if($_.SI -ne 0) { $_ } } | % { Start-Sleep 2 ; Stop-process $_; Start-Sleep 2 }

            #validate file content does not contain unprotected.
            $matches = Get-Content $filePath | Select-String -pattern "key_load_private: bad permissions"
            $matches.Count | Should Be 1
        }

        It 'Host keys -- negative (the private has wrong owner)' {
            #setup to have ssouser as owner and grant it full control
            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Set-SecureFileACL -filepath $hostKeyFilePath -owner $objUser
            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath" -User $currentUser -Perm "FullControl"
            
            #grant sshd Read permission to the public key
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User "NT Service\sshd" -Perm "Read"

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p 47003", "-h $hostKeyFilePath", "-E $filePath") -NoNewWindow
            Get-Process -Name sshd | % {if($_.SI -ne 0) { $_ } } | % { Start-Sleep 2 ; Stop-process $_; Start-Sleep 2 }

            #validate file content does not contain unprotected.
            $matches = Get-Content $filePath | Select-String -pattern "key_load_private: bad permissions"
            $matches.Count | Should Be 1
        }
        It 'Host keys -- negative (the running process does not have read access to pub key)' {
            #setup to have ssouser as owner and grant it full control
            Set-SecureFileACL -filepath $hostKeyFilePath

            $objUser = New-Object System.Security.Principal.NTAccount($ssouser)
            Set-SecureFileACL -filepath "$hostKeyFilePath.pub" -owner $objUser

            #grant current user Read permission to public key
            Add-PermissionToFileACL -FilePath "$hostKeyFilePath.pub" -User $objUser -Perm "Read" 

            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p 47003", "-h $hostKeyFilePath", "-E $filePath") -NoNewWindow
            Get-Process -Name sshd | % {if($_.SI -ne 0) { $_ } } | % { Start-Sleep 2 ; Stop-process $_; Start-Sleep 2 }

            #validate file content does not contain unprotected.
            $matches = Get-Content $filePath | Select-String -pattern "key_load_public: Permission denied"
            $matches.Count | Should Be 1
        }
    }
}
