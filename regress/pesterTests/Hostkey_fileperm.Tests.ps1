﻿If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tC = 1
$tI = 0
$suite = "hostkey_fileperm"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Import-Module "$Script:SSHBinaryPath\OpenSSHUtils" -force
Describe "Tests for host keys file permission" -Tags "CI" {
    BeforeAll {        
        $logName = "sshdlog.txt"
        $port = 47002
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"

        $script:logNum = 0
        Remove-Item -Path (Join-Path $testDir "*$logName") -Force -ErrorAction SilentlyContinue
        $skip = ([Environment]::OSVersion.Version.Major -le 6) -and ([Environment]::OSVersion.Version.Minor -lt 2)

        function Set-FilePermission
        {    
            param(
                [parameter(Mandatory=$true)]
                [string]$FilePath,
                [parameter(Mandatory=$true)]
                [System.Security.Principal.SecurityIdentifier] $UserSid,
                [System.Security.AccessControl.FileSystemRights[]]$Perms,
                [System.Security.AccessControl.AccessControlType] $AccessType = "Allow",
                [ValidateSet("Add", "Delete")]
                [string]$Action = "Add"
            )    

            $myACL = Get-ACL $FilePath
            $account = Get-UserAccount -UserSid $UserSid
            if($Action -ieq "Delete")
            {
                $myACL.SetAccessRuleProtection($True, $True)
                Enable-Privilege SeRestorePrivilege | out-null
                Set-Acl -Path $FilePath -AclObject $myACL
                $myACL = Get-ACL $FilePath
        
                if($myACL.Access) 
                {        
                    $myACL.Access | % {
                        if($_.IdentityReference.Equals($account))
                        {
                            if($_.IsInherited)
                            {
                                $myACL.SetAccessRuleProtection($True, $True)
                                Enable-Privilege SeRestorePrivilege | out-null
                                Set-Acl -Path $FilePath -AclObject $myACL
                                $myACL = Get-ACL $FilePath
                            }
                    
                            if(-not ($myACL.RemoveAccessRule($_)))
                            {
                                throw "failed to remove access of $($_.IdentityReference) rule in setup "
                            }
                        }
                    }
                } 
            }
            elseif($Perms)
            {
                $Perms | % { 
                    $userACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                        ($UserSid, $_, "None", "None", $AccessType)
                    $myACL.AddAccessRule($userACE)
                }
            }
            Enable-Privilege SeRestorePrivilege | out-null
            Set-Acl -Path $FilePath -AclObject $myACL -confirm:$false
        }
    }

    AfterEach { $tI++ }

    Context "$tC - Host key files permission" {
        BeforeAll {
            $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
            $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
            $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
            $everyoneSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::WorldSid)

            $hostKeyFilePath = join-path $testDir hostkeyFilePermTest_ed25519_key
            if(Test-path $hostKeyFilePath -PathType Leaf) {	
                Repair-SshdHostKeyPermission -filepath $hostKeyFilePath -confirm:$false
            }	
            Remove-Item -path "$hostKeyFilePath*" -Force -ErrorAction SilentlyContinue
            ssh-keygen.exe -t ed25519 -f $hostKeyFilePath -P `"`"
            
            $tI=1
            
            function WaitForValidation
            {
                param([string]$logPath, [int]$length)
                $num = 0
                while((-not (Test-Path $logPath -PathType leaf)) -or ((Get-item $logPath).Length -lt $length) -and ($num++ -lt 10))
                {
                    Start-Sleep -Milliseconds 1000
                }
                Stop-SSHDDaemon
                $num = 0
                do
                {
                    Start-Sleep -Milliseconds 1000
                    #wait for the log file be able to access
                    Get-Content $logPath -ErrorVariable a
                } while ($a -and ($num++ -lt 10))
            }
        }

        BeforeEach {
            $logPath = Join-Path $testDir "$tC.$tI.$logName"
        }

        AfterEach {
            if(Test-path $hostKeyFilePath -PathType Leaf) {
                Repair-SshdHostKeyPermission -filepath $hostKeyFilePath -confirm:$false
            }
        }
        AfterAll { $tC++ }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by admin groups)" {
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            Start-SSHDDaemon -port $port -ExtraArglist "-d" -host_key_files $hostKeyFilePath -SSHD_Log_File $logPath
            WaitForValidation -LogPath $logPath -Length 600

            #validate file content does not contain unprotected info.
            $logPath | Should -Not -FileContentMatch "UNPROTECTED PRIVATE KEY FILE!"
            
        }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by admin groups and pwd user has explicit ACE)" {
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -ReadAccessNeeded $currentUserSid -confirm:$false
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -ReadAccessNeeded $everyOneSid -confirm:$false

            #Run
            Start-SSHDDaemon -port $port -ExtraArglist "-d" -host_key_files $hostKeyFilePath -SSHD_Log_File $logPath
            WaitForValidation -LogPath $logPath -Length 600

            #validate file content does not contain unprotected info.
            $logPath | Should -Not -FileContentMatch "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-Host keys-positive (both public and private keys are owned by system and running process can access to public key file)" -skip:$skip {
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $systemSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $currentUserSid -confirm:$false
            Set-FilePermission -Filepath $hostKeyFilePath -UserSid $adminsSid -Action Delete
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $systemSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $currentUserSid -confirm:$false
            Set-FilePermission -Filepath "$hostKeyFilePath.pub" -UserSid $adminsSid -Action Delete
            
            #Run
            Start-SSHDDaemon -port $port -ExtraArglist "-d" -host_key_files $hostKeyFilePath -SSHD_Log_File $logPath
            WaitForValidation -LogPath $logPath -Length 600

            #validate file content does not contain unprotected info.
            $logPath | Should -Not -FileContentMatch "UNPROTECTED PRIVATE KEY FILE!"
        }

        <#It "$tC.$tI-Host keys-negative (other account can access private key file)" {
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $adminsSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $objUserSid -confirm:$false
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $adminsSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $everyOneSid -confirm:$false
            
            #Run
            Start-SSHDDaemon -port $port -ExtraArglist "-d" -host_key_files $hostKeyFilePath -SSHD_Log_File $logPath
            WaitForValidation -LogPath $logPath -Length 1100

            #validate file content contains unprotected info.
            $logPath | Should -FileContentMatch "bad permissions"
        }

        It "$tC.$tI-Host keys-negative (the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Repair-FilePermission -Filepath $hostKeyFilePath -Owners $objUserSid -FullAccessNeeded $systemSid,$adminsSid,$objUserSid -confirm:$false
            Repair-FilePermission -Filepath "$hostKeyFilePath.pub" -Owners $adminsSid -FullAccessNeeded $systemSid,$adminsSid -ReadAccessNeeded $everyOneSid -confirm:$false

            #Run
            Start-SSHDDaemon -port $port -ExtraArglist "-d" -host_key_files $hostKeyFilePath -SSHD_Log_File $logPath
            WaitForValidation -LogPath $logPath -Length 1100

            #validate file content contains unprotected info.
            $logPath | Should -FileContentMatch "bad permissions"
        }#>
    }
}
