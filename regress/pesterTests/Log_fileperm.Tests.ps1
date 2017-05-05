Describe "Tests for log file permission" -Tags "CI" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }
        
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\log_fileperm"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $port = 47003
        $fileName = "test.txt"
        $filePath = Join-Path $testDir $fileName

        #only validate owner and ACE of the file
        function ValiLogFilePerm {
            param($Path)

            $currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
            $myACL = Get-ACL $Path
            $myACL.Owner.Equals($currentUser.Value) | Should Be $true
            $myACL.Access | Should Not Be $null
            $myACL.Access.Count | Should Be 1
            
            $myACL.Access[0].IdentityReference.Equals($currentUser) | Should Be $true
            $myACL.Access[0].AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
            $myACL.Access[0].FileSystemRights | Should Be ([System.Security.AccessControl.FileSystemRights]::FullControl)
            $myACL.Access[0].IsInherited | Should Be $false
            $myACL.Access[0].InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
            $myACL.Access[0].PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)            
        }
    }

    Context "SSHD -E Log file permission" {
        BeforeAll {
            Remove-Item $filePath -Force -ErrorAction Ignore
            Get-Process -Name sshd | Where-Object {$_.SI -ne 0} | Stop-process
        }

        AfterEach {
            Remove-Item -Path $filePath -Force -ErrorAction ignore            
        }

        It 'SSHD -E Log file permission' {
            #Run
            Start-Process -FilePath sshd.exe -WorkingDirectory $($OpenSSHTestInfo['OpenSSHBinPath']) -ArgumentList @("-d", "-p $port", "-E $filePath") -NoNewWindow
            Start-sleep 1; 
            ValiLogFilePerm -Path $filePath
            Get-Process -Name sshd | % { if($_.SI -ne 0) { Stop-Process $_; Start-sleep 1 } }
        }
    }
}
