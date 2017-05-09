$tC = 1
$tI = 0

Describe "Tests for ssh-keygen" -Tags "CI" {
    BeforeAll {    
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Setup-OpenSSHTestEnvironment to setup test environment."
        }
        
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\keyutils"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }
        $pwd = "testpassword"
        $keytypes = @("rsa","dsa","ecdsa","ed25519")     
        #only validate owner and ACE of the file
        function ValidKeyFile {
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

    BeforeEach {
        $tI++;
    }     

    Context "$tC - ssh-keygen all key types" {

        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - Keygen -A" {
            $cd = (pwd).Path
            cd $testDir
            remove-item ssh_host_*_key* -ErrorAction SilentlyContinue
            ssh-keygen -A
            
            Get-ChildItem ssh_host_*_key | % {
                ValidKeyFile -Path $_.FullName
            }

            Get-ChildItem ssh_host_*_key.pub | % {
                ValidKeyFile -Path $_.FullName
            }
            cd $cd
        }

        It "$tC.$tI - Keygen -t -f" {
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                remove-item $keyPath -ErrorAction SilentlyContinue             
                ssh-keygen -t $type -P $pwd -f $keyPath
                ValidKeyFile -Path $keyPath
                ValidKeyFile -Path "$keyPath.pub"
            }
        }
    }

    # This uses keys generated in above context
    Context "$tC - ssh-add test cases" {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        # Executing ssh-agent will start agent service
        # This is to support typical Unix scenarios where 
        # running ssh-agent will setup the agent for current session
        It "$tC.$tI - ssh-agent starts agent service" {
            if ((Get-Service ssh-agent).Status -eq "Running") {
                Stop-Service ssh-agent
            }

            (Get-Service ssh-agent).Status | Should Be "Stopped"

            ssh-agent

            (Get-Service ssh-agent).Status | Should Be "Running"
        }

        It "$tC.$tI - ssh-add - add all key types" {
            
        }
        
    }
}
