#only validate owner and ACEs of the file
function Check-FileSecure
{
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.NTAccount[]] $Owners = $currentUser,
        [System.Security.Principal.NTAccount[]] $Identities,
        [System.Security.Principal.NTAccount[]] $ReadOnlyPermIdentities
    )

    Write-host "-----Start validating the health of file $FilePath-----"
    $return = Check-FileSecureHelp @PSBoundParameters

    if($return -contains $true) 
    {
        Write-host "Re-check the health of file $FilePath"
        Check-FileSecureHelp @PSBoundParameters
    }
}

function Check-FileSecureHelp {
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.NTAccount[]] $Owners = $currentUser,
        [System.Security.Principal.NTAccount[]] $Identities,
        [System.Security.Principal.NTAccount[]] $ReadOnlyPermIdentities
    )

    $acl = Get-Acl $FilePath
    $needChange = $false
    $hasSSHD = $false
    $health = $true
    
    if([System.Security.Principal.NTAccount]$($acl.Owner) -notin $Owners)
    {
        $warning = "It is recommendated to have '$($Owners[0].Value)' as file owner of $FilePath."        
        Do {
            Write-Warning $warning
            $input = Read-Host -Prompt "Do you want to set the file owner? [Yes] Y; [No] N (default is `"Y`")"
            if([string]::IsNullOrEmpty($input))
            {
                $input = 'Y'
            }        
        } until ($input -match "^(y(es)?|N(o)?)$")        
        

        if($Matches[0].ToLower().Startswith('y'))
        {            
            $acl.SetOwner($Owners[0])
            Write-Host "Set owner of file $FilePath to '$($Owners[0].Value)'. "  -ForegroundColor Green
            Set-Acl -Path $FilePath -AclObject $acl
        }
        else
        {
            $health = $false
            Write-Host "User decided not to make the changes."
        }
    }

    $ReadAccess = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

    foreach($a in $acl.Access)
    {
        if($a.IdentityReference.Value -in ($Identities | % { $_.Value } ))
        {
            #ingore identities
        }
        elseif(($ReadOnlyPermIdentities -and ($ReadOnlyPermIdentities.Contains($everyone))) -or `
             ($a.IdentityReference.Value -in $ReadOnlyPermIdentities))
        {
            if($a.IdentityReference.Value -eq $sshdAccount.Value)
            {
                    $hasSSHD = $true;
            }
            if (-not ($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow)) -or `
            (-not (([System.UInt32]$a.FileSystemRights.value__) -band (-bnot $ReadAccess))))
            {
                continue;
            }
            $warning = @"
It is required that '$($a.IdentityReference.Value)' has Read only access on file $FilePath.
but '$($a.IdentityReference.Value)' is granted '$($a.FileSystemRights)'.
"@            

            Do {
                    Write-Warning $warning
                    $input = Read-Host -Prompt "Do you want to update the file permission? [Yes] Y; [No] N (default is `"Y`")"
                    if([string]::IsNullOrEmpty($input))
                    {
                        $input = 'Y'
                    }
                    
                } until ($input -match "^(y(es)?|N(o)?)$")

            if($Matches[0].ToLower().Startswith('y'))
            {
                $needChange = $true
                if($a.IsInherited)
                {
                    Remove-RuleProtection -FilePath $FilePath
                    #after the inheritance is remove, you need to get acl again for correct data
                    #otherwise, the inheriance is set back to $true from $acl.
                    return $true
                }
                $sshAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
                    ($($a.IdentityReference.Value), "Read", "None", "None", "Allow")
                $acl.SetAccessRule($sshAce)
                Write-Host "Updated $($a.IdentityReference.Value) with Read access on file $FilePath. "  -ForegroundColor Green
            }
            else
            {
                $health = $false
                Write-Host "User decided not to make this changes." -ForegroundColor DarkYellow
            }            
          }
        elseif($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow))
        {
            Do {
                Write-Warning "Any access of $($a.IdentityReference.Value) on '$FilePath' is not allowed. " 
                $input = Read-Host -Prompt "Do you want to remove this access? [Yes] Y; [No] N (default is `"Y`")"
                if([string]::IsNullOrEmpty($input))
                {
                    $input = 'Y'
                }        
            } until ($input -match "^(y(es)?|N(o)?)$")
        
            if($Matches[0].ToLower().Startswith('y'))
            {
                $needChange = $true
                if($a.IsInherited)
                {
                    Remove-RuleProtection -FilePath $FilePath
                    return $true
                }
                if(-not ($acl.RemoveAccessRule($a)))
                {
                    throw "failed to remove access of $($a.IdentityReference.Value) rule to file $FilePath"
                }
                else
                {
                    Write-host "The access of $($a.IdentityReference.Value) is removed from file $FilePath." -ForegroundColor Green
                }
            }
            else
            {
                $health = $false
                Write-Host "User decided not to make the changes."  -ForegroundColor DarkYellow
            }
        }    
    }

    if($ReadOnlyPermIdentities -and (-not $hasSSHD) -and ($ReadOnlyPermIdentities.Contains($sshdAccount)))
    {
        $warning = "It is recommendated to grant '$sshdAccount' Read access on $FilePath'."
        Do {
            Write-Warning $warning
            $input = Read-Host -Prompt "Do you want to continue with the above changes? [Yes] Y; [No] N (default is `"Y`")"
            if([string]::IsNullOrEmpty($input))
            {
                $input = 'Y'
            }        
        } until ($input -match "^(y(es)?|N(o)?)$")
        
        if($Matches[0].ToLower().Startswith('y'))
        {
            $needChange = $true
            $sshdAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
                    ($sshdAccount, "Read", "None", "None", "Allow")
            $acl.AddAccessRule($sshdAce)
            Write-Host "Added $sshdAccount with Read access on file $FilePath. "  -ForegroundColor Green
        }
        else
        {
            $health = $false
            Write-Host "User decided not to make the changes."  -ForegroundColor DarkYellow
        }
    }

    if($needChange)    
    {
        Set-Acl -Path $FilePath -AclObject $acl     
    }
    if($health)
    {
        Write-Host "-------------File $FilePath is healthy!!!--------------" -ForegroundColor Green
    }
    else
    {
        Write-Host "------------File $FilePath is unhealthy!!!-------------" -ForegroundColor Red
    }
}

function Remove-RuleProtection
{
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath
    )
    $acl = Get-ACL $FilePath
    $acl.SetAccessRuleProtection($True, $True)
    Set-Acl -Path $FilePath -AclObject $acl
    Write-Host "The inheritance on file $FilePath is removed."
}
<#
    .Synopsis
    Get-UserAccount
#>
function Get-UserSID
{
    param
        (   [parameter(Mandatory=$true)]      
            [string]$UserSid
        )
    try
    {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserSid) 
        $objUser = $objSID.Translate( [System.Security.Principal.NTAccount]) 
        $objUser
    }
    catch {
    }
}


$systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
$adminsAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")            
$currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
$everyone =  New-Object System.Security.Principal.NTAccount("EveryOne")
$sshdAccount = New-Object System.Security.Principal.NTAccount("NT SERVICE","sshd")

#check sshd config file
Check-FileSecure -FilePath ( join-path $PSScriptRoot "sshd_config") -Owners $systemAccount -Identities $adminsAccount,$systemAccount, $currentUser -ReadOnlyPermIdentities $sshdAccount

#check private host keys    
Get-ChildItem $PSScriptRoot\ssh*host*key* -Exclude *.pub | % {
    Check-FileSecure -FilePath $_.FullName -Owners $systemAccount -Identities $adminsAccount,$systemAccount
}

#check public host keys
Get-ChildItem $PSScriptRoot\ssh*host*key*.pub | % {
    Check-FileSecure -FilePath $_.FullName -Owners $systemAccount -Identities $adminsAccount,$systemAccount -ReadOnlyPermIdentities $everyone
}

#check authorized_keys
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | % {
    $userProfilePath = Get-ItemPropertyValue $_.pspath -Name ProfileImagePath -ErrorAction Ignore
    if($userProfilePath.ToLower().Startswith("$($env:SystemDrive)\users".ToLower()))
    {
        $userSid = $_.PSChildName
        $account = Get-UserSID -UserSid $userSid
        $filePath = Join-Path $userProfilePath .ssh\authorized_keys
        if($account -and (Test-Path $filePath))
        {
            Check-FileSecure -FilePath $filePath -Owners $account, $adminsAccount -Identities $adminsAccount,$systemAccount,$account -ReadOnlyPermIdentities $sshdAccount
        }
    }        
}

Write-Host "--------------------Finish checking all host configs.-------------------------"  
