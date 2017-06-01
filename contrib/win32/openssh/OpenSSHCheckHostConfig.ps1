$systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
$adminsAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")            
$currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
$everyone =  New-Object System.Security.Principal.NTAccount("EveryOne")
$sshdAccount = New-Object System.Security.Principal.NTAccount("NT SERVICE","sshd")

<#
    .Synopsis
    Check-FileSecureInternal
    Only validate owner and ACEs of the file
#>

function Check-FileSecure
{
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.NTAccount[]] $Owners = $currentUser,
        [System.Security.Principal.NTAccount[]] $AnyAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessNeeded
    )
    
    Write-host "----------Validating $FilePath----------"
    $return = Check-FileSecureInternal @PSBoundParameters

    if($return -contains $true) 
    {
        #Write-host "Re-check the health of file $FilePath"
        Check-FileSecureInternal @PSBoundParameters
    }
}

<#
    .Synopsis
    Check-FileSecureInternal
#>
function Check-FileSecureInternal {
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.NTAccount[]] $Owners = $currentUser,
        [System.Security.Principal.NTAccount[]] $AnyAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessNeeded
    )

    $acl = Get-Acl $FilePath
    $needChange = $false
    $health = $true
    
    if([System.Security.Principal.NTAccount]$($acl.Owner) -notin $Owners)
    {
        #todo: unrestrict mode
        $warning = "Current owner: '$($acl.Owner)'. '$($Owners[0])' should own $FilePath."
        Do {
            Write-Warning $warning
            $input = Read-Host -Prompt "Shall I set the file owner? [Yes] Y; [No] N (default is `"Y`")"
            if([string]::IsNullOrEmpty($input))
            {
                $input = 'Y'
            }        
        } until ($input -match "^(y(es)?|N(o)?)$")        
        

        if($Matches[0].ToLower().Startswith('y'))
        {
            $needChange = $true
            $acl.SetOwner($Owners[0])
            Write-Host "'$($Owners[0])' now owns $FilePath. " -ForegroundColor Green
        }
        else
        {
            $health = $false
            Write-Host "The owner is still set to '$($acl.Owner)'." -ForegroundColor Yellow
        }
    }

    $ReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)
    $realAnyAccessOKList = $AnyAccessOK + @($systemAccount, $adminsAccount)
    $realReadAcessOKList = $ReadAccessOK + $ReadAccessNeeded
    $realReadAccessNeeded = $ReadAccessNeeded

    foreach($a in $acl.Access)
    {
        if(($realAnyAccessOKList -ne $null) -and $realAnyAccessOKList.Contains($a.IdentityReference))
        {
            #ingore identities
        }
        elseif($realReadAcessOKList -and (($realReadAcessOKList.Contains($everyone)) -or `
             ($realReadAcessOKList.Contains($a.IdentityReference))))
        {
            if($realReadAccessNeeded -and ($a.IdentityReference.Equals($everyone)))
            {
                $realReadAccessNeeded.Clear()
            }
            elseif($realReadAccessNeeded -and $realReadAccessNeeded.Contains($a.IdentityReference))
            {
                    $realReadAccessNeeded = $realReadAccessNeeded | ? { -not $_.Equals($a.IdentityReference) }
            }

            if (-not ($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow)) -or `
            (-not (([System.UInt32]$a.FileSystemRights.value__) -band (-bnot $ReadAccessPerm))))
            {
                continue;
            }
            $warning = "'$($a.IdentityReference)' has the following access to $($FilePath): '$($a.FileSystemRights)'."            

            Do {
                    Write-Warning $warning
                    $input = Read-Host -Prompt "Shall I make it Read only? [Yes] Y; [No] N (default is `"Y`")"
                    if([string]::IsNullOrEmpty($input))
                    {
                        $input = 'Y'
                    }
                    
                } until ($input -match "^(y(es)?|N(o)?)$")

            if($Matches[0].ToLower().Startswith('y'))
            {                
                if($a.IsInherited)
                {
                    if($needChange)    
                    {
                        Set-Acl -Path $FilePath -AclObject $acl     
                    }
                    Remove-RuleProtection -FilePath $FilePath
                    #after the inheritance is remove, you need to get acl again for correct data
                    #otherwise, the inheriance is set back to $true from $acl.
                    return $true
                }
                $needChange = $true
                $sshAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
                    ($a.IdentityReference, "Read", "None", "None", "Allow")
                $acl.SetAccessRule($sshAce)
                Write-Host "'$($a.IdentityReference)' now has Read access to $FilePath. "  -ForegroundColor Green
            }
            else
            {
                $health = $false
                Write-Host "'$($a.IdentityReference)' still has these access to $($FilePath): '$($a.FileSystemRights)'." -ForegroundColor Yellow
            }            
          }
        elseif($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow))
        {
            Do {
            #todo for unstrict mode
                Write-Warning "'$($a.IdentityReference)' cannot have access to '$FilePath'. " 
                $input = Read-Host -Prompt "Shall I remove this access? [Yes] Y; [No] N (default is `"Y`")"
                if([string]::IsNullOrEmpty($input))
                {
                    $input = 'Y'
                }        
            } until ($input -match "^(y(es)?|N(o)?)$")
        
            if($Matches[0].ToLower().Startswith('y'))
            {                
                if($a.IsInherited)
                {
                    if($needChange)    
                    {
                        Set-Acl -Path $FilePath -AclObject $acl     
                    }
                    Remove-RuleProtection -FilePath $FilePath
                    return $true
                }
                $needChange = $true
                if(-not ($acl.RemoveAccessRule($a)))
                {
                    throw "failed to remove access of $($a.IdentityReference) rule to file $FilePath"
                }
                else
                {
                    Write-Host "'$($a.IdentityReference)' has no more access to $FilePath." -ForegroundColor Green
                }
            }
            else
            {
                $health = $false
                Write-Host "'$($a.IdentityReference)' still has access to $FilePath." -ForegroundColor Yellow
            }
        }    
    }

    if($realReadAccessNeeded)
    {
        $realReadAccessNeeded | % {
            
            $warning = "'$_' needs Read access to $FilePath'."
            Do {
                Write-Warning $warning
                $input = Read-Host -Prompt "Shall I make the above change? [Yes] Y; [No] N (default is `"Y`")"
                if([string]::IsNullOrEmpty($input))
                {
                    $input = 'Y'
                }        
            } until ($input -match "^(y(es)?|N(o)?)$")
        
            if($Matches[0].ToLower().Startswith('y'))
            {
                $needChange = $true
                $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                        ($_, "Read", "None", "None", "Allow")
                $acl.AddAccessRule($ace)
                Write-Host "'$_' now has Read access to $FilePath. " -ForegroundColor Green
            }
            else
            {
                $health = $false
                Write-Host "'$_' does not have Read access to $FilePath." -ForegroundColor Yellow
            }
        }
    }

    if($needChange)    
    {
        Set-Acl -Path $FilePath -AclObject $acl     
    }
    if($health)
    {
        Write-Host "-----------$FilePath looks good!-------- "  -ForegroundColor Green
    }
    Write-host " "
}

<#
    .Synopsis
    Remove-RuleProtection
#>
function Remove-RuleProtection
{
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath
    )
    $acl = Get-ACL $FilePath
    $acl.SetAccessRuleProtection($True, $True)
    Set-Acl -Path $FilePath -AclObject $acl
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


#check sshd config file
Check-FileSecure -FilePath ( join-path $PSScriptRoot "sshd_config") -Owners $systemAccount,$adminsAccount -ReadAccessNeeded $sshdAccount
 
#check private host keys
$insecureConfig = $false
Do
{                
    $input = Read-Host -Prompt "Did you register host private keys with ssh-agent? [Yes] Y; [No] N"    
} until ($input -match "^(y(es)?|N(o)?)$")

if($Matches[0].ToLower().Startswith('n')) {
    $warning = @"
To keep the host private keys secure, it is recommended to register them with ssh-agent following
steps in link 'https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH'.
If you choose not, sshd needs read access to the private keys.
"@    
    Do {
        Write-Warning $warning
        $input = Read-Host -Prompt "Shall I continue with this insecure configuration? [Yes] Y; [No] N (default is `"Y`")"
        if([string]::IsNullOrEmpty($input))
        {
            $input = 'Y'
        }
    } until ($input -match "^(y(es)?|N(o)?)$")
        
    if($Matches[0].ToLower().Startswith('y'))
    {
        $insecureConfig = $true
        Write-Warning "User chose to continue with insecure configuration."
    }
    else
    {        
        Write-Warning "User chose not to continue with insecure configuration. Please register host keys with ssh-agent to have ssh remote work."
    }
}

Get-ChildItem $PSScriptRoot\ssh*host*key* -Exclude *pub | % {
#Get-ChildItem $PSScriptRoot\ssh_host_*_key | % {
    if($insecureConfig) {
        Check-FileSecure -FilePath $_.FullName -Owners $systemAccount,$adminsAccount -ReadAccessNeeded $sshdAccount
    }
    else {
        Check-FileSecure -FilePath $_.FullName -Owners $systemAccount,$adminsAccount -ReadAccessOK $sshdAccount
    }
}


#check public host keys
Get-ChildItem $PSScriptRoot\ssh*host*key*.pub | % {
#Get-ChildItem $PSScriptRoot\ssh_host_*_key.pub | % {
    if($insecureConfig) {
        Check-FileSecure -FilePath $_.FullName -Owners $systemAccount,$adminsAccount -ReadAccessOK $everyone -ReadAccessNeeded $sshdAccount
    }
    else {
        Check-FileSecure -FilePath $_.FullName -Owners $systemAccount,$adminsAccount -ReadAccessOK $everyone
    }
}

#check authorized_keys
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | % {
    $userProfilePath = Get-ItemPropertyValue $_.pspath -Name ProfileImagePath -ErrorAction Ignore    
    $userSid = $_.PSChildName
    $account = Get-UserSID -UserSid $userSid
    $filePath = Join-Path $userProfilePath .ssh\authorized_keys
    if($account -and (Test-Path $filePath))
    {
        Check-FileSecure -FilePath $filePath -Owners $account,$adminsAccount,$systemAccount -AnyAccessOK $account -ReadAccessNeeded $sshdAccount
    }
}

Write-Host "--------------------------Done-------------------------------"
