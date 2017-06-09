﻿$systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
$adminsAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")            
$currentUser = New-Object System.Security.Principal.NTAccount($($env:USERDOMAIN), $($env:USERNAME))
$everyone =  New-Object System.Security.Principal.NTAccount("EveryOne")
$sshdAccount = New-Object System.Security.Principal.NTAccount("NT SERVICE","sshd")

<#
    .Synopsis
    Repair-SshdConfigPermission
    Repair the file owner and Permission of sshd_config
#>
function Repair-SshdConfigPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath)

        Repair-FilePermission -Owners $systemAccount,$adminsAccount -ReadAccessNeeded $sshdAccount @psBoundParameters        
}

<#
    .Synopsis
    Repair-SshdHostKeyPermission
    Repair the file owner and Permission of host private and public key
    -FilePath: The path of the private host key
#>
function Repair-SshdHostKeyPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath)        
        
        if($PSBoundParameters["FilePath"].EndsWith(".pub"))
        {
            $PSBoundParameters["FilePath"] = $PSBoundParameters["FilePath"].Replace(".pub", "")
        }

        Repair-FilePermission -Owners $systemAccount,$adminsAccount -ReadAccessNeeded $sshdAccount @psBoundParameters        
        
        $PSBoundParameters["FilePath"] += ".pub"        
        Repair-FilePermission -Owners $systemAccount,$adminsAccount -ReadAccessOK $everyone -ReadAccessNeeded $sshdAccount @psBoundParameters        
}

<#
    .Synopsis
    Repair-AuthorizedKeyPermission
    Repair the file owner and Permission of authorized_keys
#>
function Repair-AuthorizedKeyPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath)        

        if(-not (Test-Path $FilePath -PathType Leaf))
        {
            Write-host "$FilePath not found" -ForegroundColor Yellow
            return
        }
        $fullPath = (Resolve-Path $FilePath).Path
        $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $profileItem = Get-ChildItem $profileListPath  -ErrorAction SilentlyContinue | ? {
            $properties =  Get-ItemProperty $_.pspath  -ErrorAction SilentlyContinue
            $userProfilePath = $null
            if($properties)
            {
                $userProfilePath =  $properties.ProfileImagePath
            }
            $fullPath -ieq "$userProfilePath\.ssh\authorized_keys"
        }
        if($profileItem)
        {
            $userSid = $profileItem.PSChildName
            $account = Get-UserAccount -UserSid $userSid
            if($account)
            {
                Repair-FilePermission -Owners $account,$adminsAccount,$systemAccount -AnyAccessOK $account -ReadAccessNeeded $sshdAccount @psBoundParameters
            }
            else
            {
                Write-host "Can't translate $userSid to an account. skip checking $fullPath..." -ForegroundColor Yellow
            }
        }
        else
        {
            Write-host "$fullPath is not in the profile folder of any user. Skip checking..." -ForegroundColor Yellow
        }
}

<#
    .Synopsis
    Repair-UserKeyPermission
    Repair the file owner and Permission of user config
    -FilePath: The path of the private user key
    -User: The user associated with this ssh config
#>
function Repair-UserKeyPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [System.Security.Principal.NTAccount] $User = $currentUser)

        if($PSBoundParameters["FilePath"].EndsWith(".pub"))
        {
            $PSBoundParameters["FilePath"] = $PSBoundParameters["FilePath"].Replace(".pub", "")
        }        
        Repair-FilePermission -Owners $User, $adminsAccount,$systemAccount -AnyAccessOK $User @psBoundParameters
        
        $PSBoundParameters["FilePath"] += ".pub"
        Repair-FilePermission -Owners $User, $adminsAccount,$systemAccount -AnyAccessOK $User -ReadAccessOK $everyone @psBoundParameters
}

<#
    .Synopsis
    Repair-UserSSHConfigPermission
    Repair the file owner and Permission of user config
#>
function Repair-UserSshConfigPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath)
        Repair-FilePermission -Owners $currentUser,$adminsAccount,$systemAccount -AnyAccessOK $currentUser @psBoundParameters
}

<#
    .Synopsis
    Repair-FilePermissionInternal
    Only validate owner and ACEs of the file
#>
function Repair-FilePermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (        
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.NTAccount[]] $Owners = $currentUser,
        [System.Security.Principal.NTAccount[]] $AnyAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessOK,
        [System.Security.Principal.NTAccount[]] $ReadAccessNeeded
    )

    if(-not (Test-Path $FilePath -PathType Leaf))
    {
        Write-host "$FilePath not found" -ForegroundColor Yellow
        return
    }
    
    Write-host "  [*] $FilePath"
    $return = Repair-FilePermissionInternal @PSBoundParameters

    if($return -contains $true) 
    {
        #Write-host "Re-check the health of file $FilePath"
        Repair-FilePermissionInternal @PSBoundParameters
    }
}

<#
    .Synopsis
    Repair-FilePermissionInternal
#>
function Repair-FilePermissionInternal {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
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
    $paras = @{}
    $PSBoundParameters.GetEnumerator() | % { if((-not $_.key.Contains("Owners")) -and (-not $_.key.Contains("Access"))) { $paras.Add($_.key,$_.Value) } }    
    
    $validOwner = $owners | ? { $_.equals([System.Security.Principal.NTAccount]$acl.owner)}
    if($validOwner -eq $null)
    {        
        $caption = "Current owner: '$($acl.Owner)'. '$($Owners[0])' should own '$FilePath'."
        $prompt = "Shall I set the file owner?"
        $description = "Set '$($Owners[0])' as owner of '$FilePath'."        
        if($pscmdlet.ShouldProcess($description, $prompt, $caption))
	    {   
            #workaround for KB318744 on win7
            #https://support.microsoft.com/en-us/help/318744/how-to-use-visual-basic-to-programmatically-change-ownership-of-a-file-or-folder
            $p = Resolve-Path $FilePath
            $uncPath = $p.path.Replace("$($p.Drive):", "\\localhost\$($p.Drive)`$")
            $acl.SetOwner($Owners[0])
            Set-Acl -Path $uncPath -AclObject $acl -ErrorVariable e -Confirm:$false
            if($e)
            {
                Write-Warning "Repair permission failed with error: $($e[0].ToString())."
            }
            else
            {
                Write-Host "'$($Owners[0])' now owns '$FilePath'. " -ForegroundColor Green
            }
        }
        else
        {
            $health = $false
            if(-not $PSBoundParameters.ContainsKey("WhatIf"))
            {
                Write-Host "The owner is still set to '$($acl.Owner)'." -ForegroundColor Yellow
            }
        }
    }

    $ReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

    #system and admin groups can have any access to the file; plus the account in the AnyAccessOK list
    $realAnyAccessOKList = $AnyAccessOK + @($systemAccount, $adminsAccount)

    #if accounts in the ReadAccessNeeded already part of dacl, they are okay; need to make sure they have read access only
    $realReadAcessOKList = $ReadAccessOK + $ReadAccessNeeded

    #this is orginal list requested by the user, the account will be removed from the list if they already part of the dacl
    $realReadAccessNeeded = $ReadAccessNeeded

    #'APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES'- can't translate fully qualified name. it is a win32 API bug.
    #'ALL APPLICATION PACKAGES' exists only on Win2k12 and Win2k16 and 'ALL RESTRICTED APPLICATION PACKAGES' exists only in Win2k16
    $specialIdRefs = "ALL APPLICATION PACKAGES","ALL RESTRICTED APPLICATION PACKAGES"

    $aclAccess = (Get-Item -Path $FilePath).GetAccessControl('Access')
    foreach($a in $aclAccess.Access)
    {        
        if($realAnyAccessOKList -and (($realAnyAccessOKList | ? { $_.equals($a.IdentityReference)}) -ne $null))
        {
            #ignore those accounts listed in the AnyAccessOK list.
        }
        #If everyone is in the ReadAccessOK list, any user can have read access;
        # below block make sure they are granted Read access only
        elseif($realReadAcessOKList -and (($realReadAcessOKList | ? { $_.Equals($everyone)}) -ne $null) -or `
             (($realReadAcessOKList | ? { $_.equals($a.IdentityReference)}) -ne $null))
        {
            if($realReadAccessNeeded -and ($a.IdentityReference.Equals($everyone)))
            {
                $realReadAccessNeeded=@()
            }
            elseif($realReadAccessNeeded)
            {
                $realReadAccessNeeded = $realReadAccessNeeded | ? { -not $_.Equals($a.IdentityReference) }
            }

            if (-not ($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow)) -or `
            (-not (([System.UInt32]$a.FileSystemRights.value__) -band (-bnot $ReadAccessPerm))))
            {
                continue;
            }           
            
            if($a.IsInherited)
            {
                if($needChange)    
                {
                    Set-Acl -Path $FilePath -AclObject $aclAccess -Path $FilePath -Confirm:$false -ErrorVariable e
                    if($e)
                    {
                        Write-Warning "Repair permission failed with error: $($e[0].ToString())."
                    }
                }
                
                return Remove-RuleProtection @paras
            }
            $caption = "'$($a.IdentityReference)' has the following access to '$FilePath': '$($a.FileSystemRights)'."
            $prompt = "Shall I make it Read only?"
            $description = "Set'$($a.IdentityReference)' Read access only to '$FilePath'. "

            if($pscmdlet.ShouldProcess($description, $prompt, $caption))
	        {            
                $needChange = $true
                $idRefShortValue = ($a.IdentityReference.Value).split('\')[-1]
                if ($specialIdRefs -icontains $idRefShortValue )
                {
                    $ruleIdentity = Get-UserSID -User (New-Object Security.Principal.NTAccount $idRefShortValue)
                    if($ruleIdentity)
                    {
                        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                            ($ruleIdentity, "Read", "None", "None", "Allow")
                    }
                    else
                    {
                        Write-Warning "Can't translate '$idRefShortValue'. "
                        continue
                    }                    
                }
                else
                {
                    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                        ($a.IdentityReference, "Read", "None", "None", "Allow")
                    }
                $aclAccess.SetAccessRule($ace)
                Write-Host "'$($a.IdentityReference)' now has Read access to '$FilePath'. "  -ForegroundColor Green
            }
            else
            {
                $health = $false
                if(-not $PSBoundParameters.ContainsKey("WhatIf"))
                {
                    Write-Host "'$($a.IdentityReference)' still has these access to '$FilePath': '$($a.FileSystemRights)'." -ForegroundColor Yellow
                }
            }
        }
        #other than AnyAccessOK and ReadAccessOK list, if any other account is allowed, they should be removed from the dacl
        elseif($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow))
        {            
            $caption = "'$($a.IdentityReference)' should not have access to '$FilePath'." 
            if($a.IsInherited)
            {
                if($needChange)    
                {
                    Set-Acl -AclObject $aclAccess -Path $FilePath -Confirm:$false -ErrorVariable e
                    if($e)
                    {
                        Write-Warning "Repair permission failed with error: $($e[0].ToString())."
                    }
                }                
                return Remove-RuleProtection @paras
            }
            
            $prompt = "Shall I remove this access?"
            $description = "Remove access rule of '$($a.IdentityReference)' from '$FilePath'."

            if($pscmdlet.ShouldProcess($description, $prompt, "$caption."))
	        {  
                $needChange = $true
                $ace = $a
                $idRefShortValue = ($a.IdentityReference.Value).split('\')[-1]
                if ($specialIdRefs -icontains $idRefShortValue)
                {                    
                    $ruleIdentity = Get-UserSID -User (New-Object Security.Principal.NTAccount $idRefShortValue)
                    if($ruleIdentity)
                    {
                        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                            ($ruleIdentity, $a.FileSystemRights, $a.InheritanceFlags, $a.PropagationFlags, $a.AccessControlType)
                    }
                    else
                    {
                        Write-Warning "Can't translate '$idRefShortValue'. "
                        continue
                    }
                }

                if(-not ($aclAccess.RemoveAccessRule($ace)))
                {
                    Write-Warning "Failed to remove access of '$($a.IdentityReference)' from '$FilePath'."
                }
                else
                {
                    Write-Host "'$($a.IdentityReference)' has no more access to '$FilePath'." -ForegroundColor Green
                }
            }
            else
            {
                $health = $false
                if(-not $PSBoundParameters.ContainsKey("WhatIf"))
                {
                    Write-Host "'$($a.IdentityReference)' still has access to '$FilePath'." -ForegroundColor Yellow                
                }        
            }
        }
    }

    #This is the real account list we need to add read access to the file
    if($realReadAccessNeeded)
    {
        $realReadAccessNeeded | % {
            if((Get-UserSID -User $_) -eq $null)
            {
                Write-Warning "'$_' needs Read access to '$FilePath', but it can't be translated on the machine."
            }
            else
            {
                $caption = "'$_' needs Read access to '$FilePath'."
                $prompt = "Shall I make the above change?"
                $description = "Set '$_' Read only access to '$FilePath'. "

                if($pscmdlet.ShouldProcess($description, $prompt, $caption))
	            {
                    $needChange = $true
                    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                            ($_, "Read", "None", "None", "Allow")
                    $aclAccess.AddAccessRule($ace)
                    Write-Host "'$_' now has Read access to '$FilePath'." -ForegroundColor Green
                }
                else
                {
                    $health = $false
                    if(-not $PSBoundParameters.ContainsKey("WhatIf"))
                    {
                        Write-Host "'$_' does not have Read access to '$FilePath'." -ForegroundColor Yellow
                    }
                }
            }
        }
    }

    if($needChange)    
    {        
        Set-Acl -Path $FilePath -AclObject $aclAccess -ErrorVariable e -Confirm:$false
        if($e)
        {
            Write-Warning "Repair permission failed with error: $($e[0].ToString())."
        }
    }
    if($health)
    {
        if ($needChange) 
        {
            Write-Host "      Repaired permissions" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "      looks good"  -ForegroundColor Green
        }
    }
    Write-host " "
}

<#
    .Synopsis
    Remove-RuleProtection
#>
function Remove-RuleProtection
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath
    )
    $message = "Need to remove the inheritance before repair the rules."
    $prompt = "Shall I remove the inheritace?"
    $description = "Remove inheritance of '$FilePath'."

    if($pscmdlet.ShouldProcess($description, $prompt, $message))
	{
        $aclAccess = (Get-Item $FilePath).GetAccessControl('Access')
        $aclAccess.SetAccessRuleProtection($True, $True)
        Set-Acl -Path $FilePath -AclObject $aclAccess -Confirm:$false
        Write-Host "Inheritance is removed from '$FilePath'."  -ForegroundColor Green
        return $true
    }
    elseif(-not $PSBoundParameters.ContainsKey("WhatIf"))
    {        
        Write-Host "inheritance is not removed from '$FilePath'. Skip Checking FilePath."  -ForegroundColor Yellow
        return $false
    }
}
<#
    .Synopsis
    Get-UserAccount
#>
function Get-UserAccount
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

<#
    .Synopsis
    Get-UserSID
#>
function Get-UserSID
{
    param ([System.Security.Principal.NTAccount]$User)    
    try
    {
        $User.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
    }
}

Export-ModuleMember -Function Repair-FilePermission, Repair-SshdConfigPermission, Repair-SshdHostKeyPermission, Repair-AuthorizedKeyPermission, Repair-UserKeyPermission, Repair-UserSshConfigPermission
