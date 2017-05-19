<#
.Synopsis
    Finds the root of the git repository

.Outputs
    A System.IO.DirectoryInfo for the location of the root.

.Inputs
    None

.Notes
    FileNotFoundException is thrown if the current directory does not contain a CMakeLists.txt file.
#>
function Get-RepositoryRoot
{
    $currentDir = (Get-Item -Path $PSCommandPath).Directory

    while ($null -ne $currentDir.Parent)
    {
        $path = Join-Path -Path $currentDir.FullName -ChildPath '.git'
        if (Test-Path -Path $path)
        {
            return $currentDir
        }
        $currentDir = $currentDir.Parent
    }

    throw new-object System.IO.DirectoryNotFoundException("Could not find the root of the GIT repository")
}

<#
.Synopsis
    Sets the Secure File ACL. 
    1. Removed all user acl except Administrators group, system, and current user
    2. whether or not take the owner

.Outputs
    N/A

.Inputs
    FilePath - The path to the file
    takeowner - if want to take the ownership
#>
function Cleanup-SecureFileACL 
{
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [System.Security.Principal.NTAccount] $Owner)

    $myACL = Get-ACL $filePath
    $myACL.SetAccessRuleProtection($True, $FALSE)
    Set-Acl -Path $filePath -AclObject $myACL

    $myACL = Get-ACL $filePath
    if($owner -ne $null)
    {        
        $myACL.SetOwner($owner)
    }
    
    if($myACL.Access) 
    {        
        $myACL.Access | % {
            if(-not ($myACL.RemoveAccessRule($_)))
            {
                throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
            }
        }
    }

    $adminACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ("BUILTIN\Administrators", "FullControl", "None", "None", "Allow") 
    $myACL.AddAccessRule($adminACE)

    $systemACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ("NT AUTHORITY\SYSTEM", "FullControl", "None", "None", "Allow")
    $myACL.AddAccessRule($systemACE)

    Set-Acl -Path $filePath -AclObject $myACL
}

<#
.Synopsis
    Host key should be owned by LOCALSYSTEM account
    private host key can be accessed by only localsystem and Administrators
    pub host key can be accessed by only localsystem and Administrators and read by everyone

.Outputs
    N/A

.Inputs
    FilePath - The path to the file
#>
function Adjust-HostKeyFileACL
{
        param (
        [parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $myACL = Get-ACL $FilePath
    $myACL.SetAccessRuleProtection($True, $FALSE)
    Set-Acl -Path $FilePath -AclObject $myACL

    $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
    $adminAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
    $everyoneAccount = New-Object System.Security.Principal.NTAccount("EveryOne")
    $myACL = Get-ACL $FilePath

    $myACL.SetOwner($systemAccount)

    if($myACL.Access) 
    {        
        $myACL.Access | % {
            if(-not ($myACL.RemoveAccessRule($_)))
            {
                throw "failed to remove access of $($_.IdentityReference.Value) rule in setup "
            }
        }
    }    

    $adminACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($adminAccount, "FullControl", "None", "None", "Allow") 
    $myACL.AddAccessRule($adminACE)

    $systemACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($systemAccount, "FullControl", "None", "None", "Allow")
    $myACL.AddAccessRule($systemACE)

    if($FilePath.EndsWith(".pub"))
    {
        $everyoneAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ("Everyone", "Read", "None", "None", "Allow")
        $myACL.AddAccessRule($everyoneAce)
    }
    else
    {
        #this only is needed when the private host keys are not registered with agent
        $sshdAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ("NT service\sshd", "Read", "None", "None", "Allow")
        $myACL.AddAccessRule($sshdAce)
    }
    Set-Acl -Path $FilePath -AclObject $myACL
}

<#
.Synopsis
    Host key should be owned by LOCALSYSTEM account
    private host key can be accessed by only localsystem and Administrators
    pub host key can be accessed by only localsystem and Administrators and read by everyone

.Outputs
    N/A

.Inputs
    FilePath - The path to the file
#>
function Adjust-UserKeyFileACL
{
    param (
    [parameter(Mandatory=$true)]
    [string]$FilePath,
    [System.Security.Principal.NTAccount] $Owner = $null,
    [System.Security.AccessControl.FileSystemRights[]] $OwnerPerms = $null
    )

    $myACL = Get-ACL $FilePath
    $myACL.SetAccessRuleProtection($True, $FALSE)
    Set-Acl -Path $FilePath -AclObject $myACL

    $systemAccount = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
    $adminAccount = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
    $everyoneAccount = New-Object System.Security.Principal.NTAccount("EveryOne")
    $myACL = Get-ACL $FilePath

    $actualOwner = $null
    if($Owner -eq $null)
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

    $adminACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($adminAccount, "FullControl", "None", "None", "Allow") 
    $myACL.AddAccessRule($adminACE)

    $systemACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($systemAccount, "FullControl", "None", "None", "Allow")
    $myACL.AddAccessRule($systemACE)

    if($OwnerPerms)
    {
        $OwnerPerms | % { 
            $ownerACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($actualOwner, $_, "None", "None", "Allow")
            $myACL.AddAccessRule($ownerACE)
        }
    }

    if($FilePath.EndsWith(".pub"))
    {
        $everyoneAce = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ("Everyone", "Read", "None", "None", "Allow")
        $myACL.AddAccessRule($everyoneAce)
    }
    
    Set-Acl -Path $FilePath -AclObject $myACL
}

<#
.Synopsis
    add a file permission to an account

.Outputs
    N/A

.Inputs
    FilePath - The path to the file    
    User - account name
    Perm - The permission to grant.
#>
function Add-PermissionToFileACL 
{
        param (
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [System.Security.Principal.NTAccount] $User,
        [System.Security.AccessControl.FileSystemRights[]]$Perms
    )    

    $myACL = Get-ACL $FilePath
        
    if($Perms)
    {
        $Perms | % { 
            $userACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($User, $_, "None", "None", "Allow")
            $myACL.AddAccessRule($userACE)
        }
    }    

    Set-Acl -Path $FilePath -AclObject $myACL
}

Export-ModuleMember -Function Get-RepositoryRoot, Add-PermissionToFileACL, Cleanup-SecureFileACL, Adjust-HostKeyFileACL, Adjust-UserKeyFileACL