Enum PlatformType {
    Windows
    Linux
    OSX
}

function Get-Platform {
    # Use the .NET Core APIs to determine the current platform; if a runtime
    # exception is thrown, we are on FullCLR, not .NET Core.
    try {
        $Runtime = [System.Runtime.InteropServices.RuntimeInformation]
        $OSPlatform = [System.Runtime.InteropServices.OSPlatform]
        
        $IsLinux = $Runtime::IsOSPlatform($OSPlatform::Linux)
        $IsOSX = $Runtime::IsOSPlatform($OSPlatform::OSX)
        $IsWindows = $Runtime::IsOSPlatform($OSPlatform::Windows)
    } catch {    
        try {            
            $IsLinux = $false
            $IsOSX = $false
            $IsWindows = $true
        }
        catch { }
    }
    if($IsOSX) {
        [PlatformType]::OSX
    } elseif($IsLinux) {
        [PlatformType]::Linux
    } else {        
        [PlatformType]::Windows    
    }
}

function Set-SecureFileACL 
{            
    param(
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [System.Security.Principal.NTAccount]$Owner = $null,
        [System.Security.AccessControl.FileSystemRights[]] $OwnerPerms = @("Read", "Write")
        )

    $myACL = Get-ACL -Path $FilePath
    $myACL.SetAccessRuleProtection($True, $FALSE)
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

    if($OwnerPerms)
    {
        $OwnerPerms | % { 
            $ownerACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($actualOwner, $_, "None", "None", "Allow")
            $myACL.AddAccessRule($ownerACE)
        }
    }

    Set-Acl -Path $FilePath -AclObject $myACL
}
        
function Add-PermissionToFileACL 
{    
    param(
        [parameter(Mandatory=$true)]
        [string]$FilePath,
        [System.Security.Principal.NTAccount] $User,
        [System.Security.AccessControl.FileSystemRights[]]$Perms,
        [System.Security.AccessControl.AccessControlType] $AccessType = "Allow"
    )    

    $myACL = Get-ACL $FilePath

    if($Perms)
    {
        $Perms | % { 
            $userACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($User, $_, "None", "None", $AccessType)
            $myACL.AddAccessRule($userACE)
        }
    }   

    Set-Acl -Path $FilePath -AclObject $myACL
}

function Add-PasswordSetting 
{
    param([string] $pass)
    $platform = Get-Platform
    if ($platform -eq [PlatformType]::Windows) {
        if (-not($env:DISPLAY)) {$env:DISPLAY = 1}
        $env:SSH_ASKPASS="$($env:ComSpec) /c echo $pass"
    }
}

function Remove-PasswordSetting
{
    if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY }
    Remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
}