param ([switch]$Quiet)
Import-Module $PSScriptRoot\OpenSSHUtils.psm1 -Force -DisableNameChecking

#check sshd config file
$sshdConfigPath = join-path $PSScriptRoot "sshd_config"
if(Test-Path $sshdConfigPath -PathType Leaf)
{
    Fix-HostSSHDConfigPermissions -FilePath $sshdConfigPath @psBoundParameters
}
else
{
    Write-host "$FilePath does not exist"  -ForegroundColor Yellow
}
 
#check private host keys
Get-ChildItem $PSScriptRoot\ssh_host_*_key -ErrorAction Ignore | % {    
    Fix-HostKeyPermissions -FilePath $_.FullName @psBoundParameters
}


#check authorized_keys
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"  -ErrorAction Ignore | % {
    $userProfilePath = Get-ItemPropertyValue $_.pspath -Name ProfileImagePath -ErrorAction Ignore
    $filePath = Join-Path $userProfilePath .ssh\authorized_keys
    if(Test-Path $filePath -PathType Leaf)
    {
        Fix-AuthorizedKeyPermissions -FilePath $filePath @psBoundParameters
    }
}

Write-Host "   Done."
Write-Host " "
