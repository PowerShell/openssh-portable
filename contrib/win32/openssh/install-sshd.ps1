﻿# @manojampalam - authored initial script
# @friism - Fixed issue with invalid SDDL on Set-Acl
# @manojampalam - removed ntrights.exe dependency
# @bingbing8 - removed secedit.exe dependency
# @tessgauthier - added permissions check for %programData%/ssh

$ErrorActionPreference = 'Stop'

if (!([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")))
{
    throw "You must be running as an administrator, please restart as administrator"
}

$scriptpath = $MyInvocation.MyCommand.Path
$scriptdir = Split-Path $scriptpath

$sshdpath = Join-Path $scriptdir "sshd.exe"
$sshagentpath = Join-Path $scriptdir "ssh-agent.exe"
$etwman = Join-Path $scriptdir "openssh-events.man"

if (-not (Test-Path $sshdpath)) {
    throw "sshd.exe is not present in script path"
}

if (Get-Service sshd -ErrorAction SilentlyContinue) 
{
   Stop-Service sshd
   sc.exe delete sshd 1>$null
}

if (Get-Service ssh-agent -ErrorAction SilentlyContinue) 
{
   Stop-Service ssh-agent
   sc.exe delete ssh-agent 1>$null
}

# unregister etw provider
wevtutil um `"$etwman`"

# adjust provider resource path in instrumentation manifest
[XML]$xml = Get-Content $etwman
$xml.instrumentationManifest.instrumentation.events.provider.resourceFileName = $sshagentpath.ToString()
$xml.instrumentationManifest.instrumentation.events.provider.messageFileName = $sshagentpath.ToString()

$streamWriter = $null
$xmlWriter = $null
try {
    $streamWriter = new-object System.IO.StreamWriter($etwman)
    $xmlWriter = [System.Xml.XmlWriter]::Create($streamWriter)    
    $xml.Save($xmlWriter)
}
finally {
    if($streamWriter) {
        $streamWriter.Close()
    }
}

# Fix the registry permissions
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\OpenSSHUtils -Force
Enable-Privilege SeRestorePrivilege | out-null

$sshRootRegPath="HKLM:SOFTWARE/Openssh"
if (Test-Path $sshRootRegPath)
{
    $sshRootAcl=Get-Acl $sshRootRegPath
    # SDDL - FullAcess to System and Builtin/Admins and read only access to Authenticated users
    $sshRootAcl.SetSecurityDescriptorSddlForm("O:BAG:SYD:P(A;OICI;KR;;;AU)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)")
    Set-Acl $sshRootRegPath $sshRootAcl
}

$sshAgentRegPath="HKLM:SOFTWARE/Openssh/agent"
if (Test-Path $sshAgentRegPath)
{
    $sshAgentAcl=Get-Acl $sshAgentRegPath
    # SDDL - FullAcess to System and Builtin/Admins.
    $sshAgentAcl.SetSecurityDescriptorSddlForm("O:BAG:SYD:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)")
    Set-Acl $sshAgentRegPath  $sshAgentAcl
}

#Fix permissions for moduli file
$moduliPath = Join-Path $PSScriptRoot "moduli"
if (Test-Path $moduliPath -PathType Leaf)
{
    Repair-ModuliFilePermission -FilePath $moduliPath @psBoundParameters -confirm:$false
}

#If %programData%/ssh folder already exists, fix permissions
$sshProgDataPath = Join-Path $env:ProgramData "ssh"
if (Test-Path $sshProgDataPath)
{
    $sshProgDataAcl=Get-Acl $sshProgDataPath
    # Folder permission is FullAccess to System and Builtin/Admins and read only access to Authenticated users
    $sshProgDataAcl.SetSecurityDescriptorSddlForm("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)")
    Set-Acl $sshProgDataPath $sshProgDataAcl
    # private key files and log folder/files should only allow FullAccess to System and Builtin/Admins
    $restricted_files = @("ssh_host_dsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key", "ssh_host_rsa_key")
    $sshProgDataAcl.SetSecurityDescriptorSddlForm("O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)")
    Get-ChildItem -Path (Join-Path $sshProgDataPath '*') -Recurse -Include $restricted_files -Force | Set-Acl -AclObject $sshProgDataAcl
    $sshProgDataAcl.SetSecurityDescriptorSddlForm("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    $log_folder = Join-Path $sshProgDataPath "logs"
    if (Test-Path $log_folder)
    {
        Set-Acl $log_folder $sshProgDataAcl 
    }
}

#register etw provider
wevtutil im `"$etwman`"

$agentDesc = "Agent to hold private keys used for public key authentication."
New-Service -Name ssh-agent -DisplayName "OpenSSH Authentication Agent" -BinaryPathName `"$sshagentpath`" -Description $agentDesc -StartupType Manual | Out-Null
sc.exe sdset ssh-agent "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)"
sc.exe privs ssh-agent SeImpersonatePrivilege

$sshdDesc = "SSH protocol based service to provide secure encrypted communications between two untrusted hosts over an insecure network."
New-Service -Name sshd -DisplayName "OpenSSH SSH Server" -BinaryPathName `"$sshdpath`" -Description $sshdDesc -StartupType Manual | Out-Null
sc.exe privs sshd SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege

Write-Host -ForegroundColor Green "sshd and ssh-agent services successfully installed"
