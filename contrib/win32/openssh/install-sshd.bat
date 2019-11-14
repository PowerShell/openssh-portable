@echo off
echo "Removing existing service sshd..."
sc.exe delete sshd
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)
echo "Removing existing service ssh-agent..."
sc.exe delete ssh-agent
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)
echo "Unregistering etw provider..."
wevtutil um "%windir%\system32\openssh\openssh-events.man"
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)
echo "Installing the SSH-Agent service..."
sc.exe create ssh-agent binpath= "%windir%\system32\openssh\ssh-agent.exe" type= own start= demand displayname= "OpenSSH Authentication Agent"
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)
echo "Setting service security descriptor for SSH-Agent..."
sc.exe sdset ssh-agent "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)"
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)
echo "Setting service priviledges for SSH-Agent..."
sc.exe privs ssh-agent SeImpersonatePrivilege
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)

echo "Installing SSHd service..."
sc.exe create sshd binpath= "%windir%\system32\openssh\sshd.exe" type= own start= demand displayname= "OpenSSH SSH Server"
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)
echo "Setting service priviledges for SSHd..."
sc.exe privs sshd SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)

echo "SSHd and SSH-Agent services successfully installed."