@echo off
echo "Stopping SSHd service..."
net stop sshd
echo "Removing SSHd service..."
sc.exe delete sshd
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
echo "Stopping SSH-Agent service..."
net stop ssh-agent
echo "Removing SSH-Agent service..."
sc.exe delete ssh-agent
if NOT ERRORLEVEL 0 (
    echo "Error %ERRORLEVEL%."
    exit %ERRORLEVEL%
)
echo "Services uninstalled successfully."