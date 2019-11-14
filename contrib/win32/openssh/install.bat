@echo off
md "%windir%\system32\openssh"
if NOT ERRORLEVEL 0 (
    echo "There was an error creating the folder '%windir%\system32\openssh' be sure to run this installer elevated."
    exit 1
) ELSE (
    copy *.* "%windir%\system32\openssh"
    install-sshd.bat
)