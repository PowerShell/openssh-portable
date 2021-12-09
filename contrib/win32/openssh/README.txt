Custom paths for the visual studio projects are defined in paths.targets.  

All projects import this targets file, and it should be in the same directory as the project.

The custom paths are:

OpenSSH-Src-Path            =  The directory path of the OpenSSH root source directory (with trailing slash)
OpenSSH-Bin-Path            =  The directory path of the location to which binaries are placed.  This is the output of the binary projects
OpenSSH-Lib-Path            =  The directory path of the location to which libraries are placed.  This is the output of the libary projects
LibreSSL-x86-Path           =  The directory path of LibreSSL statically compiled for x86 platform.
LibreSSL-x64-Path           =  The directory path of LibreSSL statically compiled for x64 platform.

Notes on FIDO2 support
----------------------

* How to build:

  - Open Windows PowerShell.

  - Build OpenSSH for Windows:

    $ cd \path\to\openssh-portable\..
    $ .\openssh-portable\contrib\win32\openssh\OpenSSH-build.ps1

* What has been tested:

  * Using a Yubico Security Key.

  - Create a new SSH key:

    $ ssh-keygen.exe -t ecdsa-sk

    * Save the key material in SSH's default paths without an associated passphrase.

  - Add the SSH key to your GitHub account.

  - Tell git to use our SSH build:

    $ $Env:GIT_SSH = '\path\to\ssh.exe'

  - Clone a repository using the SSH key for authentication:

    $ git clone ssh://git@github.com/org/some-private-repo

* WSL2:

  - Export GIT_SSH:

    $ export GIT_SSH=/mnt/c/.../path/to/ssh.exe

  - Optionally, alias ssh:

    $ alias ssh=/mnt/c/.../path/to/ssh.exe

* Note: FIDO2 keys are supported by ssh-agent.

* What definitely doesn't work:

  * ssh-keygen -O no-touch-required:
    - there does not appear to be a way to toggle user presence in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS.
  * ssh-keygen -K, ssh-add -K:
    - these use Credential Management to reconstruct the SSH private key.
