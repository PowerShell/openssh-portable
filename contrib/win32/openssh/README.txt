Custom paths for the visual studio projects are defined in paths.targets.

All projects import this targets file, and it should be in the same directory as the project.

The custom paths are:

OpenSSH-Src-Path            =  The directory path of the OpenSSH root source directory (with trailing slash)
OpenSSH-Bin-Path            =  The directory path of the location to which binaries are placed.  This is the output of the binary projects
OpenSSH-Lib-Path            =  The directory path of the location to which libraries are placed.  This is the output of the libary projects
LibreSSL-x86-Path           =  The directory path of LibreSSL statically compiled for x86 platform.
LibreSSL-x64-Path           =  The directory path of LibreSSL statically compiled for x64 platform.

Prerequisites
-------------

Before building OpenSSH for Windows, install the following:

1. Visual Studio 2022 (Community, Professional, or Build Tools).
   Required components (Visual Studio Installer -> Modify):
     - Workload: "Desktop development with C++"
         This installs MSBuild, the v143 toolset, and the Windows 10/11 SDK.
     - Individual component: "MSVC v143 - VS 2022 C++ x64/x86 Spectre-mitigated libs (Latest)"
         Required because the vcpkg x64-custom triplet compiles
         dependencies (LibreSSL, libfido2, zlib) with /Qspectre, which
         demands matching Spectre-mitigated runtime libraries.
     - For ARM64 builds, also install "MSVC v143 - VS 2022 C++ ARM64 Spectre-mitigated libs".

   Note: If a newer Visual Studio (e.g. VS 2026) is also installed,
   OpenSSH-build.ps1 prefers VS 2022 and pins vcpkg's CMake to the
   same install / v143 toolset automatically.

2. Git for Windows.
   The build script expects git.exe to be on PATH (it will add
   "%ProgramFiles%\Git\cmd" to the machine PATH if missing).

3. vcpkg (one-time bootstrap).
   Dependencies (LibreSSL, libfido2, zlib, libcbor) are managed via a
   vcpkg manifest (vcpkg.json). MSBuild auto-installs them at build
   time, but vcpkg must be cloned, bootstrapped, and integrated first:

     git clone https://github.com/microsoft/vcpkg
     cd vcpkg
     .\bootstrap-vcpkg.bat
     .\vcpkg.exe integrate install

   "vcpkg integrate install" registers vcpkg's MSBuild props user-wide;
   after that, every OpenSSH-build.ps1 run picks up the manifest
   automatically. No need to run "vcpkg install" manually.

4. Administrator PowerShell.
   The build script updates the machine PATH (to add Git / Chocolatey)
   and may install the Windows SDK via Chocolatey if missing. Run the
   build from an elevated PowerShell session.

Notes on FIDO2 support
----------------------

* How to build:

  - Open Windows PowerShell as Administrator.

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
