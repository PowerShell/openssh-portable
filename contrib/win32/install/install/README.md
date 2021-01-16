# Windows OpenSSH - MSI project

The project, based on the [WiX Toolset](https://wixtoolset.org/), creates a Windows MSI package to install OpenSSH on Windows computers.

The projects supports building MSI packages for 32bit and 64bit platforms. In addition the MSI supports a wider range of installation flags to perform the installation of OpenSSH complete silently. Furthermore the MSI ensures that Debug end Release Versions cannot installed simultaneously. When the OpenSSH server components are installed, the MSI will also configure the Windows Firewall, to ensure that the SSH Server is reachable over the network.

## Build Parameters

The following parameters are supported 

* `MANUFACTURER`: (optional) the manufacturer of the MSI; default: Microsoft Corporation
* `CONFIGURATION`: (required) the configuration used; Valid values: `Release`, `Debug`
* `VERSION`: (optional) the version tag of the MSI; default: `0.0.0.0`
* `SOURCEDIR`: (required) the path to the input files
* `PRODUCTID`: (optional) the Product GUID of the created MSI; default: dynamic (`*`), changes every time the MSI is build

The parameters are passed via `Msbuild` properties.

Example:

```
$ msbuild openssh-install.wixproj /p:Version=8.1.1 /p:Configuration=Release /p:Platform=x64 /p:SourceDir=c:\openssh-portable\bin /p:ProductId="15512e42-e946-45f9-bbe5-a8e495bd2e2b"
```

## MSI internals

### Upgrade Codes

* Debug Version: `c7a00fb1-c477-40d3-a951-ec4c749da439`
* Release Version: `e2dd3c95-7a8b-444e-b75b-3e1cf697aadc`

https://docs.microsoft.com/en-us/windows/win32/msi/using-an-upgradecode

### Flags

The following flags are supported. The flags are passed as public properties during an installation using `msiexec.exe`.

* `DISABLE_CLIENT`: don't install ssh client components
* `ENABLE_CLIENTSYMBOLS`: install symbol files for ssh client components
* `ENABLE_SERVER`: install and configure OpenSSH Server and the corresponding OpenSSH Authentication Agent
* `ENABLE_SERVERSYMBOLS`: install symbol files for ssh server components
* `ENABLE_SCRIPTS`: install scripts for managing a OpenSSH installation

**Example:** silently install OpenSSH client tools and corresponding symbol files

```
$ msiexec /q /i openssh.msi /l*vx openssh.msi.log  ENABLE_CLIENTSYMBOLS=1
```

**Example:** silently install only OpenSSH server components

```
$ msiexec /q /i openssh.msi /l*vx openssh.msi.log  DISABLE_CLIENT=1 ENABLE_SERVER=1
```
