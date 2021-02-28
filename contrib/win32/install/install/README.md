# Windows OpenSSH - MSI project

The project, based on the [WiX Toolset](https://wixtoolset.org/), creates a Windows MSI package to install OpenSSH on Windows computers.

The projects supports building MSI packages for 32bit and 64bit platforms. In addition the MSI supports a wider range of installation flags to perform the installation of OpenSSH complete silently. Furthermore the MSI ensures that Debug end Release Versions cannot installed simultaneously. When the OpenSSH server components are installed, the MSI will also configure the Windows Firewall, to ensure that the SSH Server is reachable over the network.

## Build Parameters

The following parameters are supported 

* `CONFIGURATION`: (required) the configuration used; Valid values: `Release`, `Debug`
* `VERSION`: (required) the version tag of the MSI
* `SOURCEDIR`: (required) the path to the input files
* `MANUFACTURER`: (optional) the manufacturer of the MSI; default: Microsoft Corporation
* `PRODUCTID`: (optional) the Product GUID of the created MSI; default: dynamic (`*`), changes every time the MSI is build
* `IsPreview`: (optional) create a MSI for a previw version of OpenSSH, default: `false`

The parameters are passed via `Msbuild` properties.

Example:

```shell
$ msbuild openssh-install.wixproj /p:Version=8.1.1 /p:Configuration=Release /p:Platform=x64 /p:SourceDir=c:\openssh-portable\bin /p:ProductId="15512e42-e946-45f9-bbe5-a8e495bd2e2b"
```

## MSI internals

### Upgrade Codes

https://docs.microsoft.com/en-us/windows/win32/msi/using-an-upgradecode

#### x64 (64-bit)

* Preview version: `5a388d64-a109-4d85-bddc-7f46e1e1e520`
* Release version: `c7a00fb1-c477-40d3-a951-ec4c749da439`

#### x86 (32-bit)

* Preview version: `271d2cdd-3c91-423f-b4e8-9c711a9e8ab1`
* Release version: `dd240959-6051-4108-9c7f-c409dca2b65e`

### Features

The MSI contains the following features

* `Client`: install ssh client components (enabled by default)
* `ClientSymbols`: install symbol files for ssh client components
* `Server`: install and configure OpenSSH Server and the corresponding OpenSSH Authentication Agent
* `ServerFirewall`: configure firewall exception for incoming SSH traffic (TCP, Port 22)
* `ServerSymbols`: install symbol files for ssh server components
* `Scripts`: install scripts for managing a OpenSSH installation

**Example:** silently install OpenSSH client tools and corresponding symbol files

```shell
$ msiexec /q /i openssh.msi /l*vx openssh.msi.log  ADDLOCAL=Client,ClientSymbols
```

**Example:** silently install only OpenSSH server components and firewall exception, but no client tools

```shell
$ msiexec /q /i openssh.msi /l*vx openssh.msi.log  ADDLOCAL=Server,ServerFirewall REMOVE=Client
```
