# Windows OpenSSH - Build Scripts

## `build-openssh.ps1`

`build-openssh.ps1` is kind of a Makefile file, which first builds OpenSSH based on the passed parameters and then calls functions from the `OPenSSHBuildHelper` PowerShell module to copy to the created artifacts into a target directory or into a ZIP file.

### Supported parameters

| Parameter        | Required | Default                                         | Description                                                     |
|------------------|----------|-------------------------------------------------|-----------------------------------------------------------------|
| ProjectDirectory | yes      |                                                 | Source directory                                                |
| Configuration    | no       | Release                                         | What configuration to build<br>Valid values: Release, Debug     |
| Platform         | no       | x64                                             | Build for what platform<br>Valid values: x86, x64               |
| DestinationPath  | no       | `$(OpenSSH-Bin-Path)$(Platform)\$(Configuration)` | The directory path of the location to which binaries are placed |
| SkipClean        | no       |                                                 | Don't run a clean before a build                                |

## `build-msi.ps1`

`build-msi.ps1` is used for building the MSI installation package for OpenSSH. 

In addition it creates MSI product GUIDs for a given version of OpenSSH in a deterministic way. Creating MSI product GUIDs in a deterministic eases the deployment of the generated MSI by using a configuration management software like Ansible, Chef or Puppet, because those frameworks idempotently configure a target system and thus rely on a fixed anchor to determine if a MSI Product of a specific version is installed or not.

**Example:** Install MSI using Ansible `win_package` task

```yaml
- name: Install OpenSSH
  win_package:
    path: openssh.msi
    product_id: '{0240359E-6A4C-4884-9E94-B397A02D893C}'
    state: present
```

### Supported parameters

| Parameter        | Required | Default                                                     | Description                                                                                                                                             |
|------------------|----------|-------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| ProjectDirectory | yes      |                                                             | Path to openssh-install.wixproj                                                                                                                         |
| SourceDirectory  | yes      |                                                             | Path to the installation binaries.<br>Typically the destination directory of `build-openssh.ps1`                                                        |
| Configuration    | no       | Release                                                     | What configuration to build<br>Valid values: Release, Debug                                                                                             |
| Platform         | no       | x64                                                         | Build for what platform<br>Valid values: x86, x64                                                                                                       |
| DestinationPath  | no       | $env:TEMP                                                   | The directory where to put the created MSI.<br>Inside this directory the MSI will be saved into the<br>`bin\$(Platform)\$(Configuration)` subdirectory. |
| Version          | no       | Version information of ssh.exe<br>in the `$(SourceDirectory)` | The Version tag of the created MSI                                                                                                                      |
| SkipClean        | no       |                                                             | Don't run a clean before a build                                                                                                                        |
