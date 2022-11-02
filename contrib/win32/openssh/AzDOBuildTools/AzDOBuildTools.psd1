##
## Azure DevOps CI build tools
## (TODO: Add appropriate copyright)
##
@{

RootModule = './AzDOBuildTools.psm1'

ModuleVersion = '1.0.0'

GUID = '0b8fa798-ea71-40c7-b9ab-a417958bb3c4'

Author = 'Microsoft Corporation'

CompanyName = 'Microsoft Corporation'

Copyright = '(c) Microsoft Corporation. All rights reserved.'

Description = 'AzDO build tools for Win32-OpenSSH repository.'

PowerShellVersion = '5.1'
DotnetFrameworkVersion = '4.6.1'
CLRVersion = '4.0.0'

NestedModules = @(
    '../OpenSSHCommonUtils.psm1',
    '../OpenSSHBuildHelper.psm1',
    '../OpenSSHTestHelper.psm1')

FunctionsToExport = @(
    'Invoke-AllLocally',
    'Invoke-AzDOBuild',
    'Install-OpenSSH',
    'Invoke-OpenSSHTests',
    'Copy-OpenSSHTestResults')

}
