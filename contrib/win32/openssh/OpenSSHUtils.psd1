@{
    ModuleToProcess = 'OpenSSHUtils.psm1'
    ModuleVersion = '0.0.2.0'
    GUID = '08285dee-3d08-476b-8948-1a7e2562c079'
    Author = 'Microsoft Corporation'
    CompanyName = 'Microsoft Corporation'
    Copyright = '© Microsoft Corporation. All rights reserved.'
    Description = 'Utilities and functions for configuring OpenSSH on Windows.'
    FunctionsToExport = 'Repair-SshdConfigPermission', 'Repair-SshdHostKeyPermission', 'Repair-AuthorizedKeyPermission', 'Repair-UserKeyPermission', 'Repair-UserSshConfigPermission' 
    CmdletsToExport= ''
    VariablesToExport = ''
    AliasesToExport = ''
    PowerShellVersion = '2.0'
    
    PrivateData = @{
        PSData = @{
            Tags = @('SSH', 'OpenSSH', 'PSEdition_Desktop')
            ProjectUri = 'https://github.com/PowerShell/Win32-OpenSSH'
        }
    }
}
