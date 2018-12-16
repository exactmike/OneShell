﻿#
# Module manifest for module 'OneShell'
#
# Generated by: Mike Campbell
#
# Generated on:
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'OneShell.psm1'

    # Version number of this module.
    ModuleVersion     = '2.2.7'

    # ID used to uniquely identify this module
    GUID              = 'bd4390dc-a8ad-4bce-8d69-f53ccf8e4163'

    # Author of this module
    Author            = 'Mike Campbell'

    # Company or vendor of this module
    CompanyName       = 'Exact Solutions'

    # Copyright statement for this module
    Copyright         = '(c) 2018. All rights reserved.'

    # Description of the functionality provided by this module
    # Description = ''

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.0'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @(PsMenu)

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    #NestedModules = @('PSMenu.psm1')

    # Functions to export from this module
    #FunctionsToExport = '*'
    FunctionsToExport = @(
        'Connect-OneShellSystem'
        'ConvertFrom-FQDN'
        'Export-OneShellData'
        'Export-OneShellOrgProfile'
        'Export-OneShellUserProfile'
        'Get-OneShellSystem'
        'Get-OneShellOrgProfile'
        'Get-OneShellOrgProfileSystem'
        'Get-OneShellOrgProfileSystemEndpoint'
        'Get-OneShellServiceTypeDefinition'
        'Get-OneShellServiceTypeName'
        'Get-OneShellSystemPSSession'
        'Get-OneShellUserProfile'
        'Get-OneShellUserProfileCredential'
        'Get-OneShellUserProfileSystem'
        'Get-OneShellVariable'
        'Get-OneShellVariableValue'
        'Get-MicrosoftAzureADTenantID'
        'Import-OneShellSystemPSSession'
        'New-OneShellOrgProfile'
        'New-OneShellOrgProfileSystem'
        'New-OneShellOrgProfileSystemEndpoint'
        'New-OneShellTimer'
        'New-OneShellUserProfile'
        'New-OneShellUserProfileCredential'
        'New-OneShellVariable'
        'Remove-OneShellAgedFile'
        'Remove-OneShellOrgProfileSystem'
        'Remove-OneShellOrgProfileSystemEndpoint'
        'Remove-OneShellUserProfile'
        'Remove-OneShellUserProfileCredential'
        'Remove-OneShellVariable'
        'Set-OneShellOrgProfile'
        'Set-OneShellOrgProfileDirectory'
        'Set-OneShellOrgProfileSystem'
        'Set-OneShellOrgProfileSystemEndpoint'
        'Set-OneShellOrgProfileSystemServiceTypeAttribute'
        'Set-OneShellUserProfile'
        'Set-OneShellUserProfileCredential'
        'Set-OneShellUserProfileDirectory'
        'Set-OneShellUserProfileSystem'
        'Set-OneShellUserProfileSystemCredential'
        'Set-OneShellUserProfileSystemPreferredEndpoint'
        'Set-OneShellVariable'
        'Test-OneShellSystemConnection'
        'Update-OneShellUserProfileSystem'
        'Update-OneShellUserProfileTypeVersion'
        'Update-OneShellServiceType'
        'Use-OneShellOrgProfile'
        'Use-OneShellUserProfile'
        'Write-OneShellLog'
    )

    # Cmdlets to export from this module
    #CmdletsToExport = '*'

    # Variables to export from this module
    #VariablesToExport = '*'

    # Aliases to export from this module
    #AliasesToExport = '*'

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('Office365','AzureAD','Exchange','Skype','Azure','Active-Directory','AD-LDS','Azure-AD-Connect','administration','migration','skype-for-business','azure-active-directory','lotus-notes','scheduled-tasks')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/exactmike/OneShell/blob/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/exactmike/OneShell'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

            # External dependent modules of this module
            # ExternalModuleDependencies = ''
        } # End of PSData hashtable
    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/exactmike/OneShell/blob/master/GettingStarted.md'

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}
