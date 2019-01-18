Function SetOneShellVariables
{
    [cmdletbinding()]
    Param()
    #Write-OneShellLog -message 'Setting OneShell Module Variables'
    $Script:PSModuleAutoloadingPreference = 'none'
    $Script:OneShellModuleFolderPath = $PSScriptRoot #Split-Path $((Get-Module -ListAvailable -Name OneShell).Path)
    GetOneShellOrgProfileDirectory
    GetOneShellUserProfileDirectory
    $Script:LogPreference = $True
    $Script:Stamp = GetTimeStamp
    $Script:UserProfileTypeLatestVersion = 1.4
    $script:OrgProfileTypeLatestVersion = 1.2
    $script:ManagedConnections = @()
    $script:ManagedConnectionID = 0
    if (-not (Test-Path -Path variable:Script:ImportedSessionModules))
    {
        New-Variable -Name 'ImportedSessionModules' -Value @{} -Description 'Modules Imported From OneShell Sessions' -Scope Script
    }
    ##########################################################################################################
    #Import settings from json files
    ##########################################################################################################
    $Script:ServiceTypesDirectory = Join-Path $($PSScriptRoot | Split-Path -Parent) 'ServiceTypes'
    Update-OneShellServiceType
}
