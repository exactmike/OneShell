Function New-OneShellOrgProfile
{
    [cmdletbinding(DefaultParameterSetName = 'WriteToDisk')]
    param
    (
        [parameter(Mandatory)]
        [string]$Name
        ,
        [parameter()]
        [string[]]$OrganizationSpecificModules
        ,
        [parameter(ParameterSetName = 'WriteToDisk')]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$Path = $script:OneShellOrgProfilePath
        ,
        [parameter(ParameterSetName = 'WriteToPipeline')]
        [switch]$WriteToPipeline
    )
    $GenericOrgProfileObject = NewGenericOrgProfileObject
    $GenericOrgProfileObject.Name = $Name
    $GenericOrgProfileObject.OrganizationSpecificModules = $OrganizationSpecificModules
    Switch ($PSCmdlet.ParameterSetName)
    {
        'WriteToDisk'
        {Export-OneShellOrgProfile -Profile $GenericOrgProfileObject -Path $path -ErrorAction Stop}
        'WriteToPipeline'
        {$GenericOrgProfileObject}
    }
}
