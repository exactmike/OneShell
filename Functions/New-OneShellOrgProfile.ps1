    Function New-OneShellOrgProfile
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [string]$Name
        ,
        [parameter()]
        [string[]]$OrganizationSpecificModules
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$Path = $script:OneShellOrgProfilePath
    )
    $GenericOrgProfileObject = NewGenericOrgProfileObject
    $GenericOrgProfileObject.Name = $Name
    $GenericOrgProfileObject.OrganizationSpecificModules = $OrganizationSpecificModules
    Export-OneShellOrgProfile -profile $GenericOrgProfileObject -path $path -erroraction Stop

    }

