    Function Remove-OneShellOrgProfileSystem
    {
        
    [cmdletbinding(SupportsShouldProcess)]
    param
    (
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity #System Identity or Name
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
    )
    Process
    {
        Foreach ($i in $Identity)
        {
            #Get the System and then the profile from the system
            $System = Get-OneShellOrgProfileSystem -Identity $Identity -Path $Path -ErrorAction Stop -ProfileIdentity $ProfileIdentity
            $OrgProfile = Get-OneShellOrgProfile -Identity $ProfileIdentity
            #Remove the system from the Org Profile
            $OrgProfile = Remove-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath -ErrorAction Stop
        }
    }

    }

