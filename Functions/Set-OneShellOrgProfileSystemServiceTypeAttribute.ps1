    Function Set-OneShellOrgProfileSystemServiceTypeAttribute
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipelineByPropertyName, Mandatory)]
        [string]$ProfileIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity #System Identity or Name
        ,
        [parameter(Mandatory)]
        [string]$ServiceType
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )#end param
    DynamicParam
    {
        #build any service type specific parameters that may be needed
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.System -and $ServiceTypeDefinition.ServiceTypeAttributes.System.count -ge 1)
        {
            foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.System)
            {
                $newDynamicParameterParams = @{
                    Name = $a.name
                    Type = $($a.type -as [type])
                    Mandatory = $a.mandatory
                    DPDictionary = $dictionary
                }
                if ($true -eq $a.Value) {$newDynamicParameterParams.ValidateSet = $a.Value}
                $dictionary = New-DynamicParameter @newDynamicParameterParams
            }
        }
        $dictionary
    }#End DynamicParam
    Begin
    {
        $PotentialOrgProfiles = GetPotentialOrgProfiles -path $Path
    }
    Process
    {
        foreach ($i in $Identity)
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Org Profile
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
            #Get/Select the System
            $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $i -Operation Edit
            if ($ServiceType -ne $System.ServiceType) {throw("ServiceType specified does not match the system.")}
            #Edit the selected System
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            #Set the ServiceType Specific System Attributes
            $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
            if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.System -and $ServiceTypeDefinition.ServiceTypeAttributes.System.count -ge 1)
            {
                $ServiceTypeAttributeNames = @($ServiceTypeDefinition.ServiceTypeAttributes.System.Name)
            }
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in $ServiceTypeAttributeNames)
                {$System.ServiceTypeAttributes.$($vp.name) = $($vp.value)}
            }
            #update the system entry in the org profile
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath
        }
    }

    }

