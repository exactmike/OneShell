    Function New-OneShellOrgProfileSystem
    {
        
    [cmdletbinding(SupportsShouldProcess)]
    param
    (
        [parameter(ParameterSetName = 'Identity', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$Description
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ServiceType
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$ProxyEnabled
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$AuthenticationRequired
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$UseTLS
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$UsePSRemoting = $true
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Basic', 'Kerberos', 'Integrated')]
        $AuthMethod
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$CommandPrefix
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
        $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
        if ($null -ne $dictionary)
        {
            Set-DynamicParameterVariable -dictionary $dictionary
        }
        #Get/Select the OrgProfile
        $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
        #Build the System Object
        $GenericSystemObject = NewGenericOrgSystemObject
        $GenericSystemObject.ServiceType = $ServiceType
        #Edit the selected System
        $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
        #Set the common System Attributes
        foreach ($vp in $AllValuedParameters)
        {
            if ($vp.name -in 'Name', 'Description')
            {$GenericSystemObject.$($vp.name) = $($vp.value)}
        }
        #set the default System Attributes
        foreach ($vp in $AllValuedParameters)
        {
            if ($vp.name -in 'UseTLS', 'ProxyEnabled', 'CommandPrefix', 'AuthenticationRequired', 'AuthMethod','UsePSRemoting')
            {$GenericSystemObject.defaults.$($vp.name) = $($vp.value)}
        }
        $addServiceTypeAttributesParams = @{
            OrgSystemObject = $GenericSystemObject
            ServiceType     = $ServiceType
        }
        if ($null -ne $Dictionary)
        {$addServiceTypeAttributesParams.Dictionary = $Dictionary}
        $GenericSystemObject = AddServiceTypeAttributesToGenericOrgSystemObject @addServiceTypeAttributesParams
        $OrgProfile.Systems += $GenericSystemObject
        Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath
    }

    }

