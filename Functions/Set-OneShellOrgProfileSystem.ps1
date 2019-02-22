function Set-OneShellOrgProfileSystem
{
    [cmdletbinding()]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Identity')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity #System Identity or Name
        #,switching service types of a system is not currently supported because of ServiceTypeAttributes for systems and endpoints
        #[parameter(ValueFromPipelineByPropertyName)]
        #[string]$ServiceType
        ,
        [parameter(ValueFromPipelineByPropertyName)]
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
        [bool]$UsePSRemoting
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
                    Mandatory = $false #$a.mandatory
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
    }
    Process
    {
        foreach ($i in $Identity)
        {
            #Get/Select the Org Profile
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
            #Get/Select the System
            $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $i -Operation Edit
            #Edit the selected System
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            #Set the common System Attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'Name', 'Description', 'ServiceType')
                {$System.$($vp.name) = $($vp.value)}
            }
            #set the default System Attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'UseTLS', 'ProxyEnabled', 'CommandPrefix', 'AuthenticationRequired', 'AuthMethod','UsePSRemoting')
                {$System.defaults.$($vp.name) = $($vp.value)}
            }
            #set the ServiceType Attributes
            #make sure they exist on the object
            $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $System.ServiceType
            Add-RequiredMember -RequiredMember $ServiceTypeDefinition.ServiceTypeAttributes.System.Name -InputObject $System.ServiceTypeAttributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in $ServiceTypeDefinition.ServiceTypeAttributes.System.Name)
                {$System.ServiceTypeAttributes.$($vp.name) = $($vp.value)}
            }
            #update the system entry in the org profile
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath
        }
    }
}
#end function Set-OneShellOrgProfileSystem