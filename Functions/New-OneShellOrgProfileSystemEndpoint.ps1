    Function New-OneShellOrgProfileSystemEndpoint
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$SystemIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ServiceType
        ,
        [Parameter(Mandatory)]
        [ValidateSet('URL', 'IPAddress', 'FQDN')]
        [String]$AddressType
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Address
        ,
        [Parameter()]
        [AllowNull()]
        [ValidatePattern("^\d{1,5}$")]
        $ServicePort
        ,
        [parameter()]
        [AllowNull()]
        [ValidateSet($true, $false, $null)]
        $UseTLS
        ,
        [parameter()]
        [AllowNull()]
        [validateSet($true, $false, $null)]
        $ProxyEnabled = $false
        ,
        [parameter()]
        [ValidateLength(2, 5)]
        $CommandPrefix
        ,
        [parameter()]
        [AllowNull()]
        [validateSet($true, $false, $null)]
        $AuthenticationRequired
        ,
        [parameter()]
        [ValidateSet('Basic', 'Kerberos', 'Integrated')]
        $AuthMethod
        ,
        [parameter()]
        [string]$EndpointGroup
        ,
        [parameter()]
        [int16]$Precedence
        ,
        [parameter()]
        [ValidateSet('Admin', 'MRSProxyServer')]
        [string]$EndpointType = 'Admin'
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$Path = $Script:OneShellOrgProfilePath
    )
    DynamicParam
    {
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint -and $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.count -ge 1)
        {
            foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint)
            {
                $Dictionary = New-DynamicParameter -Name $a.name -Type $($a.type -as [type]) -Mandatory $a.Mandatory -DPDictionary $Dictionary
            }
        }
        #if (Test-IsNotNullOrWhiteSpace -string $ServiceTypeDefinition.WellKnownEndpointURI)
        #{Write-Warning -Message "$($serviceType) systems in OneShell use a well-known endpoint $($ServiceTypeDefinition.WellKnownEndpointURI). If you create an endpoint for this system type it will be ignored when connecting to this system."}
        $Dictionary
    }#End DynamicParam
    Process
    {
        Foreach ($i in $SystemIdentity)
        {
            if ($null -ne $Dictionary)
            {
                Set-DynamicParameterVariable -dictionary $Dictionary
            }
            #Get the System and then the profile from the system
            $System = Get-OneShellOrgProfileSystem -Identity $i -Path $Path -ErrorAction Stop -ProfileIdentity $ProfileIdentity
            $OrgProfile = Get-OneShellOrgProfile -Identity $ProfileIdentity
            if ($ServiceType -ne $system.ServiceType)
            {throw("Invalid ServiceType $serviceType specified (does not match system ServiceType $($system.servicetype))")}
            #Get the new endpoint object
            $GenericEndpointObject = NewGenericSystemEndpointObject
            #Set the new endpoint object attributes
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'AddressType', 'Address', 'ServicePort', 'UseTLS', 'ProxyEnabled', 'CommandPrefix', 'AuthenticationRequired', 'AuthMethod', 'EndpointGroup', 'EndpointType', 'ServiceType', 'Precedence')
                {$GenericEndpointObject.$($vp.name) = $($vp.value)}
            }
            #Add any servicetype specific attributes that were specified
            ###########################################################
            $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
            if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint -and $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.count -ge 1)
            {
                $ServiceTypeAttributeNames = @($ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.Name)
                foreach ($n in $ServiceTypeAttributeNames)
                {
                    $GenericEndpointObject.ServiceTypeAttributes | Add-Member -Name $n -Value $null -MemberType NoteProperty
                }
            }
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in $ServiceTypeAttributeNames)
                {
                    $GenericEndpointObject.ServiceTypeAttributes.$($vp.name) = $($vp.value)
                }
            }
            ###########################################################
            #Add the endpoint object to the system
            $system.endpoints += $GenericEndpointObject
            #Strip 'extra' Org Attributes that were added
            $system = $system | Select-Object -Property * -excludeProperty OrgName, OrgIdentity, ProfileIdentity
            #update the system on the profile object
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName 'Systems' -IdentityAttributeName 'Identity'
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath -ErrorAction Stop
        }
    }

    }

