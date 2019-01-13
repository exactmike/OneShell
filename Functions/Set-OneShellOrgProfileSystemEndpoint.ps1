    Function Set-OneShellOrgProfileSystemEndpoint
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$SystemIdentity
        ,
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ServiceType
        ,
        [Parameter()]
        [ValidateSet('URL', 'IPAddress', 'FQDN')]
        [String]$AddressType
        ,
        [Parameter()]
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
        $EndpointGroup
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
        if ($null -ne $Dictionary)
        {
            Set-DynamicParameterVariable -dictionary $Dictionary
        }
        #Get Org Profile
        $OrgProfile = Get-OneShellOrgProfile -Identity $ProfileIdentity -Path $Path -ErrorAction Stop
        #Get the System
        $System = Get-OneShellOrgProfileSystem -Identity $SystemIdentity -Path $Path -ErrorAction Stop
        if ($System.Endpoints.Count -eq 0) {throw('There are no endpoints to set')}
        #Get the Endpoint
        foreach ($i in $Identity)
        {
            $endPoint = @($System.Endpoints | Where-Object -FilterScript {
                    $_.Identity -eq $i -or $_.Address -eq $i
                })
            if ($endPoint.Count -ne 1) {throw ("Invalid or Ambiguous Endpoint Identity $Identity Provided")}
            else {$Endpoint = $Endpoint[0]}
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            #Set the new endpoint object attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'AddressType', 'Address', 'ServicePort', 'UseTLS', 'ProxyEnabled', 'CommandPrefix', 'AuthenticationRequired', 'AuthMethod', 'EndpointGroup', 'EndpointType', 'ServiceType', 'Precedence')
                {$endpoint.$($vp.name) = $($vp.value)}
            }
        }
        #Set any servicetype specific attributes that were specified
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint -and $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.count -ge 1)
        {
            $ServiceTypeAttributeNames = @($ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.Name)
        }
        foreach ($vp in $AllValuedParameters)
        {
            if ($vp.name -in $ServiceTypeAttributeNames)
            {
                $Endpoint.ServiceTypeAttributes.$($vp.name) = $($vp.value)
            }
        }
        $System = update-ExistingObjectFromMultivaluedAttribute -ParentObject $System -ChildObject $Endpoint -MultiValuedAttributeName Endpoints -IdentityAttributeName Identity
        $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
        Export-OneShellOrgProfile -Path $OrgProfile.DirectoryPath -profile $OrgProfile -ErrorAction Stop
    }#end End

    }

