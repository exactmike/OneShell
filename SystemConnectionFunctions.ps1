##########################################################################################################
#Remote System Connection Functions
##########################################################################################################
function Find-EndPointToUse
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [AllowNull()]
            $EndPointIdentity
            ,
            $ServiceObject
            ,
            $EndPointGroup
        )
        $FilteredEndpoints = @(
            switch ($null -eq $EndPointIdentity)
            {
                $false
                {
                    Write-verbose -Message "Endpoint Identity was specified.  Return only that endpoint."
                    if ($EndPointIdentity -notin $ServiceObject.EndPoints.Identity)
                    {throw("Invalid EndPoint Identity $EndPointIdentity was specified. System $($ServiceObject.Identity) has no such endpoint.")}
                    else
                    {
                        $ServiceObject.EndPoints | Where-Object -FilterScript {$_.Identity -eq $EndPointIdentity}
                    }
                }
                $true
                {
                    Write-verbose -message "Endpoint Identity was not specified.  Return all applicable endpoints, with preferred first if specified."
                    switch ($null -eq $ServiceObject.PreferredEndpoint)
                    {
                        $false
                        {
                            Write-Verbose -Message "Preferred Endpoint is specified."
                            $PreEndpoints = @(
                                switch ($null -eq $EndPointGroup)
                                {
                                    $true
                                    {
                                        Write-Verbose -message 'EndPointGroup was not specified'
                                        $ServiceObject.EndPoints | Sort-Object -Property Precedence
                                    }#end false
                                    $false
                                    {
                                        Write-Verbose -message 'EndPointGroup was specified'
                                        $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndPointGroup -eq $EndPointGroup} | Sort-Object -Property Precedence
                                    }#end true
                                }#end switch
                            )
                            $PreEndpoints | Where-Object {$_.Identity -eq $ServiceObject.PreferredEndpoint} | ForEach-Object {$_.Precedence = -1}
                            Write-Output -InputObject $PreEndpoints
                        }#end false
                        $true
                        {
                            Write-Verbose -Message "Preferred Endpoint is not specified."
                            switch ($null -eq $EndPointGroup)
                            {
                                $true
                                {
                                    Write-Verbose -message 'EndPointGroup was not specified'
                                    $ServiceObject.EndPoints | Sort-Object -Property Precedence
                                }#end false
                                #EndPointGroup was specified
                                $false
                                {
                                    Write-Verbose -message 'EndPointGroup was specified'
                                    $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndPointGroup -eq $EndPointGroup} | Sort-Object -Property Precedence
                                }#end true
                            }#end switch
                        }#end true
                    }#end switch
                }#end $true
            }#end switch
        )
        $GroupedEndpoints = @($FilteredEndpoints | Group-Object -Property Precedence)
        Write-Output -InputObject $GroupedEndpoints
    }
#end function Find-EndPointToUse
function Find-ExchangeOnlineEndpointToUse
    {
        [cmdletbinding()]
        param
        (
            $ServiceObject
        )
        Group-Object -InputObject @(
            [PSCustomObject]@{
                Identity = (New-Guid).guid
                AddressType = 'URL'
                Address = 'https://outlook.office365.com/powershell-liveid/'
                ServicePort = $null
                UseTLS = $false
                ProxyEnabled = $ServiceObject.Defaults.ProxyEnabled
                CommandPrefix = $ServiceObject.Defaults.CommandPrefix
                AuthenticationRequired = $true
                AuthMethod = 'Basic'
                EndPointGroup = $null
                EndPointType = 'Admin'
                ServiceTypeAttributes = $null
                ServiceType = 'ExchangeOrganization'
                AllowRedirection = $true
                Precedence = -1
                PSRemoting = $true
            }
        )
    }
#end function Find-ExchangeOnlineEndpointToUse
function Find-ComplianceCenterEndpointToUse
    {
        [cmdletbinding()]
        param
        (
            $ServiceObject
        )
        Group-Object
        [PSCustomObject]@{
            Identity = (New-Guid).guid
            AddressType = 'URL'
            Address = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
            ServicePort = $null
            IsDefault = $true
            UseTLS = $false
            ProxyEnabled = $ServiceObject.Defaults.ProxyEnabled
            CommandPrefix = $ServiceObject.Defaults.CommandPrefix
            AuthenticationRequired = $true
            AuthMethod = 'Basic'
            EndPointGroup = $null
            EndPointType = 'Admin'
            ServiceTypeAttributes = $null
            ServiceType = 'ExchangeOrganization'
            AllowRedirection = $true
            PSRemoting = $true
        }
    }
#end function Find-ComplianceCenterEndpointToUse
function Get-OneShellAvailableSystem
    {
        [cmdletbinding()]
        param
        (
        )
        DynamicParam
        {
            $dictionary = New-DynamicParameter -name ServiceType -ValidateSet $(getorgprofilesystemservicetypes) -Type $([string[]]) -Mandatory $false
            Write-Output -InputObject $dictionary
        }
        end
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            if ($null -eq $script:CurrentOrgProfile)
            {throw('No OneShell Organization profile is active.  Use function Use-OrgProfile to load an organization profile.')}
            if ($null -eq $script:CurrentAdminUserProfile)
            {throw('No OneShell Admin user profile is active.  Use function Use-AdminUserProfile to load an admin user profile.')}
            Write-Verbose -Message "ServiceType is set to $($serviceType -join ',')"
            (Get-OneShellVariableValue -Name CurrentSystems -ErrorAction Stop).GetEnumerator() |
            Where-object -FilterScript {$null -eq $ServiceType -or $_.ServiceType -in $ServiceType}
        }
    }
#end function Get-OneShellAvailableSystem
Function Connect-OneShellSystem
{
    [cmdletbinding(DefaultParameterSetName = 'Default')]
    Param
    (
        [parameter(ParameterSetName = 'EndPointIdentity')]
        [ValidateNotNullOrEmpty()]
        [string]$EndPointIdentity #An endpoint identity from existing endpoints configure for this system. Overrides the otherwise specified endpoint.
        ,
        [parameter(ParameterSetName = 'EndPointGroup')]
        [ValidateNotNullOrEmpty()]
        [string]$EndPointGroup #An endpoint identity from existing endpoints configure for this system. Overrides the otherwise specified endpoint.
        ,
        [parameter()]
        [ValidateScript({($_.length -ge 2 -and $_.length -le 5) -or [string]::isnullorempty($_)})]
        [string]$CommandPrefix #Overrides the otherwise specified command prefix.
        ,
        [parameter()]
        [ValidateSet('PowerShell','SQLDatabase','ExchangeOnPremises','ExchangeOnline','ExchangeComplianceCenter','AADSyncServer','AzureADTenant','Office365Tenant','ActiveDirectoryDomain','ActiveDirectoryGlobalCatalog','ActiveDirectoryLDS','MailRelayEndpoint','SkypeOrganization')]
        [string[]]$ServiceType #used only to filter list of available system identities and names
    )
    DynamicParam
    {
        if ($null -ne $serviceType)
        {
            $AvailableOneShellSystems = @(Get-OneShellAvailableSystem -ServiceType $ServiceType)
        }
        else
        {
            $AvailableOneShellSystems = @(Get-OneShellAvailableSystem)
        }
        $AvailableOneShellSystemNamesAndIdentities = @($AvailableOneShellSystems.Name;$AvailableOneShellSystems.Identity)
        $Dictionary = New-DynamicParameter -Name Identity -Type $([String]) -Mandatory $true -ValidateSet $AvailableOneShellSystemNamesAndIdentities -Position 1
        Write-Output -InputObject $dictionary
    }#DynamicParam
    end
    {
        Set-DynamicParameterVariable -dictionary $Dictionary
        $ServiceObject = $AvailableOneShellSystems  | Where-Object -FilterScript {$_.name -eq $Identity -or $_.Identity -eq $Identity}
        Write-Verbose -Message "Selecting an Endpoint"
        $EndPointGroups = @(
            switch ($ServiceObject.ServiceType)
            {
                'ExchangeOnline'
                {
                    Find-ExchangeOnlineEndpointToUse -ServiceObject $ServiceObject -ErrorAction Stop
                }
                'ExchangeComplianceCenter'
                {
                    Find-ComplianceCenterEndpointToUse -ServiceObject $ServiceObject -ErrorAction Stop
                }
                Default
                {
                    $FindEndPointToUseParams = @{
                        ErrorAction = 'Stop'
                        ServiceObject = $ServiceObject
                    }
                    switch ($PSCmdlet.ParameterSetName)
                    {
                        'Default'
                        {}
                        'EndPointIdentity'
                        {$FindEndPointToUseParams.EndPointIdentity = $EndPointIdentity}
                        'EndPointGroup'
                        {$FindEndPointToUseParams.EndPointGroup = $EndPointGroup}
                    }
                    Find-EndPointToUse @FindEndPointToUseParams
                }
            }
        )
        if ($null -eq $EndPointGroups -or $EndPointGroups.Count -eq 0)
        {throw("No endpoint found for system $($serviceObject.Name), $($serviceObject.Identity)")}
        #Test for an existing connection
            #if the connection is opened, test for functionality
            #if not remove
            #if functional leave as is
            #if not remove
        #
    }#end End
}#function Connect-Exchange
