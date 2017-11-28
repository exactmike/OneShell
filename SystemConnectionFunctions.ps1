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
            ,
            [parameter()]
            [ValidateSet('Admin','MRS')]
            $EndPointType = 'Admin'
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
                                        $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType} | Sort-Object -Property Precedence
                                    }#end false
                                    $false
                                    {
                                        Write-Verbose -message 'EndPointGroup was specified'
                                        $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType -and $_.EndPointGroup -eq $EndPointGroup} | Sort-Object -Property Precedence
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
                                    $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType} | Sort-Object -Property Precedence
                                }#end false
                                #EndPointGroup was specified
                                $false
                                {
                                    Write-Verbose -message 'EndPointGroup was specified'
                                    $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType -and $_.EndPointGroup -eq $EndPointGroup} | Sort-Object -Property Precedence
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
        @(
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
        ) | Group-Object
    }
#end function Find-ExchangeOnlineEndpointToUse
function Find-ComplianceCenterEndpointToUse
    {
        [cmdletbinding()]
        param
        (
            $ServiceObject
        )
        @(
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
        ) | Group-Object
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
function Get-OneShellSystemPSSession
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $serviceObject
    )
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
    end
    {
        [string]$SessionNameWildcard = $($serviceObject.Identity) + '*'
        $message = "Run Get-PSSession for name like $SessionNameWildcard"
        try
        {
            Write-Log -Message $message -EntryType Attempting
            $ServiceSession = @(Get-PSSession -Name $SessionNameWildcard -ErrorAction Stop)
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $myerror = $_
            Write-Log -Message $message -EntryType Failed
            Write-Log -Message $myerror.tostring() -ErrorLog
        }
        Write-Output -InputObject $ServiceSession
    }
}#end function Get-OneShellSystemPSSession
function Test-OneShellSystemConnection
{
    [cmdletbinding()]
    param
    (
        $serviceObject
        ,
        [switch]$ReturnSession
    )
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
    end
    {
        try
        {
            $ServiceSession = @(Get-OneShellSystemPSSession -serviceObject $serviceObject -ErrorAction Stop)
        }
        catch
        {
            Write-Log -Message $_.tostring() -ErrorLog
        }
        switch ($ServiceSession.Count)
        {
            1
            {
                $ServiceSession = $ServiceSession[0]
                $message = "Found PSSession $($ServiceSession.name) for service $($serviceObject.Name)."
                Write-Log -Message $message -EntryType Notification
                #Test the Session functionality
                if ($ServiceSession.state -ne 'Opened')
                {
                    Write-Log -Message "PSSession $($ServiceSession.name) for service $($serviceObject.Name) is not in state 'Opened'." -EntryType Notification
                    Write-Output -InputObject $false
                    break
                }
                else
                {
                    Write-Log -Message "PSSession $($ServiceSession.name) for service $($serviceObject.Name) is in state 'Opened'." -EntryType Notification
                }
                Write-Log -Message "Getting Service Type Session Test Commands from file ServiceTypeSessionTestCommands.json" -EntryType Notification
                $testCommands = import-JSON -Path (Join-Path $PSScriptRoot ServiceTypeSessionTestCommands.json) -ErrorAction Stop
                $testCommandDetails = $testCommands.ServiceTypes | Where-Object -FilterScript {$_.Name -eq $serviceObject.ServiceType}
                if ($null -ne $testCommandDetails)
                {
                    $testCommand = $testCommandDetails.SessionTestCmdlet
                    $testCommandParams = Convert-ObjectToHashTable -InputObject $testCommandDetails.parameters
                    Write-Log -Message "Found Service Type Command to use for $($serviceObject.ServiceType): $testCommand" -EntryType Notification
                    $ScriptBlock = [scriptblock]::Create("$TestCommand @TestCommandParams")
                    $message = "Run $([string]$scriptblock) in $($serviceSession.name) PSSession"
                    try
                    {
                        Write-Log -Message $message -EntryType Attempting
                        invoke-command -Session $ServiceSession -ScriptBlock {$TestCommandParams = $using:TestCommandParams} -ErrorAction Stop
                        invoke-command -Session $ServiceSession -ScriptBlock $ScriptBlock -ErrorAction Stop
                        Write-Log -Message $message -EntryType Succeeded
                        Write-Output -InputObject $true
                    }
                    catch
                    {
                        $myerror = $_
                        Write-Log -Message $message -EntryType Failed -ErrorLog
                        Write-Log -message $myerror.tostring() -ErrorLog
                        Write-Output -InputObject $false
                        break
                    }
                }#end if
                else
                {
                    Write-Log "No Service Type Command to use for Service Testing is specified for ServiceType $($ServiceObject.ServiceType)."
                    Write-Output -InputObject $true
                }
            }
            0
            {
                $message = "Found No PSSession for service $($serviceObject.Name)."
                Write-Log -Message $message -EntryType Notification
                Write-Output -InputObject $false
            }
            Default
            {
                $message = "Found multiple PSSessions $($ServiceSession.name -join ',') for service $($serviceObject.Name). Please delete one or more sessions then try again."
                Write-Log -Message $message -EntryType Failed -ErrorLog
                Write-Output -InputObject $false
            }
        }
        if ($ReturnSession)
        {Write-Output -InputObject $ServiceSession}
    }
}
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
        switch ($ServiceObject.defaults.UsePSRemoting -or $true)
        {
            $true
            {
                $ExistingConnectionIsValid,$ExistingSession = Test-OneShellSystemConnection -serviceObject $ServiceObject -ErrorAction Stop -ReturnSession
                #check results of the test for an existing session
                if ($ExistingConnectionIsValid)
                {
                    Write-Log -Message "Existing Session $($session.name) for Service $($serviceObject.Name) is valid."
                    #nothing further to do since existing connection is valid
                    #add logic for preferred endpoint/specified endpoint checking?
                }
                else
                {
                    if ($null -ne $ExistingSession)
                    {
                        try
                        {
                            $message = "Remove Existing Invalid Session $($Session.name) for Service $($serviceObject.name)."
                            Write-Log -Message $message -EntryType Attempting
                            Remove-PSSession -Session $ExistingSession -ErrorAction Stop
                            Write-Log -Message $message -EntryType Succeeded
                        }
                        catch
                        {
                            $myerror = $_
                            Write-Log -Message $message -EntryType Failed -ErrorLog
                            Write-Log -Message $myerror.tostring() -EntryType -ErrorLog
                            throw ($myerror)
                        }
                    }
                    #create and test the new session
                    do
                    {
                        foreach ($g in $EndPointGroups)
                        {
                            $endpoints = @($g.group)
                            do
                            {
                                $RandomSelection = Get-Random -Maximum $endpoints.Count -Minimum 0
                                $endpoint = $endpoints[$RandomSelection]
                                $endpoints = @($endpoints | Where-Object -FilterScript {$_.Identity -ne $endpoint.Identity})
                                $ConnectPSSessionParams = @{
                                    ErrorAction = 'Stop'
                                    Name = $($ServiceObject.Identity + '%' + $Endpoint.Identity)
                                    Credential = $ServiceObject.Credential
                                }
                                switch ($endpoint.AddressType)
                                {
                                    'URL'
                                    {
                                        $ConnectPSSessionParams.ConnectionUri = $endpoint.Address
                                    }
                                    'IPAddress'
                                    {
                                        $ConnectPSSessionParams.ComputerName = $endpoint.Address
                                    }
                                    'FQDN'
                                    {
                                        $ConnectPSSessionParams.ComputerName = $endpoint.Address
                                    }
                                }
                                switch -Wildcard ($endpoint.ServiceType)
                                {
                                    'Exchange*'
                                    {
                                        $ConnectPSSessionParams.ConfigurationName = 'Microsoft.Exchange'
                                    }
                                    'ExchangeOnline'
                                    {
                                        $ConnectPSSessionParams.Authentication = 'Basic'
                                    }
                                    'ExchangeComplianceCenter'
                                    {
                                        $ConnectPSSessionParams.Authentication = 'Basic'
                                    }
                                    'ExchangeOnPremises'
                                    {
                                        $ConnectPSSessionParams.Authentication = 'Kerberos'
                                    }
                                }
                                switch ($endpoint.AllowRedirection)
                                {
                                    $true
                                    {
                                        $ConnectPSSessionParams.AllowRedirection = $endpoint.AllowRedirection
                                    }
                                }
                            }
                            until ($endpoints.Count -eq 0)
                            $AllEndpointsFailed = $true
                        }
                    }
                    until
                    (
                        $Connected -eq $true -or $AllEndpointsFailed -eq $true
                    )
                }
            }#end $true
            default
            {
                Write-Warning -Message "This version of OneShell does not yet test for existing connections to services/systems configured with UsePSRemoting: False"
            }#end $false
        }#end Switch
        Return $ConnectPSSessionParams
    }#end End
}#function Connect-OneShellSystem
