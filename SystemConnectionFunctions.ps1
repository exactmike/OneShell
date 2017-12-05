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
            [ValidateSet('Admin','MRS','Service')]
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
function Find-CommandPrefixToUse
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory)]
            $ServiceObject
        )
        $CommandPrefix = $(
            if ($null -ne $ServiceObject.PreferredPrefix) #this allows a blank string to be the PreferredPrefix . . . which is what an admin may want
            {
                $ServiceObject.PreferredPrefix
            }
            else
            {
                if ($null -ne $endpoint.CommandPrefix)
                {
                    $endpoint.CommandPrefix
                }
                else
                {
                    $ServiceObject.Defaults.CommandPrefix
                }
            }
        )
        Write-Output -InputObject $CommandPrefix
    }
#end function Find-CommandPrefixToUse
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

    }
#end function Get-OneShellSystemPSSession
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
                    Write-Log -Message "Getting Service Type Session Test Commands from `$script:ServiceTypes" -EntryType Notification
                    $ServiceTypeDefinition = GetServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
                    if ($null -ne $ServiceTypeDefinition.SessionTestCmdlet)
                    {
                        $testCommand = $ServiceTypeDefinition.SessionTestCmdlet
                        $testCommandParams = Convert-ObjectToHashTable -InputObject $ServiceTypeDefinition.SessionTestCmdletParameters
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
#end function Test-OneShellSystemConnection
function Get-OneShellSystemEndpointPSSessionParameter
    {
        [cmdletbinding()]
        param
        (
            $ServiceObject
            ,
            $Endpoint
        )
        begin
        {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }#end begin
        end
        {
            $ConnectPSSessionParams = @{
                ErrorAction = 'Stop'
                Name = $($ServiceObject.Identity + '%' + $Endpoint.Identity)
                Credential = $ServiceObject.Credential
            }
            #Apply Service Type Defaults
            switch -Wildcard ($ServiceObject.ServiceType)
            {
                'Exchange*'
                {
                    $ConnectPSSessionParams.ConfigurationName = 'Microsoft.Exchange'
                    $ConnectPSSessionParams.AllowRedirection = $true
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
            #Apply ServiceObject Defaults or their endpoint overrides
            if ($ServiceObject.defaults.ProxyEnabled -eq $true -or $Endpoint.ProxyEnabled -eq $true)
            {
                $ConnectPSSessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig #-ProxyAuthentication basic
            }
            if ($ServiceObject.defaults.UseTLS -eq $true -or $Endpoint.UseTLS -eq $true)
            {
                $ConnectPSSessionParams.UseSSL = $true
            }
            if (Test-IsNotNullOrWhiteSpace -string $ServiceObject.defaults.AuthMethod)
            {
                $ConnectPSSessionParams.Authentication = $ServiceObject.defaults.AuthMethod
            }
            if (Test-IsNotNullOrWhiteSpace -String $endpoint.AuthMethod)
            {
                $ConnectPSSessionParams.Authentication = $Endpoint.AuthMethod
            }
            #Apply Endpoint only settings
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
                    if ($ServiceObject.ServiceType -eq 'ExchangeOnPremises')
                    {
                        $ConnectPSSessionParams.ConnectionUri = "http://$($endpoint.address)/PowerShell/"
                    }
                    else
                    {
                        $ConnectPSSessionParams.ComputerName = $endpoint.Address
                    }
                }
            }
            switch ($endpoint.AllowRedirection)
            {
                $true
                {
                    $ConnectPSSessionParams.AllowRedirection = $endpoint.AllowRedirection
                }
            }
            if (Test-IsNotNullOrWhiteSpace -String $endpoint.ServicePort)
            {
                $ConnectPSSessionParams.Port = $Endpoint.ServicePort
            }
            Write-Output -InputObject $ConnectPSSessionParams
        }#end end
    }
#end function Get-EndPointPSSessionParameter
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
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
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
                    Write-Log -Message "Existing Session $($ExistingSession.name) for Service $($serviceObject.Name) is valid."
                    #nothing further to do since existing connection is valid
                    #add logic for preferred endpoint/specified endpoint checking?
                }#end if
                else
                {
                    if ($null -ne $ExistingSession)
                    {
                        try
                        {
                            $message = "Remove Existing Invalid Session $($ExistingSession.name) for Service $($serviceObject.name)."
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
                    }#end if 
                    Write-Log -Message "No Existing Valid Session found for $($ServiceObject.name)" -EntryType Notification
                    #create and test the new session
                    $ConnectionReady = $false #we switch this to true when a session is connected and initialized with required modules and settings
                    #Work through the endpoint groups to try connecting in order of precedence
                    for ($i = 0; $i -lt $EndPointGroups.count -and $ConnectionReady -eq $false; $i++)
                    {
                        #get the first endpoint group and randomly order them, then work through them one at a time until successfully connected
                        $g  = $endPointGroups[$i]
                        $endpoints = @($g.group | Sort-Object -Property {Get-Random})
                        for ($ii = 0; $ii -lt $endpoints.Count -and $ConnectionReady -eq $false; $ii++)
                        {
                            $e = $endpoints[$ii]
                            $ConnectPSSessionParams = Get-OneShellSystemEndpointPSSessionParameter -ServiceObject $ServiceObject -Endpoint $e -ErrorAction Stop
                            try
                            {
                                $message = "Create New-PsSession with Name $($connectPSSessionParams.Name) for Service $($serviceObject.Name)"
                                Write-Log -Message $message -EntryType Attempting
                                $ServiceSession = New-PSSession @ConnectPSSessionParams
                                Write-Log -Message $message -EntryType Succeeded
                                $Connected = $true
                            }#end Try
                            catch
                            {
                                $myerror = $_
                                Write-Log -Message $message -EntryType Failed -ErrorLog
                                Write-Log -Message $myerror.tostring() -ErrorLog
                            }#end Catch
                            #determine if the session needs to be initialized with imported modules, variables, etc. based on ServiceType
                            $RequiredModuleImported = $(
                                if ($Connected -eq $true)
                                {
                                    try
                                    {
                                        $message = "Import Required Module(s) into PSSession $($serviceSession.Name) for $($serviceObject.Name)"
                                        Write-Log -Message $message -EntryType Attempting
                                        Import-RequiredModuleIntoOneShellSystemPSSession -ServiceObject $ServiceObject -ServiceSession $ServiceSession -ErrorAction Stop
                                        Write-Log -Message $message -EntryType Succeeded
                                    }
                                    catch
                                    {
                                        $myerror = $_
                                        Write-Log -Message $message -EntryType Failed
                                        Write-Log -Message $myerror.tostring() -ErrorLog
                                        $false
                                    }
                                }
                                else 
                                {
                                    $false
                                }
                            )
                            $Initialized = $(
                                if ($RequiredModuleImported -ne $false)
                                {
                                    try
                                    {
                                        $message = "Initialize PSSession $($serviceSession.Name) for $($serviceObject.Name)"
                                        Write-Log -Message $message -EntryType Attempting
                                        Initialize-OneShellSystemPSSession -ServiceObject $ServiceObject -ServiceSession $ServiceSession -endpoint $e -ErrorAction Stop
                                        Write-Log -Message $message -EntryType Succeeded
                                    }
                                    catch
                                    {
                                        $myerror = $_
                                        Write-Log -Message $message -EntryType Failed
                                        Write-Log -Message $myerror.tostring() -ErrorLog
                                        $false
                                    }
                                    #determine if the session needs further initialization
                                }#end if
                                else
                                {
                                    $false
                                }
                            )
                            $message = "Connection and Initialization of PSSession $($serviceSession.name) for $($serviceobject.name)"
                            if (@($Connected,$RequiredModuleImported,$Initialized) -notcontains $false)
                            {
                                Write-Log -Message $message -EntryType Succeeded
                                $ConnectionReady = $true
                            }
                            else 
                            {
                                Write-Log -Message $message -EntryType Failed -ErrorLog
                                if ($null -ne $ServiceSession)
                                {
                                    Remove-PSSession -Session $ServiceSession -ErrorAction Stop
                                }
                                
                            }
                        }#end for
                    }#end for
                    switch ($ConnectionReady)
                    {
                        $false #we couldn't connect after trying all applicable endpoints
                        {
                            Write-Log -Message "Failed to Connect to $($ServiceObject.Name). Review the errors and resolve them to connect." -ErrorLog -Verbose
                        }
                        $true
                        {
                            if ($ServiceObject.AutoImport)
                            {
                                switch ($ServiceObject.ServiceType)
                                {
                                    'AADSyncServer'
                                    {}
                                    'ActiveDirectoryDomain'
                                    {}
                                    'ActiveDirectoryGlobalCatalog'
                                    {}
                                    'ActiveDirectoryLDS'
                                    {}
                                    'AzureADTenant'
                                    {}
                                    'Office365Tenant'
                                    {}
                                    'SkypeOrganization'
                                    {}
                                    'SQLDatabase'
                                    {}
                                    Default #Exchange types and PowerShell types
                                    {
                                    }
                                }
                            }
                        }
                    }
                }
            }#end $true
            default
            {
                Write-Warning -Message "This version of OneShell does not yet test for existing connections to services/systems configured with UsePSRemoting: False"
            }#end $false
        }#end Switch
    }#end End
}#function Connect-OneShellSystem
function Import-RequiredModuleIntoOneShellSystemPSSession
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory)]
            $ServiceObject
            ,
            [parameter(Mandatory)]
            $ServiceSession
        )
        #add the module test and import functions
        switch -Wildcard ($ServiceObject.ServiceType)
        {
            'Exchange*'
            {}
            Default
            {
                Add-FunctionToPSSession -FunctionNames 'Test-ForInstalledModule','Test-ForImportedModule' -PSSession $ServiceSession
            }
        }
        #specify the required module(s) and any pre-module import settings
        switch -Wildcard ($ServiceObject.ServiceType)
        {
            'AADSyncServer'
            {
                $ModuleName  = 'AdSync'
            }
            'ActiveDirectory*'
            {
                $ModuleName = 'ActiveDirectory'
                #Suppress Creation of the Default AD Drive with current credentials
                Invoke-Command -session $ServiceSession -ScriptBlock {$Env:ADPS_LoadDefaultDrive = 0} -ErrorAction Stop
            }
            'AzureADTenant'
            {
                $ModuleName = 'AzureADPreview'
            }
            'Office365Tenant'
            {
                $ModuleName = 'MSOnline'
            }
            'SkypeOrganization'
            {
                $ModuleName = 'SkypeOnlineConnector'
            }
            'SQLDatabase'
            {
                $ModuleName = 'POSH_ADO_SQLServer'
            }
            Default
            {
                $ModuleName = $null
            }
        }
        switch ($null -eq $ModuleName)
        {
            $true
            {$ModuleImported = $null}
            $false
            {
                if (Invoke-Command -session $ServiceSession -ScriptBlock {Test-ForInstalledModule -Name $using:ModuleName} -HideComputerName)
                {
                    if (Invoke-Command -session $ServiceSession -ScriptBlock {Test-ForImportedModule -Name $using:ModuleName} -HideComputerName)
                    {
                        #module already loaded in the session
                    }
                    else
                    {
                        try
                        {
                            $message = "import required module $ModuleName into PSSession $($ServiceSession.name) for System $($serviceObject.Name)."
                            Write-Log -Message $message -EntryType Attempting
                            Invoke-Command -session $ServiceSession -ScriptBlock {Import-Module -Name $using:ModuleName -ErrorAction Stop} -ErrorAction Stop
                            Write-Log -Message $message -EntryType Succeeded
                            $ModuleImported = $true
                        }
                        catch
                        {
                            $myerror = $_
                            Write-Log -Message $message -ErrorLog -Verbose -EntryType Failed
                            Write-Log -Message $myerror.tostring() -ErrorLog
                            $ModuleImported = $false
                        }
                    }
                }
                else
                {
                    $message = "import required module $ModuleName into PSSession $($ServiceSession.name) for System $($serviceObject.Name) fails because the module is not installed at the endpoint."
                    Write-Log -Message $message -EntryType Failed -ErrorLog
                    $ModuleImported = $false
                }
            }
        }
        Write-Output -InputObject $ModuleImported
    }
#end function Import-RequiredModuleIntoOneShellSystemPSSession
function Initialize-OneShellSystemPSSession
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        $ServiceObject
        ,
        [parameter(Mandatory)]
        $ServiceSession
        ,
        [parameter(Mandatory)]
        $endpoint
    )
    Try
    {
        switch ($ServiceObject.ServiceType)
        {
            'ExchangeOnPremises'
            {
                Invoke-Command -session $ServiceSession -ScriptBlock {Set-ADserverSettings -ViewEntireForest $true -errorAction Stop} -ErrorAction Stop
                if ($endpoint.ServiceTypeAttributes.PreferredDomainControllers.count -ge 1)
                {
                    $PreferredDomainControllers = $endpoint.ServiceTypeAttributes.PreferredDomainControllers
                    Invoke-Command -session $ServiceSession -ScriptBlock {Set-ADserverSettings -SetPreferredDomainControllers $using:PreferredDomainControllers -ErrorAction Stop} -ErrorAction Stop
                }
                Write-Output -inputObject $true
            }#end ExchangeOnPremises
            'ActiveDirectory*'
            {
                #Determine the Drive Name 
                $CommandPrefix = Find-CommandPrefixToUse -serviceObject $ServiceObject
                if (Test-IsNullOrWhiteSpace -String $CommandPrefix)
                {
                    $DriveName = $ServiceObject.Name.replace(' ','') 
                }
                else
                {
                    $DriveName = $CommandPrefix
                }
                $existingdrive = Invoke-Comand -Session $serviceSession -ScriptBlock {Get-PSDrive -Name $using:DriveName -ErrorAction SilentlyContinue} -errorAction SilentlyContinue
                if ($null -eq $existingdrive)
                {
                    $UseExistingDrive = $false
                }#end if
                else
                {
                    Write-Log -Message "Existing Drive for $DriveName exists." 
                    $message = "Validate Operational Status of Drive $DriveName."
                    Write-Log -Message $message -EntryType Attempting
                    try {
                        $path = $DriveName + ':\'
                        $result = @(Invoke-Command -Session $serviceSession -Scriptblock {Get-ChildItem -Path $using:path -ErrorAction Stop})
                        If ($result.Count -ge 1)
                        {
                            Write-Log -Message $message -EntryType Succeeded
                            $UseExistingDrive = $True
                        }
                        else
                        {
                            Write-Log -Message $message -EntryType Failed -ErrorLog
                            Remove-PSDrive -Name $DriveName -ErrorAction Stop
                            $UseExistingDrive = $false
                        }
                    }
                    catch
                    {
                        Write-Log -Message $message -ErrorLog -EntryType Failed
                        Remove-PSDrive -Name $DriveName -ErrorAction Stop
                        $UseExistingDrive = $False
                    }
                }#end else
                if ($UseExistingDrive -eq $False)
                {
                    $NewPSDriveParams = @{
                        Name = $DriveName
                        Server = $endpoint.Address
                        Root = '//RootDSE/'
                        Scope = 'Global'
                        PSProvider = 'ActiveDirectory'
                        ErrorAction = 'Stop'
                        Credential = $ServiceObject.Credential
                    }#newpsdriveparams
                    if ($ServiceObject.ServiceType -eq 'ActiveDirectoryGlobalCatalog') {$NewPSDriveParams.Server = $NewPSDriveParams.Server + ':3268'}
                    if (Test-IsNotNullOrWhiteSpace -string $ServiceObject.Description) {$NewPSDriveParams.Description = $ServiceObject.Description}
                    $message = "Connect PS Drive $DriveName`: to $($serviceObject.Name)"
                    Write-Log -Message $message -EntryType Attempting
                    New-PSDrive @NewPSDriveParams  > $null
                    Write-Log -Message $message -EntryType Succeeded
                    Write-Output -InputObject $true
                } #if
            }#end ActiveDirectory
            '*Tenant'
            {
                #need to use the connect-* function to intialize the connection
            }
            'SQLDatabase'
            {
                #need to connect to the database
            }
            'LotusNotes'
            {
                #need to connect to the lotus database
            }
            Default
            {$null}
        }
    }#end Try
    Catch
    {
        Write-Log -Message $message -EntryType Failed -errorLog
        Write-Log -Message $_.tostring() -ErrorLog
        Write-Output -inputObject $false
    }
}

function Add-FunctionToPSSession
    {
        [cmdletbinding()]
        param(
            [parameter(Mandatory)]
            [string[]]$FunctionNames
            ,
            [parameter(ParameterSetName = 'SessionID',Mandatory,ValuefromPipelineByPropertyName)]
            [int]$ID
            ,
            [parameter(ParameterSetName = 'SessionName',Mandatory,ValueFromPipelineByPropertyName)]
            [string]$Name
            ,
            [parameter(ParameterSetName = 'SessionObject',Mandatory,ValueFromPipeline)]
            [Management.Automation.Runspaces.PSSession]$PSSession
            ,
            [switch]$Refresh
        )
        #Find the session
        $GetPSSessionParams=@{
            ErrorAction = 'Stop'
        }
        switch ($PSCmdlet.ParameterSetName)
        {
            'SessionID'
            {
                $GetPSSessionParams.ID = $ID
                $PSSession = Get-PSSession @GetPSSessionParams
            }
            'SessionName'
            {
                $GetPSSessionParams.Name = $Name
                $PSSession = Get-PSSession @GetPSSessionParams
            }
            'SessionObject'
            {
                #nothing required here
            }
        }
        #Verify the session availability
        if (-not $PSSession.Availability -eq 'Available')
        {
            throw "Availability Status for PSSession $($PSSession.Name) is $($PSSession.Availability).  It must be Available."
        }
        #Verify if the functions already exist in the PSSession unless Refresh
        foreach ($FN in $FunctionNames)
        {
            $script = "Get-Command -Name '$FN' -ErrorAction SilentlyContinue"
            $scriptblock = [scriptblock]::Create($script)
            $remoteFunction = Invoke-Command -Session $PSSession -ScriptBlock $scriptblock -ErrorAction SilentlyContinue
            if ($remoteFunction.CommandType -ne $null -and -not $Refresh)
            {
                $FunctionNames = $FunctionNames | Where-Object -FilterScript {$_ -ne $FN}
            }
        }
        Write-Verbose -Message "Functions remaining: $($FunctionNames -join ',')"
        #Verify the local function availiability
        $Functions = @(
            foreach ($FN in $FunctionNames)
            {
                Get-Command -ErrorAction Stop -Name $FN -CommandType Function
            }
        )
        #build functions text to initialize in PsSession 
        $FunctionsText = ''
        foreach ($Function in $Functions) {
            $FunctionText = 'function ' + $Function.Name + "`r`n {`r`n" + $Function.Definition + "`r`n}`r`n"
            $FunctionsText = $FunctionsText + $FunctionText
        }
        #convert functions text to scriptblock
        $ScriptBlock = [scriptblock]::Create($FunctionsText)
    Invoke-Command -Session $PSSession -ScriptBlock $ScriptBlock -ErrorAction Stop
    }
#end function Add-FunctionToPSSession