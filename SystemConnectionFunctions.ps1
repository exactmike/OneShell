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
function Get-WellKnownEndPoint
    {
        [cmdletbinding()]
        param
        (
            $ServiceObject
        )
        $ServiceTypeDefinition = GetServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
        @(
            [PSCustomObject]@{
                Identity = $ServiceObject.ServiceType + '-WellKnownEndPoint'
                AddressType = 'URL'
                Address = $ServiceTypeDefinition.WellKnownEndPointURI
                ServicePort = $null
                UseTLS = $false
                ProxyEnabled = $ServiceObject.Defaults.ProxyEnabled
                CommandPrefix = $ServiceObject.Defaults.CommandPrefix
                AuthenticationRequired = $true
                AuthMethod = $ServiceTypeDefinition.WellKnownEndPointAuthMethod
                EndPointGroup = $null
                EndPointType = 'Admin'
                ServiceTypeAttributes = $null
                ServiceType = $ServiceObject.ServiceType
                Precedence = -1
                PSRemoting = $true
            }
        ) | Group-Object
    }
#end function Find-ExchangeOnlineEndpointToUse
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
                    Write-Log -Message "Getting Service Type Session Test Commands" -EntryType Notification
                    $ServiceTypeDefinition = GetServiceTypeDefinition -ServiceType $ServiceObject.ServiceType -ErrorAction Stop
                    if ($null -ne $ServiceTypeDefinition.SessionTestCmdlet)
                    {
                        $testCommand = $ServiceTypeDefinition.SessionTestCmdlet
                        $TestCommandParams = @{
                            ErrorAction = 'Stop'
                        }
                        #$testCommandParams.WarningAction = 'SilentlyContinue' #don't add because in constrained PSSessions this might not be allowed
                        if ($null -ne $ServiceTypeDefinition.SessionTestCmdletParameters -and $ServiceTypeDefinition.SessionTestCmdletParameters.count -ge 1)
                        {
                            foreach ($p in $ServiceTypeDefinition.SessionTestCmdletParameters)
                            {
                                $value = $(
                                    switch ($p.ValueType)
                                    {
                                        'Static'
                                        {$p.Value}
                                        'ScriptBlock'
                                        {
                                            $ValueGeneratingScriptBlock = [scriptblock]::Create($p.Value)
                                            &$ValueGeneratingScriptBlock
                                        }
                                    }
                                )
                                $TestCommandParams.$($p.name) = $value
                            }
    
                        }
                        Write-Log -Message "Found Service Type Command to use for $($serviceObject.ServiceType): $testCommand" -EntryType Notification
                        $message = "Run $testCommand in $($serviceSession.name) PSSession"
                        try
                        {
                            Write-Log -Message $message -EntryType Attempting
                            invoke-command -Session $ServiceSession -ScriptBlock {&$Using:TestCommand @using:TestCommandParams} -ErrorAction Stop | out-null
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
            $ServiceTypeDefinition = GetServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
            $NewPSSessionParams = @{
                ErrorAction = 'Stop'
                Name = $($ServiceObject.Identity + '%' + $Endpoint.Identity)
                Credential = $ServiceObject.Credentials.PSSession
            }
            #Apply Service Type Defaults
            foreach ($p in $ServiceTypeDefinition.PSSessionParameters)
            {
                $value = $(
                    switch ($p.ValueType)
                    {
                        'Static'
                        {$p.Value}
                        'ScriptBlock'
                        {
                            & $([scriptblock]::Create($p.Value))
                        }
                    }
                )
                $NewPSSessionParams.$($p.name) = $value
            }
            #Apply ServiceObject Defaults or their endpoint overrides
            if ($ServiceObject.defaults.ProxyEnabled -eq $true -or $Endpoint.ProxyEnabled -eq $true)
            {
                $NewPSSessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig #-ProxyAuthentication basic
            }
            if ($ServiceObject.defaults.UseTLS -eq $true -or $Endpoint.UseTLS -eq $true)
            {
                $NewPSSessionParams.UseSSL = $true
            }
            if (Test-IsNotNullOrWhiteSpace -string $ServiceObject.defaults.AuthMethod)
            {
                $NewPSSessionParams.Authentication = $ServiceObject.defaults.AuthMethod
            }
            if (Test-IsNotNullOrWhiteSpace -String $endpoint.AuthMethod)
            {
                $NewPSSessionParams.Authentication = $Endpoint.AuthMethod
            }
            #Apply Endpoint only settings
            if (Test-IsNotNullOrWhiteSpace -String $endpoint.ServicePort)
            {
                $NewPSSessionParams.Port = $Endpoint.ServicePort
            }
            Write-Output -InputObject $NewPSSessionParams
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
        [ValidateSet('PowerShell','SQLDatabase','ExchangeOnPremises','ExchangeOnline','ExchangeComplianceCenter','AADSyncServer','AzureAD','AzureADPreview','MSOnline','ActiveDirectoryDomain','ActiveDirectoryGlobalCatalog','ActiveDirectoryLDS','SMTPMailRelay','SkypeForBusinessOnline','SkypeForBusinessOnPremises')]
        [string[]]$ServiceType #used only to filter list of available system identities and names
        ,
        [parameter()]
        [switch]$NoAutoImport
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
        Write-Verbose -Message "Using Service/System: $($serviceObject.Name)"
        $ServiceTypeDefinition = GetServiceTypeDefinition -ServiceType $ServiceObject.ServiceType -errorAction Stop
        Write-Verbose -Message "Using ServiceTypeDefinition: $($serviceTypeDefinition.Name)"
        $EndPointGroups = @(
            Write-Verbose -Message "Selecting an Endpoint"
            switch ($ServiceTypeDefinition.DefaultsToWellKnownEndPoint -and ($null -eq $EndPointIdentity -or (Test-IsNullOrWhiteSpace -String $EndPointIdentity)))
            {
                $true
                {
                    Write-Verbose -Message "Get Well Known Endpoint(s)."
                    Get-WellKnownEndPoint -ServiceObject $ServiceObject -ErrorAction Stop
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
                            if ($script:ImportedSessionModules.ContainsKey($ServiceObject.Identity))
                            {
                                $ImportedSessionModule = $script:ImportedSessionModules.$($ServiceObject.Identity)
                                try
                                {
                                    Remove-Module -Name $ImportedSessionModule.Name -ErrorAction Stop
                                }
                                catch
                                {
                                    
                                }
                            }
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
                            $NewPSSessionParams = Get-OneShellSystemEndpointPSSessionParameter -ServiceObject $ServiceObject -Endpoint $e -ErrorAction Stop
                            $NewPSSessionCmdlet = 'New-PSSession'
                            try
                            {
                                if ($null -ne $ServiceTypeDefinition.PSSessionCmdlet)
                                {
                                    $NewPSSessionCmdlet = $ServiceTypeDefinition.PSSessionCmdlet
                                }
                                $message = "Create PsSession using command $NewPSsessionCmdlet with name $($NewPSSessionParams.Name) for Service $($serviceObject.Name)"
                                Write-Log -Message $message -EntryType Attempting
                                $ServiceSession = Invoke-Command -ScriptBlock {& $NewPSSessionCmdlet @NewPSSessionParams}
                                Write-Log -Message $message -EntryType Succeeded
                                $PSSessionConnected = $true
                            }#end Try
                            catch
                            {
                                $myerror = $_
                                $PSSessionConnected = $false
                                Write-Log -Message $message -EntryType Failed -ErrorLog
                                Write-Log -Message $myerror.tostring() -ErrorLog
                            }#end Catch
                            #determine if the session needs to be initialized with imported modules, variables, etc. based on ServiceType
                            $Phase1InitializationCompleted = $(
                                if ($PSSessionConnected -eq $true)
                                {
                                    $message = "Perform Phase 1 Initilization of PSSession $($serviceSession.Name) for $($serviceObject.Name)"
                                    try
                                    {
                                        Write-Log -Message $message -EntryType Attempting
                                        Initialize-OneShellSystemPSSession -Phase Phase1_PreModuleImport -ServiceObject $ServiceObject -ServiceSession $ServiceSession -endpoint $e -ErrorAction Stop
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
                            $Phase2InitializationCompleted = $(
                                if ($Phase1InitializationCompleted -ne $false)
                                {
                                    try
                                    {
                                        $message = "Import Required Module(s) into PSSession $($serviceSession.Name) for $($serviceObject.Name)"
                                        Write-Log -Message $message -EntryType Attempting
                                        Import-ModuleInOneShellSystemPSSession -ServiceObject $ServiceObject -ServiceSession $ServiceSession -ErrorAction Stop
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
                            $Phase3InitializationCompleted = $(
                                if ($Phase2InitializationCompleted -ne $false)
                                {
                                    try
                                    {
                                        $message = "Perform Phase 3 Initilization of PSSession $($serviceSession.Name) for $($serviceObject.Name)"
                                        Write-Log -Message $message -EntryType Attempting
                                        Initialize-OneShellSystemPSSession -Phase Phase3 -ServiceObject $ServiceObject -ServiceSession $ServiceSession -endpoint $e -ErrorAction Stop
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
                            if (@($Phase1InitializationCompleted,$Phase2InitializationCompleted,$Phase3InitializationCompleted) -notcontains $false)
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
                            Write-Log -Message "Successfully Connected to $($ServiceObject.Name) with PSSession $($ServiceSession.Name)" -Verbose
                            $SessionManagementGroups = @(
                                if ($null -ne $ServiceObject.ServiceTypeAttributes -and $null -ne $ServiceObject.ServiceTypeAttributes.SessionManagementGroups)
                                {
                                    $ServiceObject.ServiceTypeAttributes.SessionManagementGroups
                                }
                                $ServiceObject.ServiceType
                            )
                            Update-SessionManagementGroups -ServiceSession $ServiceSession -ManagementGroups $SessionManagementGroups
                            if ($ServiceObject.AutoImport -eq $true -and $NoAutoImport -ne $true)
                            {
                                Import-OneShellSystem -ServiceObject $ServiceObject -ServiceSession $ServiceSession
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
function Import-ModuleInOneShellSystemPSSession
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
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        $ServiceTypeDefinition = GetServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
        $ModuleImportResults = @(
            if ($null -ne $ServiceTypeDefinition.PSSessionSettings.Initialization.Phase2_ModuleImport -and $ServiceTypeDefinition.PSSessionSettings.Initialization.Phase2_ModuleImport.count -ge 1) 
            {
                foreach ($m in $ServiceTypeDefinition.PSSessionSettings.Initialization.Phase2_ModuleImport)
                {
                    $ModuleName = $m.name
                    $ImportModuleParams = @{
                        Name = $ModuleName
                        ErrorAction = 'Stop'
                    }
                    switch ($m.type)
                    {
                        'PSSnapIn'
                        {
                            $ImportCommand = 'Add-PSSnapin'
                        }
                        default
                        {
                            $ImportCommand = 'Import-Module'
                        }
                    }
                    try
                    {
                        $message = "import required module $ModuleName into PSSession $($ServiceSession.name) for System $($serviceObject.Name)."
                        Write-Log -Message $message -EntryType Attempting
                        Invoke-Command -session $ServiceSession -ScriptBlock {&$using:ImportCommand @using:ImportModuleParams} -ErrorAction Stop
                        Write-Log -Message $message -EntryType Succeeded
                        $ModuleImported =  $true
                    }
                    catch
                    {
                        $myerror = $_
                        Write-Log -Message $message -ErrorLog -Verbose -EntryType Failed
                        Write-Log -Message $myerror.tostring() -ErrorLog
                        $ModuleImported = $false
                    }
                    Write-Output -InputObject $ModuleImported
                }
            }#end if
        )
        switch ($ModuleImportResults) 
        {
            {$_.count -eq 0}
            {Write-Output -InputObject $null}
            {$_ -contains $false}
            {Write-Output -InputObject $false}
            {$_ -notcontains $false -and $_ -contains $true}
            {Write-Output -InputObject $true}
        }
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
        ,
        [parameter(Mandatory)]
        [ValidateSet('Phase1_PreModuleImport','Phase3')]
        $Phase
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    $ServiceTypeDefinition = GetServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
    switch ($null -ne $ServiceTypeDefinition.PSSessionSettings.Initialization.$Phase -and ($ServiceTypeDefinition.PSSessionSettings.Initialization.$Phase).count -ge 1)
    {
        $true
        {
            $InitializationCommandsResults = @(
                foreach ($cmd in $ServiceTypeDefinition.PSSessionSettings.Initialization.$phase)
                {
                    $conditionResults = @(
                        foreach ($c in $cmd.conditions)
                        {
                            switch ($c.type)
                            {
                                'Local'
                                {
                                    $ScriptBlockToTest = [scriptblock]::Create($c.test)
                                    &$ScriptBlockToTest
                                }
                                'InPSSession'
                                {
                                    Invoke-Command -Session $serviceSession -ScriptBlock {& $($($using:c).test)}
                                }
                            }
                        }
                    )
                    switch ($conditionResults -notcontains $false)
                    {
                        $true
                        {
                            $CmdParams = @{
                                ErrorAction = 'Stop'
                            }
                            foreach ($p in $cmd.parameters)
                            {
                                $value = $(
                                    switch ($p.ValueType)
                                    {
                                        'Static'
                                        {$p.Value}
                                        'ScriptBlock'
                                        {
                                            $ValueGeneratingScriptBlock = [scriptblock]::Create($p.Value)
                                            &$ValueGeneratingScriptBlock
                                        }
                                    }
                                )
                                $CmdParams.$($p.name) = $value
                            }
                            Try
                            {
                                Invoke-Command -Session $serviceSession -ScriptBlock {& $(($Using:cmd).command) @using:CmdParams} -ErrorAction Stop | Out-Null
                                Write-Output -InputObject $true
                            }#end Try
                            Catch
                            {
                                $myerror = $_
                                Write-Log -Message "Initialization Phase $Phase failed." -ErrorLog -Verbose -EntryType Failed
                                Write-Log -Message $myerror.tostring() -ErrorLog
                                Write-Output -inputObject $false
                            }
                        }
                        $false
                        {
                            Write-Output -InputObject $null
                        }
                    }
                }
            )
            #output True or false depending on results above
            $InitializationCommandsResults -notcontains $false
        }
        $false
        {
            Write-Output -InputObject $null
        }
    }#end Switch
}
#end function Initialize-OneShellSystemPSSession
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
Function Update-SessionManagementGroups
    {
        [cmdletbinding()]
        Param
        (
            [parameter(Mandatory=$true)]
            $ServiceSession
            ,[parameter(Mandatory=$true)]
            [string[]]$ManagementGroups
        )
        foreach ($MG in $ManagementGroups)
        {
            $SessionGroup = $MG + '_PSSessions'
            #Check if the Session Group already exists
            if (Test-Path -Path "variable:\$SessionGroup") 
            {
                #since the session group already exists, add the session to it if it is not already present
                $ExistingSessions = Get-Variable -Name $SessionGroup -Scope Global -ValueOnly
                $ExistingSessionNames = $existingSessions | Select-Object -ExpandProperty Name
                if ($ServiceSession.name -in $ExistingSessionNames) 
                {
                    $NewValue = @($ExistingSessions | Where-Object -FilterScript {$_.Name -ne $ServiceSession.Name})
                    $NewValue += $ServiceSession
                    Set-Variable -Name $SessionGroup -Value $NewValue -Scope Global
                } else {
                    $NewValue = $ExistingSessions + $ServiceSession
                    Set-Variable -Name $SessionGroup -Value $NewValue -Scope Global
                }
            }
            else #since the session group does not exist, create it and add the session to it
            {
                New-Variable -Name $SessionGroup -Value @($ServiceSession) -Scope Global
            }# end else
        }# end foreach
    }
#end function Update-SessionManagementGroups
Function Import-OneShellSystem
{
    [CmdletBinding(DefaultParameterSetName = 'ServiceObjectAndSession')]
    param
    (
        [parameter(ParameterSetName = 'ServiceObjectAndSession')]
        [psobject]$ServiceObject
        ,
        [parameter(ParameterSetName = 'ServiceObjectAndSession')]
        [System.Management.Automation.Runspaces.PSSession]$ServiceSession
        ,
        [parameter(ParameterSetName = 'Identity')]
        [string]$Identity
        ,
        [parameter()]
        [string]$CommandPrefix
    )
    switch($PSCmdlet.ParameterSetName)
    {
        'ServiceObjectAndSession'
        {

        }
        'Identity'
        {
            #here we need to get the ServiceObject and the Session Object
        }
    } #end switch
    $ImportPSSessionParams = @{
        ErrorAction = 'Stop'
        Session = $ServiceSession
        WarningAction = 'SilentlyContinue'
    }
    $ServiceTypeDefinition = GetServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
    switch ($ServiceTypeDefinition.PSSessionSettings.Initialization.Phase2_ModuleImport.count)
    {
        $null
        {}
        {$_ -ge 1}
        {
            $ImportPSSessionParams.Module = $ServiceTypeDefinition.PSSessionSettings.Initialization.Phase2_ModuleImport.Name
        }
    }
    #Setup for CommandPrefix
    if ($PSBoundParameters.ContainsKey('CommandPrefix'))
    {
        $CommandPrefixExists = $true
    }
    else
    {
        $CommandPrefix = Find-CommandPrefixToUse -ServiceObject $ServiceObject
        $CommandPrefixExists = Test-IsNotNullOrWhiteSpace -String $CommandPrefix
    }
    #Imported Session Module Cleanup and Tracking
    if (-not (Test-Path -Path variable:Script:ImportedSessionModules))
    {
        New-Variable -Name 'ImportedSessionModules' -Value @{} -Description 'Modules Imported From OneShell Sessions' -Scope Script
    }
    if ($script:ImportedSessionModules.ContainsKey($ServiceObject.Identity))
    {
        $ImportedSessionModule = $Script:ImportedSessionModules.$($ServiceObject.Identity)
        if ($null -ne (Get-Module -Name $ImportedSessionModule.Name))
        {
            Remove-Module -Name $ImportedSessionModule.Name -ErrorAction Stop
        }
    }

    $message = "Import OneShell System $($ServiceObject.Name) Session $($ServiceSession.Name) into Current Session"
    if ($CommandPrefixExists -eq $true)
    {
        $ImportPSSessionParams.Prefix = $CommandPrefix
        $message = $message + " with Command Prefix $CommandPrefix"
    }
    $ImportModuleParams = @{
        ErrorAction = 'Stop'
        WarningAction = 'SilentlyContinue'
        Passthru = $true
        Global = $true
        ModuleInfo = Import-PSSession @ImportPSSessionParams
    }
    if ($CommandPrefixExists -eq $true)
    {
        $ImportModuleParams.Prefix = $CommandPrefix
    }
    Write-Log -Message $message -EntryType Attempting
    $ImportedModule  = Import-Module @ImportModuleParams
    Write-Log -Message $message -EntryType Succeeded -Verbose

    $script:ImportedSessionModules.$($ServiceObject.Identity) = [PSCustomObject]@{Identity = $serviceobject.Identity; CommandPrefix = $CommandPrefix; Name = $ImportedModule.name; ServiceType = $ServiceObject.ServiceType}
}
#################################################
# Need to update
#################################################
