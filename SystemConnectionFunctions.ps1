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
        [ValidateSet('Admin', 'MRS')]
        $EndPointType = 'Admin'
    )
    $FilteredEndpoints = @(
        switch ($null -eq $EndPointIdentity)
        {
            $false
            {
                #Write-verbose -Message "Endpoint Identity was specified.  Return only that endpoint."
                if ($EndPointIdentity -notin $ServiceObject.EndPoints.Identity)
                {throw("Invalid EndPoint Identity $EndPointIdentity was specified. System $($ServiceObject.Identity) has no such endpoint.")}
                else
                {
                    $ServiceObject.EndPoints | Where-Object -FilterScript {$_.Identity -eq $EndPointIdentity}
                }
            }
            $true
            {
                #Write-verbose -message "Endpoint Identity was not specified.  Return all applicable endpoints, with preferred first if specified."
                switch ($null -eq $ServiceObject.PreferredEndpoint)
                {
                    $false
                    {
                        #Write-Verbose -Message "Preferred Endpoint is specified."
                        $PreEndpoints = @(
                            switch ($null -eq $EndPointGroup)
                            {
                                $true
                                {
                                    #Write-Verbose -message 'EndPointGroup was not specified'
                                    $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType} | Sort-Object -Property Precedence
                                }#end false
                                $false
                                {
                                    #Write-Verbose -message 'EndPointGroup was specified'
                                    $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType -and $_.EndPointGroup -eq $EndPointGroup} | Sort-Object -Property Precedence
                                }#end true
                            }#end switch
                        )
                        $PreEndpoints | Where-Object {$_.Identity -eq $ServiceObject.PreferredEndpoint} | ForEach-Object {$_.Precedence = -1}
                        $PreEndpoints
                    }#end false
                    $true
                    {
                        #Write-Verbose -Message "Preferred Endpoint is not specified."
                        switch ($null -eq $EndPointGroup)
                        {
                            $true
                            {
                                #Write-Verbose -message 'EndPointGroup was not specified'
                                $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType} | Sort-Object -Property Precedence
                            }#end false
                            #EndPointGroup was specified
                            $false
                            {
                                #Write-Verbose -message 'EndPointGroup was specified'
                                $ServiceObject.EndPoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType -and $_.EndPointGroup -eq $EndPointGroup} | Sort-Object -Property Precedence
                            }#end true
                        }#end switch
                    }#end true
                }#end switch
            }#end $true
        }#end switch
    )
    $GroupedEndpoints = @($FilteredEndpoints | Group-Object -Property Precedence)
    $GroupedEndpoints
}
#end function Find-EndPointToUse
function Get-WellKnownEndPoint
{
    [cmdletbinding()]
    param
    (
        $ServiceObject
    )
    $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
    @(
        [PSCustomObject]@{
            Identity               = $ServiceObject.ServiceType + '-WellKnownEndPoint'
            AddressType            = 'URL'
            Address                = $ServiceTypeDefinition.WellKnownEndPointURI
            ServicePort            = $null
            UseTLS                 = $false
            ProxyEnabled           = $ServiceObject.Defaults.ProxyEnabled
            CommandPrefix          = $ServiceObject.Defaults.CommandPrefix
            AuthenticationRequired = $true
            AuthMethod             = $ServiceTypeDefinition.WellKnownEndPointAuthMethod
            EndPointGroup          = $null
            EndPointType           = 'Admin'
            ServiceTypeAttributes  = $null
            ServiceType            = $ServiceObject.ServiceType
            Precedence             = -1
            PSRemoting             = $true
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
        if ($null -ne $ServiceObject.PreferredPrefix) #this allows a blank string to be the PreferredPrefix . . . which is what an user may want
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
    $CommandPrefix
}
#end function Find-CommandPrefixToUse
function Get-OneShellSystem
{
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(ParameterSetName = 'Identity')]
        [string[]]$Identity
        ,
        [parameter(ParameterSetName = 'ServiceType')]
        [string[]]$ServiceType
    )
    begin
    {
        if ($null -eq $script:CurrentUserProfile)
        {throw('No OneShell User Profile is active.  Use function Use-OneShellUserProfile to load an User Profile.')}
    }
    Process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'Identity'
            {
                if ($null -eq $Identity)
                {
                    $script:CurrentSystems
                }
                foreach ($i in $Identity)
                {
                    $script:CurrentSystems | Where-Object -FilterScript {$_.Identity -eq $i -or $_.name -eq $i}
                }
            }
            'ServiceType'
            {
                $script:CurrentSystems | Where-Object -FilterScript {$_.ServiceType -in $ServiceType}
            }
        }
    }
}
#end function Get-OneShellSystem
function GetOneShellSystemPSSession
{
    [cmdletbinding()]
    param
    (
        $ServiceObject
    )
    [string]$SessionNameWildcard = $($ServiceObject.Identity) + '*'
    $message = "Run Get-PSSession for name like $SessionNameWildcard"
    try
    {
        #Write-OneShellLog -Message $message -EntryType Attempting
        $ServiceSession = @(Get-PSSession -Name $SessionNameWildcard -ErrorAction Stop)
        #Write-OneShellLog -Message $message -EntryType Succeeded
    }
    catch
    {
        $myerror = $_
        #Write-OneShellLog -Message $message -EntryType Failed
        #Write-OneShellLog -Message $myerror.tostring() -ErrorLog
    }
    $ServiceSession
}
#end function GetOneShellSystemPSSession
function Get-OneShellSystemPSSession
{
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(Mandatory, ParameterSetName = 'ServiceObject', ValueFromPipeline)]
        $serviceObject
        ,
        [parameter(Mandatory, ParameterSetName = 'Identity', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string[]]$Identity

    )
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
    process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'Identity'
            {
                foreach ($i in $Identity)
                {
                    $ServiceObject = $script:CurrentSystems | Where-Object -FilterScript {$_.Identity -eq $i -or $_.name -eq $i}
                    GetOneShellSystemPSSession -ServiceObject $ServiceObject
                }
            }
            'ServiceObject'
            {
                GetOneShellSystemPSSession -ServiceObject $ServiceObject
            }
        }
    }
}
#end function Get-OneShellSystemPSSession
function Test-OneShellSystemConnection
{
    [cmdletbinding()]
    param
    (
        $serviceObject
    )
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
    process
    {
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType -ErrorAction Stop
        $UsePSRemoting = $($serviceObject.UsePSRemoting;$serviceObject.defaults.UsePSRemoting) | Where-Object -FilterScript {$null -ne $_} | Select-Object -First 1
        switch ($UsePSRemoting)
        {
            #Since UsePSRemoting is true for this system, look for an existing PSSession
            $true
            {
                try
                {
                    Write-Verbose -Message "Getting Service PSSession for $($serviceObject.Name)."
                    $ServiceSession = @(Get-OneShellSystemPSSession -serviceObject $serviceObject -ErrorAction Stop)
                }
                catch
                {
                    Write-OneShellLog -Message $_.tostring() -ErrorLog
                }
                switch ($ServiceSession.Count)
                {
                    1
                    {
                        $ServiceSession = $ServiceSession[0]
                        $message = "Found PSSession $($ServiceSession.name) for service $($serviceObject.Name)."
                        Write-OneShellLog -Message $message -EntryType Notification
                        #Test the Session functionality
                        if ($ServiceSession.state -ne 'Opened')
                        {
                            Write-OneShellLog -Message "PSSession $($ServiceSession.name) for service $($serviceObject.Name) is not in state 'Opened'." -EntryType Notification
                            #no existing PSSession found so we aren't connected to this system. Output $false
                            return $false

                        }
                        else
                        {
                            Write-OneShellLog -Message "PSSession $($ServiceSession.name) for service $($serviceObject.Name) is in state 'Opened'." -EntryType Notification
                        }
                    }
                    0
                    {
                        $message = "Found No PSSession for service $($serviceObject.Name)."
                        Write-OneShellLog -Message $message -EntryType Notification
                        return $false
                    }
                    Default
                    {
                        $message = "Found multiple PSSessions $($ServiceSession.name -join ',') for service $($serviceObject.Name). Please delete one or more sessions then try again."
                        Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                        return $false
                    }
                }
            }
            $false
            {
                #nothing to do here for DirectConnect systems
            }
        }
        if ($null -ne $ServiceTypeDefinition.ConnectionTestCommand.command)
        {
            $TestCommand = $ServiceTypeDefinition.ConnectionTestCommand.Command
            Write-Verbose -message "Test Command is $TestCommand"
            $TestCommandParams = Get-ParameterSplatFromDefinition -ParameterDefinition $ServiceTypeDefinition.ConnectionTestCommand.Parameters -ValueForErrorAction 'Stop'
            Write-OneShellLog -Message "Found Service Type Command to use for $($serviceObject.ServiceType): $testCommand" -EntryType Notification
            $PreTestCommands = @(
                if ($null -ne $ServiceTypeDefinition.ConnectionTestCommand.PreTestCommands -and $ServiceTypeDefinition.ConnectionTestCommand.PreTestCommands.count -ge 1)
                {
                    foreach ($ptc in $ServiceTypeDefinition.ConnectionTestCommand.PreTestCommands)
                    {
                        [pscustomobject]@{
                            Command = $ptc.Command
                            Parameters = Get-ParameterSplatFromDefinition -ParameterDefinition $ptc.parameters -ValueForErrorAction 'Stop'
                        }
                    }
                }
            )
            $PostTestCommands = @(
                if ($null -ne $ServiceTypeDefinition.ConnectionTestCommand.PostTestCommands -and $ServiceTypeDefinition.ConnectionTestCommand.PostTestCommands.count -ge 1)
                {
                    foreach ($ptc in $ServiceTypeDefinition.ConnectionTestCommand.PostTestCommands)
                    {
                        [pscustomobject]@{
                            Command = $ptc.Command
                            Parameters = Get-ParameterSplatFromDefinition -ParameterDefinition $ptc.parameters -ValueForErrorAction 'Stop'
                        }
                    }
                }
            )
            switch ($UsePSRemoting)
            {
                #determine whether to run the ConnectionTestCommand in Session or directly
                $true
                {
                    $message = "Run $TestCommand in $($serviceSession.name) PSSession"
                    try
                    {
                        Write-OneShellLog -Message $message -EntryType Attempting
                        if ($false -eq $ServiceTypeDefinition.PSRemotingSettings.ExpectConstrainedSession)
                        {
                            Invoke-Command -Session $ServiceSession -ScriptBlock {$Original_PSModuleAutoLoadingPreference = $PSModuleAutoLoadingPreference; $PSModuleAutoLoadingPreference = 'none'}
                        }
                        if ($PreTestCommands.Count -ge 1)
                        {
                            foreach ($ptc in $PreTestCommands)
                            {
                                $ptcommand = $ptc.Command
                                $ptcparams = $ptc.Parameters
                                Invoke-Command -Session $ServiceSession -ScriptBlock {&$Using:ptcommand @using:ptcparams} -ErrorAction Stop
                            }
                        }
                        $ConnectionTestCommandOutput = Invoke-Command -Session $ServiceSession -ScriptBlock {&$Using:TestCommand @using:TestCommandParams} -ErrorAction Stop
                        if ($false -eq $ServiceTypeDefinition.PSRemotingSettings.ExpectConstrainedSession)
                        {
                            Invoke-Command -Session $serviceSession -ScriptBlock {$PSModuleAutoLoadingPreference = $Original_PSModuleAutoLoadingPreference}
                        }
                        if ($PostTestCommands.Count -ge 1)
                        {
                            foreach ($ptc in $PostTestCommands)
                            {
                                $ptcommand = $ptc.Command
                                $ptcparams = $ptc.Parameters
                                Invoke-Command -Session $ServiceSession -ScriptBlock {&$Using:ptcommand @using:ptcparams} -ErrorAction Stop
                            }
                        }
                        Write-OneShellLog -Message $message -EntryType Succeeded
                    }
                    catch
                    {
                        $myerror = $_
                        if ($false -eq $ServiceTypeDefinition.PSRemotingSettings.ExpectConstrainedSession)
                        {
                            Invoke-Command -Session $serviceSession -ScriptBlock {$PSModuleAutoLoadingPreference = $Original_PSModuleAutoLoadingPreference}
                        }
                        if ($PostTestCommands.Count -ge 1)
                        {
                            foreach ($ptc in $PostTestCommands)
                            {
                                $ptcommand = $ptc.Command
                                $ptcparams = $ptc.Parameters
                                Invoke-Command -Session $ServiceSession -ScriptBlock {&$Using:ptcommand @using:ptcparams} -ErrorAction Stop
                            }
                        }
                        Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                        Write-OneShellLog -message $myerror.tostring() -ErrorLog
                        return $false
                    }
                }
                $false
                {
                    $message = "Run $TestCommand for System $($ServiceObject.Name)."
                    try
                    {
                        Write-OneShellLog -Message $message -EntryType Attempting
                        $Global:Original_PSModuleAutoLoadingPreference = $Global:PSModuleAutoLoadingPreference
                        $Global:PSModuleAutoLoadingPreference = 'none'
                        if ($PreTestCommands.Count -ge 1)
                        {
                            foreach ($ptc in $PreTestCommands)
                            {
                                $ptcommand = $ptc.Command
                                $ptcparams = $ptc.Parameters
                                Invoke-Command -ScriptBlock {&$ptcommand @ptcparams} -ErrorAction Stop
                            }
                        }
                        $ConnectionTestCommandOutput = Invoke-Command -ScriptBlock {&$TestCommand @TestCommandParams} -ErrorAction Stop
                        $Global:PSModuleAutoLoadingPreference = $Global:Original_PSModuleAutoLoadingPreference
                        if ($PostTestCommands.Count -ge 1)
                        {
                            foreach ($ptc in $PostTestCommands)
                            {
                                $ptcommand = $ptc.Command
                                $ptcparams = $ptc.Parameters
                                Invoke-Command -ScriptBlock {&$ptcommand @ptcparams} -ErrorAction Stop
                            }
                        }
                        Write-OneShellLog -Message $message -EntryType Succeeded
                    }
                    catch
                    {
                        $myerror = $_
                        $Global:PSModuleAutoLoadingPreference = $Global:Original_PSModuleAutoLoadingPreference
                        if ($PostTestCommands.Count -ge 1)
                        {
                            foreach ($ptc in $PostTestCommands)
                            {
                                $ptcommand = $ptc.Command
                                $ptcparams = $ptc.Parameters
                                Invoke-Command -ScriptBlock {&$ptcommand @ptcparams} -ErrorAction Stop
                            }
                        }
                        Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                        Write-OneShellLog -message $myerror.tostring() -ErrorLog
                        return $false
                    }
                }
            }
            if ($null -ne $ConnectionTestCommandOutput)
            {
                if ($null -ne $ServiceTypeDefinition.ConnectionTestCommand.Validation -and $ServiceTypeDefinition.ConnectionTestCommand.Validation.Count -ge 1)
                {
                    $Validations = @(
                        foreach ($v in $ServiceTypeDefinition.ConnectionTestCommand.Validation)
                        {
                            $Value = $(
                                switch ($v.ValueType)
                                {
                                    'Static'
                                    {$v.Value}
                                    'ScriptBlock'
                                    {
                                        $ValueGeneratingScriptBlock = [scriptblock]::Create($v.Value)
                                        &$ValueGeneratingScriptBlock
                                    }
                                }
                            )
                            if ($null -ne $value)
                            {
                                $ValueToTest = $ConnectionTestCommandOutput.$($v.Name)
                                Write-OneShellLog -Message "Testing Expression: '$ValueToTest' $($v.Operator) '$Value'"
                                Invoke-Expression -Command $("'$ValueToTest' $($v.Operator) '$Value'")
                            }
                            else {
                                $false
                            }
                        }
                    )
                    if ($Validations -contains $false) {return $false} else {return $true}
                }
                else
                {
                    #No Validation is specified and ConnectionTestCommandOutput is not null so we pass the connection test and output $true
                    return $true
                }
            }
            else
            {
                #$ConnectionTestCommandOutput was NULL so test fails and output $false
                return $false
            }
        }#end if
        else
        {
            #Write-OneShellLog "No Service Type Command to use for Service Testing is specified for ServiceType $($ServiceObject.ServiceType)."
            return $true
        }
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
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
        $NewPSSessionParams = @{
            ErrorAction = 'Stop'
            Name        = $($ServiceObject.Identity + '%' + $Endpoint.Identity)
        }
        if ($null -ne $ServiceObject.Credentials.PSSession)
        {
            $NewPSSessionParams.Credential = $ServiceObject.Credentials.PSSession
        }
        #Apply Service Type Defaults
        foreach ($p in $ServiceTypeDefinition.PSRemotingSettings.ConnectCommand.Parameters)
        {
            $Value = $(
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
            $NewPSSessionParams.$($p.Name) = $Value
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
        $NewPSSessionParams
    }#end end
}
#end function Get-EndPointPSSessionParameter
Function Connect-OneShellSystem
{
    [cmdletbinding(DefaultParameterSetName = 'Default')]
    Param
    (
        [parameter(Mandatory, ParameterSetName = 'Identity', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [parameter(ParameterSetName = 'Reconnect', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string[]]$Identity
        ,
        [parameter(ParameterSetName = 'EndPointIdentity')]
        [ValidateNotNullOrEmpty()]
        [string]$EndPointIdentity #An endpoint identity from existing endpoints configure for this system. Overrides the otherwise specified endpoint.
        ,
        [parameter(ParameterSetName = 'EndPointGroup')]
        [ValidateNotNullOrEmpty()]
        [string]$EndPointGroup #An endpoint identity from existing endpoints configure for this system. Overrides the otherwise specified endpoint.
        ,
        [parameter()]
        [ValidateScript( {($_.length -ge 2 -and $_.length -le 5) -or [string]::isnullorempty($_)})]
        [string]$CommandPrefix #Overrides the otherwise specified command prefix.
        ,
        [parameter()]
        [string[]]$ServiceType #used only to filter list of available system identities and names
        ,
        [parameter()]
        [switch]$NoAutoImport
        ,
        [parameter(Mandatory, ParameterSetName = 'Reconnect')]
        [switch]$Reconnect
    )
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Reconnect')
        {
            if (-not $PSBoundParameters.ContainsKey('Identity'))
            {
                $Identity = @(Get-Pssession | Where-Object {$_.State -eq 'Broken'} | ForEach-Object {$_.name.split('%')[0]} | Where-Object {$_ -in $script:CurrentSystems.Identity})
            }
        }
        foreach ($id in $Identity)
        {
            $ServiceObject = $script:CurrentSystems  | Where-Object -FilterScript {$_.name -eq $id -or $_.Identity -eq $id}
            #Write-Verbose -Message "Using Service/System: $($serviceObject.Name)"
            $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType -errorAction Stop
            #Write-Verbose -Message "Using ServiceTypeDefinition: $($serviceTypeDefinition.Name)"
            #Test for an existing connection
            $ExistingConnectionIsValid = Test-OneShellSystemConnection -serviceObject $ServiceObject -ErrorAction Stop
            $UsePSRemoting = $($serviceObject.UsePSRemoting;$serviceObject.defaults.UsePSRemoting) | Where-Object -FilterScript {$null -ne $_} | Select-Object -First 1
            switch ($UsePSRemoting)
            {
                $true
                {
                    #check results of the test for an existing session
                    if ($ExistingConnectionIsValid)
                    {
                        $ExistingSession = Get-OneShellSystemPSSession -serviceObject $ServiceObject -ErrorAction Stop
                        #Write-OneShellLog -Message "Existing Session $($ExistingSession.name) for Service $($serviceObject.Name) is valid."
                        #nothing further to do since existing connection is valid
                        #add logic for preferred endpoint/specified endpoint checking?
                    }#end if
                    else
                    {
                        $ExistingSession = Get-OneShellSystemPSSession -serviceObject $ServiceObject -ErrorAction Stop
                        if ($null -ne $ExistingSession)
                        {
                            $message = "Remove Existing Invalid Session $($ExistingSession.name) for Service $($serviceObject.name)."
                            try
                            {
                                if ($script:ImportedSessionModules.ContainsKey($ServiceObject.Identity))
                                {
                                    $ImportedSessionModule = $script:ImportedSessionModules.$($ServiceObject.Identity)
                                    $message = "Remove Previously Imported Session Module $ImportedSessionModule for System $($ServiceObject.Identity)"
                                    try
                                    {
                                        Write-OneShellLog -Message $message -EntryType Attempting
                                        Remove-Module -Name $ImportedSessionModule.Name -ErrorAction Stop
                                        Write-OneShellLog -Message $message -EntryType Succeeded
                                    }
                                    catch
                                    {
                                        $myerror = $_
                                        Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                                        Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                                    }
                                }

                                Try
                                {
                                    Write-OneShellLog -Message $message -EntryType Attempting
                                    Remove-PSSession -Session $ExistingSession -ErrorAction Stop
                                    Write-OneShellLog -Message $message -EntryType Succeeded
                                }
                                Catch
                                {
                                    $myerror = $_
                                    Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                                    Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                                }
                            }
                            catch
                            {
                                $myerror = $_
                                Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                                Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                                throw ($myerror)
                            }
                        }#end if
                        Write-OneShellLog -Message "No Existing Valid Session found for $($ServiceObject.name)" -EntryType Notification
                        #create and test the new session
                        $EndPointGroups = @(
                            #Write-Verbose -Message "Selecting an Endpoint"
                            switch ($ServiceTypeDefinition.DefaultsToWellKnownEndPoint -and ($null -eq $EndPointIdentity -or (Test-IsNullOrWhiteSpace -String $EndPointIdentity)))
                            {
                                $true
                                {
                                    #Write-Verbose -Message "Get Well Known Endpoint(s)."
                                    Get-WellKnownEndPoint -ServiceObject $ServiceObject -ErrorAction Stop
                                }
                                Default
                                {
                                    $FindEndPointToUseParams = @{
                                        ErrorAction   = 'Stop'
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
                                        Default
                                        {}
                                    }
                                    Find-EndPointToUse @FindEndPointToUseParams
                                }
                            }
                        )
                        if ($null -eq $EndPointGroups -or $EndPointGroups.Count -eq 0)
                        {throw("No endpoint found for system $($serviceObject.Name), $($serviceObject.Identity)")}
                        $ConnectionReady = $false #we switch this to true when a session is connected and initialized with required modules and settings
                        #Work through the endpoint groups to try connecting in order of precedence
                        for ($i = 0; $i -lt $EndPointGroups.count -and $ConnectionReady -eq $false; $i++)
                        {
                            #get the first endpoint group and randomly order them, then work through them one at a time until successfully connected
                            $g = $endPointGroups[$i]
                            $endpoints = @($g.group | Sort-Object -Property {Get-Random})
                            for ($ii = 0; $ii -lt $endpoints.Count -and $ConnectionReady -eq $false; $ii++)
                            {
                                $e = $endpoints[$ii]
                                $NewPSSessionParams = Get-OneShellSystemEndpointPSSessionParameter -ServiceObject $ServiceObject -Endpoint $e -ErrorAction Stop
                                $NewPSSessionCmdlet = 'New-PSSession'
                                try
                                {
                                    if ($null -ne $ServiceTypeDefinition.PSRemotingSettings.ConnectCommand.Command)
                                    {
                                        $NewPSSessionCmdlet = $ServiceTypeDefinition.PSRemotingSettings.ConnectCommand.Command
                                    }
                                    $message = "Create PsSession using command $NewPSsessionCmdlet with name $($NewPSSessionParams.Name) for Service $($serviceObject.Name)"
                                    Write-OneShellLog -Message $message -EntryType Attempting
                                    $ServiceSession = Invoke-Command -ScriptBlock {& $NewPSSessionCmdlet @NewPSSessionParams}
                                    Write-OneShellLog -Message $message -EntryType Succeeded
                                    $PSSessionConnected = $true
                                }#end Try
                                catch
                                {
                                    $myerror = $_
                                    $PSSessionConnected = $false
                                    Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                                    Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                                }#end Catch
                                #determine if the session needs to be initialized with imported modules, variables, etc. based on ServiceType
                                $Phase1InitializationCompleted = $(
                                    if ($PSSessionConnected -eq $true)
                                    {
                                        $message = "Perform Phase 1 Initilization of PSSession $($serviceSession.Name) for $($serviceObject.Name)"
                                        try
                                        {
                                            Write-OneShellLog -Message $message -EntryType Attempting
                                            Initialize-OneShellSystemPSSession -Phase Phase1_PreModuleImport -ServiceObject $ServiceObject -ServiceSession $ServiceSession -endpoint $e -ErrorAction Stop -UsePSRemoting $UsePSRemoting
                                            Write-OneShellLog -Message $message -EntryType Succeeded
                                        }
                                        catch
                                        {
                                            $myerror = $_
                                            Write-OneShellLog -Message $message -EntryType Failed
                                            Write-OneShellLog -Message $myerror.tostring() -ErrorLog
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
                                            Write-OneShellLog -Message $message -EntryType Attempting
                                            Import-ModuleInOneShellSystemPSSession -ServiceObject $ServiceObject -ServiceSession $ServiceSession -ErrorAction Stop -UsePSRemoting $UsePSRemoting
                                            Write-OneShellLog -Message $message -EntryType Succeeded
                                        }
                                        catch
                                        {
                                            $myerror = $_
                                            Write-OneShellLog -Message $message -EntryType Failed
                                            Write-OneShellLog -Message $myerror.tostring() -ErrorLog
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
                                            Write-OneShellLog -Message $message -EntryType Attempting
                                            Initialize-OneShellSystemPSSession -Phase Phase3 -ServiceObject $ServiceObject -ServiceSession $ServiceSession -endpoint $e -ErrorAction Stop -UsePSRemoting $UsePSRemoting
                                            Write-OneShellLog -Message $message -EntryType Succeeded
                                        }
                                        catch
                                        {
                                            $myerror = $_
                                            Write-OneShellLog -Message $message -EntryType Failed
                                            Write-OneShellLog -Message $myerror.tostring() -ErrorLog
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
                                if (@($Phase1InitializationCompleted, $Phase2InitializationCompleted, $Phase3InitializationCompleted) -notcontains $false)
                                {
                                    Write-OneShellLog -Message $message -EntryType Succeeded
                                    if ($(Test-OneShellSystemConnection -serviceObject $ServiceObject))
                                    {
                                        $ConnectionReady = $true
                                    }
                                    else
                                    {
                                        Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                                        if ($null -ne $ServiceSession)
                                        {
                                            Remove-PSSession -Session $ServiceSession -ErrorAction Stop
                                        }
                                    }
                                }
                                else
                                {
                                    Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
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
                                Write-OneShellLog -Message "Failed to Connect to $($ServiceObject.Name). Review the errors and resolve them to connect." -ErrorLog -Verbose
                            }
                            $true
                            {
                                Write-OneShellLog -Message "Successfully Connected to $($ServiceObject.Name) with PSSession $($ServiceSession.Name)" -Verbose
                                $SessionManagementGroups = @(
                                    if ($null -ne $ServiceObject.ServiceTypeAttributes -and $null -ne $ServiceObject.ServiceTypeAttributes.SessionManagementGroups)
                                    {
                                        $ServiceObject.ServiceTypeAttributes.SessionManagementGroups
                                    }
                                    $ServiceObject.ServiceType
                                )
                                Update-SessionManagementGroup -ServiceSession $ServiceSession -ManagementGroups $SessionManagementGroups
                                if ($ServiceObject.AutoImport -eq $true -and $NoAutoImport -ne $true)
                                {
                                    $ImportOneShellSystemPSSessionParams = @{
                                        ErrorAction    = 'Stop'
                                        ServiceSession = $ServiceSession
                                        ServiceObject  = $ServiceObject
                                    }
                                    if ($PSBoundParameters.ContainsKey('CommandPrefix'))
                                    {
                                        $ImportOneShellSystemPSSessionParams.CommandPrefix = $CommandPrefix
                                    }
                                    Import-OneShellSystemPSSession @ImportOneShellSystemPSSessionParams
                                }
                            }
                        }
                    }
                }#end $true
                $false #Not using PSRemoting
                {
                    if ($false -eq $ExistingConnectionIsValid)
                    {
                        $ConnectionReady = $false #we switch this to true when a system is connected and initialized with required modules and settings
                        $Phase1InitializationCompleted = $(
                                $message = "Perform Phase 1 Initilization of Local Session for $($serviceObject.Name)"
                                try
                                {
                                    Write-OneShellLog -Message $message -EntryType Attempting
                                    Initialize-OneShellSystemPSSession -Phase Phase1_PreModuleImport -ServiceObject $ServiceObject -ErrorAction Stop -UsePSRemoting $UsePSRemoting
                                    Write-OneShellLog -Message $message -EntryType Succeeded
                                }
                                catch
                                {
                                    $myerror = $_
                                    Write-OneShellLog -Message $message -EntryType Failed
                                    Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                                    $false
                                }
                        )
                        $Phase2InitializationCompleted = $(
                            if ($Phase1InitializationCompleted -ne $false)
                            {
                                try
                                {
                                    $message = "Import Required Module(s) into Local Session for $($serviceObject.Name)"
                                    Write-OneShellLog -Message $message -EntryType Attempting
                                    Import-ModuleInOneShellSystemPSSession -ServiceObject $ServiceObject  -ErrorAction Stop -UsePSRemoting $UsePSRemoting
                                    Write-OneShellLog -Message $message -EntryType Succeeded
                                }
                                catch
                                {
                                    $myerror = $_
                                    Write-OneShellLog -Message $message -EntryType Failed
                                    Write-OneShellLog -Message $myerror.tostring() -ErrorLog
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
                                    $message = "Perform Phase 3 Initilization of Local Session for $($serviceObject.Name)"
                                    Write-OneShellLog -Message $message -EntryType Attempting
                                    Initialize-OneShellSystemPSSession -Phase Phase3 -ServiceObject $ServiceObject -ErrorAction Stop -UsePSRemoting $UsePSRemoting
                                    Write-OneShellLog -Message $message -EntryType Succeeded
                                }
                                catch
                                {
                                    $myerror = $_
                                    Write-OneShellLog -Message $message -EntryType Failed
                                    Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                                    $false
                                }
                                #determine if the session needs further initialization
                            }#end if
                            else
                            {
                                $false
                            }
                        )
                        $message = "Connection and Initialization of Local Session for $($serviceobject.name)"
                        if (@($Phase1InitializationCompleted, $Phase2InitializationCompleted, $Phase3InitializationCompleted) -notcontains $false)
                        {
                            Write-OneShellLog -Message $message -EntryType Succeeded
                            if ($(Test-OneShellSystemConnection -serviceObject $ServiceObject))
                            {
                                $ConnectionReady = $true
                            }
                        }
                        else
                        {
                            Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                            #Remove Module(s)?
                        }
                    }
                }#end $false
            }#end Switch
        }#end foreach i in Identity
    }#end Process
}
#end function Connect-OneShellSystem
function Import-ModuleInOneShellSystemPSSession
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        $ServiceObject
        ,
        [parameter()]
        $ServiceSession
        ,
        [parameter(Mandatory)]
        [bool]$UsePSRemoting
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
    $serviceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
    switch ($UsePSRemoting)
    {
        $true
        {
            $Phase2Modules = $serviceTypeDefinition.PSRemotingSettings.SessionInitialization.Phase2_ModuleImport
        }
        $false
        {
            $Phase2Modules = $serviceTypeDefinition.DirectConnectSettings.SessionInitialization.Phase2_ModuleImport
        }
    }
    $ModuleImportResults = @(
        if ($null -ne $Phase2Modules -and $Phase2Modules.count -ge 1)
        {
            foreach ($m in $Phase2Modules)
            {
                $ModuleName = $m.name
                $ImportModuleParams = @{
                    Name        = $ModuleName
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
                    switch ($UsePSRemoting)
                    {
                        $true
                        {
                            $message = "import required module $ModuleName into PSSession $($ServiceSession.name) for System $($serviceObject.Name)."
                            Write-OneShellLog -Message $message -EntryType Attempting
                            Invoke-Command -session $ServiceSession -ScriptBlock {&$using:ImportCommand @using:ImportModuleParams} -ErrorAction Stop
                        }
                        $false
                        {
                            $message = "import required module $ModuleName into Local Session for System $($serviceObject.Name)."
                            Write-OneShellLog -Message $message -EntryType Attempting
                            Invoke-Command -ScriptBlock {&$ImportCommand @ImportModuleParams} -ErrorAction Stop
                        }
                    }
                    Write-OneShellLog -Message $message -EntryType Succeeded
                    $ModuleImported = $true
                }
                catch
                {
                    $myerror = $_
                    Write-OneShellLog -Message $message -ErrorLog -Verbose -EntryType Failed
                    Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                    $ModuleImported = $false
                }
                $ModuleImported
            }
        }#end if
    )
    switch ($ModuleImportResults)
    {
        {$_.count -eq 0}
        {$null}
        {$_ -contains $false}
        {$false}
        {$_ -notcontains $false -and $_ -contains $true}
        {$true}
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
        [parameter()]
        $ServiceSession
        ,
        [parameter()]
        $endpoint
        ,
        [parameter(Mandatory)]
        [ValidateSet('Phase1_PreModuleImport', 'Phase3')]
        $Phase
        ,
        [parameter(Mandatory)]
        [bool]$UsePSRemoting
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    $serviceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
    switch ($UsePSRemoting)
    {
        $true
        {
            $PhaseCommands = $serviceTypeDefinition.PSRemotingSettings.SessionInitialization.$Phase
        }
        $false
        {
            $PhaseCommands = $serviceTypeDefinition.DirectConnectSettings.SessionInitialization.$Phase
        }
    }
    switch ($null -ne $PhaseCommands -and ($PhaseCommands).count -ge 1)
    {
        $true
        {
            $InitializationCommandsResults = @(
                foreach ($cmd in $PhaseCommands)
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
                                if ($null -ne $value)
                                {
                                    $CmdParams.$($p.name) = $value
                                }
                            }
                            Try
                            {
                                switch ($UsePSRemoting)
                                {
                                    $true
                                    {
                                        [void](Invoke-Command -Session $serviceSession -ScriptBlock {& $(($Using:cmd).command) @using:CmdParams} -ErrorAction Stop)
                                    }
                                    $false
                                    {
                                        [void](Invoke-Command -ScriptBlock {& $(($cmd).command) @CmdParams} -ErrorAction Stop)
                                    }
                                }
                                $true
                            }#end Try
                            Catch
                            {
                                $myerror = $_
                                Write-OneShellLog -Message "Initialization Phase $Phase failed." -ErrorLog -Verbose -EntryType Failed
                                Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                                $false
                            }
                        }
                        $false
                        {
                            $null
                        }
                    }
                }
            )
            #output True or false depending on results above
            $InitializationCommandsResults -notcontains $false
        }
        $false
        {
            $null
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
        [parameter(ParameterSetName = 'SessionID', Mandatory, ValuefromPipelineByPropertyName)]
        [int]$ID
        ,
        [parameter(ParameterSetName = 'SessionName', Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name
        ,
        [parameter(ParameterSetName = 'SessionObject', Mandatory, ValueFromPipeline)]
        [Management.Automation.Runspaces.PSSession]$PSSession
        ,
        [switch]$Refresh
    )
    #Find the session
    $GetPSSessionParams = @{
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
        if ($null -ne $remoteFunction.CommandType -and -not $Refresh)
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
    foreach ($Function in $Functions)
    {
        $FunctionText = 'function ' + $Function.Name + "`r`n {`r`n" + $Function.Definition + "`r`n}`r`n"
        $FunctionsText = $FunctionsText + $FunctionText
    }
    #convert functions text to scriptblock
    $ScriptBlock = [scriptblock]::Create($FunctionsText)
    Invoke-Command -Session $PSSession -ScriptBlock $ScriptBlock -ErrorAction Stop
}
#end function Add-FunctionToPSSession
Function Update-SessionManagementGroup
{
    [cmdletbinding()]
    Param
    (
        [parameter(Mandatory = $true)]
        $ServiceSession
        , [parameter(Mandatory = $true)]
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
            }
            else
            {
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
Function Import-OneShellSystemPSSession
{
    [CmdletBinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(Mandatory, ParameterSetName = 'Identity', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string[]]$Identity
        ,
        [parameter(ParameterSetName = 'ServiceObjectAndSession', ValueFromPipelineByPropertyName, Mandatory)]
        [psobject]$ServiceObject
        ,
        [parameter(ParameterSetName = 'ServiceObjectAndSession', ValueFromPipelineByPropertyName, Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$ServiceSession
        ,
        [parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CommandPrefix
    )
    Begin
    {
        if ($null -eq $script:CurrentUserProfile)
        {throw('No OneShell User Profile is active.  Use function Use-OneShellUserProfile to load an User Profile.')}
        $ImportOneShellSystemPSSessionParams = @{
            ErrorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('CommandPrefix'))
        {
            $ImportOneShellSystemPSSessionParams.CommandPrefix = $CommandPrefix
        }
    }
    Process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'ServiceObjectAndSession'
            {
                $ImportOneShellSystemPSSessionParams.ServiceObject = $ServiceObject
                $ImportOneShellSystemPSSessionParams.ServiceSession = $ServiceSession
                ImportOneShellSystemPSSession @ImportOneShellSystemPSSessionParams
            }
            'Identity'
            {
                foreach ($i in $Identity)
                {
                    Try
                    {
                        $ImportOneShellSystemPSSessionParams.ServiceObject = Get-OneShellSystem -identity $i -ErrorAction Stop
                        $ImportOneShellSystemPSSessionParams.ServiceSession = Get-OneShellSystemPSSession -serviceObject $ImportOneShellSystemPSSessionParams.ServiceObject -ErrorAction Stop
                        ImportOneShellSystemPSSession @ImportOneShellSystemPSSessionParams
                    }
                    Catch
                    {
                        $myerror = $_
                        Write-OneShellLog -Message $myerror.tostring() -ErrorLog -Verbose
                    }
                }
            }
        } #end switch
    }
}
#end function Import-OneShellSystem
Function ImportOneShellSystemPSSession
{
    [cmdletbinding()]
    param
    (
        [parameter(ParameterSetName = 'ServiceObjectAndSession')]
        [psobject]$ServiceObject
        ,
        [parameter(ParameterSetName = 'ServiceObjectAndSession')]
        [System.Management.Automation.Runspaces.PSSession]$ServiceSession
        ,
        [parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CommandPrefix
    )
    $ImportPSSessionParams = @{
        ErrorAction         = 'Stop'
        Session             = $ServiceSession
        WarningAction       = 'SilentlyContinue'
        AllowClobber        = $true
        DisableNameChecking = $true
    }
    $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
    if ($null -ne $ServiceTypeDefinition.PSRemotingSettings.Import -and $ServiceTypeDefinition.PSRemotingSettings.Import.ArbitraryCommands.count -ge 1)
    {
        foreach ($cmd in $ServiceTypeDefinition.PSRemotingSettings.Import.ArbitraryCommands)
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
            if ($conditionResults -notcontains $false)
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
                    if ($null -ne $value)
                    {
                        $CmdParams.$($p.name) = $value
                    }
                }
                Try
                {
                    [void](Invoke-Command -Session $serviceSession -ScriptBlock {& $(($Using:cmd).command) @using:CmdParams} -ErrorAction Stop)
                }#end Try
                Catch
                {
                    $myerror = $_
                    Write-OneShellLog -Message "Import PSSession Command $($cmd.command) failed." -ErrorLog -Verbose -EntryType Failed
                    Write-OneShellLog -Message $myerror.tostring() -ErrorLog
                }
            }
        }
    }#end if
    if ($null -ne $ServiceTypeDefinition.PSRemotingSettings.Import -and $ServiceTypeDefinition.PSRemotingSettings.Import.ModulesAndCommands.count -ge 1)
    {
        $Command = @($ServiceTypeDefinition.PSRemotingSettings.Import.ModulesAndCommands | Where-Object -FilterScript {$_.Type -eq 'Command'})
        $Module = @($ServiceTypeDefinition.PSRemotingSettings.Import.ModulesAndCommands | Where-Object -FilterScript {$_.Type -eq 'Module'})
        if ($Command.Count -ge 1)
        {
            $ImportPSSessionParams.CommandName = $Command.name
        }
        if ($Module.Count -ge 1)
        {
            $ImportPSSessionParams.Module = $Module.name
        }
    }
    else
    {
        switch ($ServiceTypeDefinition.PSRemotingSettings.SessionInitialization.Phase2_ModuleImport.count)
        {
            $null
            {}
            {$_ -ge 1}
            {
                $ImportPSSessionParams.Module = $ServiceTypeDefinition.PSRemotingSettings.SessionInitialization.Phase2_ModuleImport.Name
            }
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
    if ($script:ImportedSessionModules.ContainsKey($ServiceObject.Identity))
    {
        $ImportedSessionModule = $Script:ImportedSessionModules.$($ServiceObject.Identity)
        if ((Test-IsNotNullOrWhiteSpace -String $ImportedSessionModule.Name) -and $null -ne (Get-Module -Name $ImportedSessionModule.Name))
        {
            Remove-Module -Name $ImportedSessionModule.Name -ErrorAction Stop
        }
    }

    $message = "Import OneShell System $($ServiceObject.Name) Session $($ServiceSession.Name) into Current Session"
    if ($CommandPrefixExists -eq $true)
    {
        if ($null -ne $CommandPrefix -and -not [string]::IsNullOrWhiteSpace($CommandPrefix))
        {
            $ImportPSSessionParams.Prefix = $CommandPrefix
            $message = $message + " with Command Prefix $CommandPrefix"
        }
        else
        {
            $message = $message + " with NO Command Prefix"
        }
    }
    $ImportModuleParams = @{
        ErrorAction         = 'Stop'
        WarningAction       = 'SilentlyContinue'
        Passthru            = $true
        Global              = $true
        ModuleInfo          = Import-PSSession @ImportPSSessionParams
        DisableNameChecking = $true
    }
    if ($CommandPrefixExists -eq $true)
    {
        $ImportModuleParams.Prefix = $CommandPrefix
    }
    Write-OneShellLog -Message $message -EntryType Attempting
    $ImportedModule = Import-Module @ImportModuleParams
    Write-OneShellLog -Message $message -EntryType Succeeded -Verbose

    $script:ImportedSessionModules.$($ServiceObject.Identity) = [PSCustomObject]@{Identity = $serviceobject.Identity; CommandPrefix = $CommandPrefix; Name = $ImportedModule.name; ServiceType = $ServiceObject.ServiceType}
}
#end function ImportOneShellSystemPSSession
#################################################
# Need to update
#################################################
