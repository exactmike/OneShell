Function Connect-OneShellSystem
{
    [cmdletbinding(DefaultParameterSetName = 'Default')]
    Param
    (
        [parameter(Mandatory, ParameterSetName = 'Identity', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [parameter(ParameterSetName = 'Reconnect', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string[]]$Identity
        ,
        [parameter(ParameterSetName = 'EndpointIdentity')]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointIdentity #An endpoint identity from existing endpoints configure for this system. Overrides the otherwise specified endpoint.
        ,
        [parameter(ParameterSetName = 'EndpointGroup')]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointGroup #An endpoint identity from existing endpoints configure for this system. Overrides the otherwise specified endpoint.
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
        ,
        [parameter(Mandatory, ParameterSetName = 'AutoConnect')]
        [switch]$AutoConnect
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
        if ($PSCmdlet.ParameterSetName -eq 'AutoConnect')
        {
            $Identity = @(Get-OneShellSystem | Where-Object -FilterScript {$_.AutoConnect -eq $true} | Select-Object -ExpandProperty Identity)
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
            Write-Verbose -Message "UsePSRemoting for this connection is $UsePSRemoting"
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
                        $EndpointGroups = @(
                            #Write-Verbose -Message "Selecting an Endpoint"
                            switch ($ServiceTypeDefinition.DefaultsToWellKnownEndpoint -and ($null -eq $EndpointIdentity -or (Test-IsNullOrWhiteSpace -String $EndpointIdentity)))
                            {
                                $true
                                {
                                    #Write-Verbose -Message "Get Well Known Endpoint(s)."
                                    GetWellKnownEndpoint -ServiceObject $ServiceObject -ErrorAction Stop
                                }
                                Default
                                {
                                    $FindEndpointToUseParams = @{
                                        ErrorAction   = 'Stop'
                                        ServiceObject = $ServiceObject
                                    }
                                    switch ($PSCmdlet.ParameterSetName)
                                    {
                                        'Default'
                                        {}
                                        'EndpointIdentity'
                                        {$FindEndpointToUseParams.EndpointIdentity = $EndpointIdentity}
                                        'EndpointGroup'
                                        {$FindEndpointToUseParams.EndpointGroup = $EndpointGroup}
                                        Default
                                        {}
                                    }
                                    FindEndpointToUse @FindEndpointToUseParams
                                }
                            }
                        )
                        if ($null -eq $EndpointGroups -or $EndpointGroups.Count -eq 0)
                        {throw("No endpoint found for system $($serviceObject.Name), $($serviceObject.Identity)")}
                        $ConnectionReady = $false #we switch this to true when a session is connected and initialized with required modules and settings
                        #Work through the endpoint groups to try connecting in order of precedence
                        for ($i = 0; $i -lt $EndpointGroups.count -and $ConnectionReady -eq $false; $i++)
                        {
                            #get the first endpoint group and randomly order them, then work through them one at a time until successfully connected
                            $g = $endPointGroups[$i]
                            $endpoints = @($g.group | Sort-Object -Property {Get-Random})
                            for ($ii = 0; $ii -lt $endpoints.Count -and $ConnectionReady -eq $false; $ii++)
                            {
                                $e = $endpoints[$ii]
                                $NewPSSessionParams = GetOneShellSystemEndpointPSSessionParameter -ServiceObject $ServiceObject -Endpoint $e -ErrorAction Stop
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
                                            InitializeOneShellSystemPSSession -Phase PreModuleImport -ServiceObject $ServiceObject -ServiceSession $ServiceSession -endpoint $e -ErrorAction Stop -UsePSRemoting $UsePSRemoting
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
                                            ImportModuleInOneShellSystemPSSession -ServiceObject $ServiceObject -ServiceSession $ServiceSession -ErrorAction Stop -UsePSRemoting $UsePSRemoting
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
                                            InitializeOneShellSystemPSSession -Phase PostModuleImport -ServiceObject $ServiceObject -ServiceSession $ServiceSession -endpoint $e -ErrorAction Stop -UsePSRemoting $UsePSRemoting
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
                                    InitializeOneShellSystemPSSession -Phase PreModuleImport -ServiceObject $ServiceObject -ErrorAction Stop -UsePSRemoting $UsePSRemoting
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
                                    ImportModuleInOneShellSystemPSSession -ServiceObject $ServiceObject  -ErrorAction Stop -UsePSRemoting $UsePSRemoting
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
                                    InitializeOneShellSystemPSSession -Phase PostModuleImport -ServiceObject $ServiceObject -ErrorAction Stop -UsePSRemoting $UsePSRemoting
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
                            else
                            {
                                throw("Connection to $($serviceObject.Name) Failed. See Logs for Details.")
                            }
                        }
                        else
                        {
                            Write-OneShellLog -Message $message -EntryType Failed -ErrorLog
                            throw("Connection to $($serviceObject.Name) Failed. See Logs for Details.")
                            #Remove Module(s)?
                        }
                    }
                }#end $false
            }#end Switch
        }#end foreach i in Identity
    }#end Process
}
#end function Connect-OneShellSystem