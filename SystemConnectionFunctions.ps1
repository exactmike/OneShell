##########################################################################################################
#Remote System Connection Functions
##########################################################################################################
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
    foreach ($mg in $ManagementGroups)
    {
        $SessionGroup = $mg + '_PSSessions'
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
        switch ($ServiceTypeDefinition.PSRemotingSettings.SessionInitialization.ModuleImport.count)
        {
            $null
            {}
            {$_ -ge 1}
            {
                $ImportPSSessionParams.Module = $ServiceTypeDefinition.PSRemotingSettings.SessionInitialization.ModuleImport.Name
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
