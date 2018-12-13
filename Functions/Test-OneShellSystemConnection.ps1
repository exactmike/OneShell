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
        if ($null -ne $serviceTypeDefinition.ConnectionTest.command)
        {
            $TestCommand = $serviceTypeDefinition.ConnectionTest.Command
            Write-Verbose -message "Test Command is $TestCommand"
            $TestCommandParams = Get-ParameterSplatFromDefinition -ParameterDefinition $serviceTypeDefinition.ConnectionTest.Parameters -ValueForErrorAction 'Stop'
            Write-OneShellLog -Message "Found Service Type Command to use for $($serviceObject.ServiceType): $testCommand" -EntryType Notification
            $PreTestCommands = @(
                if ($null -ne $serviceTypeDefinition.ConnectionTest.PreTestCommands -and $serviceTypeDefinition.ConnectionTest.PreTestCommands.count -ge 1)
                {
                    foreach ($ptc in $serviceTypeDefinition.ConnectionTest.PreTestCommands)
                    {
                        [pscustomobject]@{
                            Command = $ptc.Command
                            Parameters = Get-ParameterSplatFromDefinition -ParameterDefinition $ptc.parameters -ValueForErrorAction 'Stop'
                        }
                    }
                }
            )
            $PostTestCommands = @(
                if ($null -ne $serviceTypeDefinition.ConnectionTest.PostTestCommands -and $serviceTypeDefinition.ConnectionTest.PostTestCommands.count -ge 1)
                {
                    foreach ($ptc in $serviceTypeDefinition.ConnectionTest.PostTestCommands)
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
                #determine whether to run the Connection Test in Session or directly
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
                if ($null -ne $serviceTypeDefinition.ConnectionTest.Validation -and $serviceTypeDefinition.ConnectionTest.Validation.Count -ge 1)
                {
                    $Validations = @(
                        foreach ($v in $serviceTypeDefinition.ConnectionTest.Validation)
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