function InitializeOneShellSystemPSSession
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
        [ValidateSet('PreModuleImport', 'PostModuleImport')]
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
#end function InitializeOneShellSystemPSSession