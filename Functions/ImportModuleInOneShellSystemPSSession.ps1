function ImportModuleInOneShellSystemPSSession
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
            $Phase2Modules = $serviceTypeDefinition.PSRemotingSettings.SessionInitialization.ModuleImport
        }
        $false
        {
            $Phase2Modules = $serviceTypeDefinition.DirectConnectSettings.SessionInitialization.ModuleImport
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
                    Scope = 'Global'
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
#end function ImportModuleIntoOneShellSystemPSSession