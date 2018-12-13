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
