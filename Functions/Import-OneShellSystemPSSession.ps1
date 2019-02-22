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