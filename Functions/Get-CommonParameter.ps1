    Function Get-CommonParameter
    {
        [cmdletbinding(SupportsShouldProcess)]
        param()
        if ($PSCmdlet.ShouldProcess($true))
        {
            $MyInvocation.MyCommand.Parameters.Keys
        }
    }
