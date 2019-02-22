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