    Function GetSelectProfileSystem
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [psobject[]]$PotentialSystems
        ,
        [parameter()]
        [AllowNull()]
        $Identity
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Associate', 'Get', 'Use')]
        $Operation
    )
    $System = $(
        if ($null -eq $Identity -or (Test-IsNullOrWhiteSpace -String $identity))
        {
            Select-ProfileSystem -Systems $PotentialSystems -Operation $Operation
        }
        else
        {
            if ($Identity -in $PotentialSystems.Identity -or $Identity -in $PotentialSystems.Name)
            {$PotentialSystems | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Name -eq $Identity}}
        }
    )
    if ($null -eq $system -or $system.count -ge 2 -or $system.count -eq 0)
    {throw("Invalid SystemIdentity $Identity was provided.  No such system exists or ambiguous system exists.")}
    else
    {$system}

    }

