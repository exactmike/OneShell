    Function GetSelectProfile
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [ValidateSet('Org', 'User')]
        $ProfileType
        ,
        [parameter(Mandatory)]
        $Path
        ,
        [parameter(Mandatory)]
        [psobject[]]$PotentialProfiles
        ,
        [parameter()]
        [AllowNull()]
        $Identity
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Associate', 'Get', 'Use')]
        $Operation
    )
    if ($null -eq $Identity -or (Test-IsNullOrWhiteSpace -String $identity))
    {
        Select-Profile -Profiles $PotentialProfiles -Operation $Operation
    }
    else
    {
        $Profile = $(
            switch ($ProfileType)
            {
                'Org'
                {
                    $GetOrgProfileParams = @{
                        ErrorAction = 'Stop'
                        Identity    = $Identity
                        Path        = $Path
                    }
                    Get-OneShellOrgProfile @GetOrgProfileParams
                }
                'User'
                {
                    $GetUserProfileParams = @{
                        ErrorAction = 'Stop'
                        Path        = $Path
                        Identity    = $Identity
                    }
                    Get-OneShellUserProfile @GetUserProfileParams
                }
            }
        )
        if ($null -eq $Profile -or $Profile.count -ge 2 -or $profile.count -eq 0)
        {
            throw("No valid $ProfileType Profile Identity was provided.")
        }
        else
        {
            $Profile
        }
    }

    }

