    Function Update-OneShellUserProfileTypeVersion
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $Identity
        ,
        $Path = $Script:OneShellUserProfilePath
    )
    End
    {
        $GetUserProfileParams = @{
            Identity    = $Identity
            errorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Path'))
        {
            $GetUserProfileParams.Path = $Path
        }
        $UserProfile = Get-OneShellUserProfile @GetUserProfileParams
        $UpdatedUserProfile = UpdateUserProfileObjectVersion -UserProfile $UserProfile
        Export-OneShellUserProfile -profile $UpdatedUserProfile -path $Path
    }

    }

