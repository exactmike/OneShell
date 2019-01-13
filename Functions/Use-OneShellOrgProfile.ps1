    Function Use-OneShellOrgProfile
    {
        
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'Object')]
        $profile
        ,
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )
    end
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'Object'
            {}
            'Identity'
            {
                $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
                if ($null -eq $Identity)
                {
                    $Profile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
                }
                else
                {
                    #Get the Org Profile
                    $GetOrgProfileParams = @{
                        ErrorAction = 'Stop'
                        Identity    = $Identity
                        Path        = $Path
                    }
                    $Profile = $(Get-OneShellOrgProfile @GetOrgProfileParams)
                }
            }
        }# end switch
        if ($null -ne $script:CurrentOrgProfile -and $profile.Identity -ne $script:CurrentOrgProfile.Identity)
        {
            $script:CurrentOrgProfile = $profile
            Write-OneShellLog -message "Org Profile has been changed to $($script:CurrentOrgProfile.Identity), $($script:CurrentOrgProfile.name).  Remove PSSessions and select an user Profile to load." -EntryType Notification -Verbose
        }
        else
        {
            $script:CurrentOrgProfile = $profile
            Write-OneShellLog -Message "Org Profile has been set to $($script:CurrentOrgProfile.Identity), $($script:CurrentOrgProfile.name)." -EntryType Notification -Verbose
        }
    }

    }

