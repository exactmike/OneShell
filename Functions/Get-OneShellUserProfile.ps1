    Function Get-OneShellUserProfile
    {
        
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter(ParameterSetName = 'OrgProfileIdentity')]
        [string]$OrgProfileIdentity
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        $ProfileType = 'OneShellUserProfile'
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath
        ,
        [parameter(ParameterSetName = 'GetCurrent')]
        [switch]$GetCurrent
    )#end param
    Begin
    {
    }
    Process
    {
        $outputprofiles = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'GetCurrent'
                {
                    $script:CurrentUserProfile
                }
                Default
                {
                    $PotentialUserProfiles = GetPotentialUserProfiles -path $Path
                    $FoundUserProfiles = @($PotentialUserProfiles | Where-Object {$_.ProfileType -eq $ProfileType})
                    if ($FoundUserProfiles.Count -ge 1)
                    {
                        switch ($PSCmdlet.ParameterSetName)
                        {
                            'All'
                            {
                                $FoundUserProfiles
                            }
                            'Identity'
                            {
                                foreach ($i in $Identity)
                                {
                                    $FoundUserProfiles | Where-Object -FilterScript {$_.Identity -eq $i -or $_.Name -eq $i}
                                }
                            }
                            'OrgProfileIdentity'
                            {
                                $FoundUserProfiles | Where-Object -FilterScript {$_.organization.identity -eq $OrgProfileIdentity -or $_.organization.Name -eq $OrgProfileIdentity}
                            }
                        }#end Switch
                    }#end if
                }#end Default
            }#end Switch
        )#end outputprofiles
        #output the found profiles
        $outputprofiles
        foreach ($opp in $outputprofiles)
        {
            if ($null -ne $opp)
            {
                if ($opp.ProfileTypeVersion -lt $script:UserProfileTypeLatestVersion)
                {
                    Write-Warning -Message "The Schema of User Profile $($opp.Name) is out of date. Run Update-OneShellUserProfileTypeVersion -Identity $($opp.Name) to update."
                }
            }
        }
    }#end End

    }

