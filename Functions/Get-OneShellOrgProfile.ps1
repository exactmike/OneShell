    Function Get-OneShellOrgProfile
    {
        
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param
    (
        [parameter(ParameterSetName = 'Identity', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        $OrgProfileType = 'OneShellOrgProfile'
        ,
        [parameter(ParameterSetName = 'GetCurrent')]
        [switch]$GetCurrent
    )
    Process
    {
        Write-Verbose -Message "Parameter Set is $($pscmdlet.ParameterSetName)"
        switch ($PSCmdlet.ParameterSetName)
        {
            'GetCurrent'
            {
                $Script:CurrentOrgProfile
            }
            Default
            {
                $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $path)
                if ($PotentialOrgProfiles.Count -ge 1)
                {
                    $FoundOrgProfiles = @($PotentialOrgProfiles | Where-Object {$_.ProfileType -eq $OrgProfileType})
                    Write-Verbose -Message "Found $($FoundOrgProfiles.Count) Org Profiles."
                    switch ($PSCmdlet.ParameterSetName)
                    {
                        'Identity'
                        {
                            foreach ($i in $Identity)
                            {
                                Write-Verbose -Message "Identity is set to $"
                                @($FoundOrgProfiles | Where-Object -FilterScript {$_.Identity -eq $i -or $_.Name -eq $i})
                            }
                        }#Identity
                        'All'
                        {
                            @($FoundOrgProfiles)
                        }#All
                    }#switch
                }#if
            }#Default
        }#switch
    }#end Process

    }

