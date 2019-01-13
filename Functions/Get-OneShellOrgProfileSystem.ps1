    Function Get-OneShellOrgProfileSystem
    {
        
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity #System Identity or Name
        ,
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'All')]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
        ,
        [parameter(ParameterSetName = 'GetCurrent')]
        [switch]$GetCurrent
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [string[]]$ServiceType
        ,
        [parameter(ParameterSetName = 'Identity')]
        [string[]]$ProfileIdentity
    )
    Begin
    {
        $profiles = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'GetCurrent'
                {
                    Get-OneShellOrgProfile -GetCurrent -ErrorAction Stop -Path $Path
                }
                'Identity'
                {
                    if ($PsBoundParameters.ContainsKey('ProfileIdentity'))
                    {
                        Get-OneShellOrgProfile -Identity $ProfileIdentity -ErrorAction Stop -Path $Path
                    }
                    else
                    {
                        Get-OneShellOrgProfile -Path $Path -ErrorAction Stop
                    }
                }
                'All'
                {
                    Get-OneShellOrgProfile -ErrorAction Stop -Path $Path
                }
            }
        )
        $OutputSystems = @(
            foreach ($p in $profiles)
            {
                $p.systems #| Select-Object -Property *, @{n = 'OrgName'; e = {$p.Name}}, @{n = 'OrgIdentity'; e = {$p.Identity}}, @{n = 'ProfileIdentity'; e = {$p.Identity}}
            }
        )
        #Filter outputSystems if required by specified parameters
        $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.ServiceType -in $ServiceType -or (Test-IsNullOrWhiteSpace -string $ServiceType)})
        $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.Identity -in $Identity -or $_.Name -in $Identity -or (Test-IsNullorWhiteSpace -string $Identity)})
        $OutputSystems
    }

    }

