    Function GetPotentialOrgProfiles
    {
        
    [cmdletbinding()]
    param
    (
        [parameter()]
        [AllowNull()]
        [string[]]$path
    )
    if ($null -eq $path)
    {
        throw('You must specify the Path parameter or run Set-OneShellOrgProfilePath')
    }
    $JSONProfiles = @(
        foreach ($p in $Path)
        {
            Write-Verbose -Message "Getting json Files From $p"
            (Get-ChildItem -Path "$p\*" -Include '*.json' -Exclude 'OneShellSystemSettings.json')
        }
    )
    Write-Verbose -Message "Found $($jsonProfiles.count) json Files"
    $PotentialOrgProfiles = @(
        foreach ($file in $JSONProfiles)
        {
            Import-Json -Path $file.fullname |
            Where-Object -FilterScript {$_.ProfileType -eq 'OneShellOrgProfile'} |
            Add-Member -MemberType NoteProperty -Name DirectoryPath -Value $File.DirectoryName -PassThru
        }
    )
    Write-Verbose -Message "Found $($PotentialOrgProfiles.count) Potential Org Profiles"
    if ($PotentialOrgProfiles.Count -lt 1)
    {
        throw('You must specify a folder path which contains OneShell Org Profiles with the Path parameter and/or you must create at least one Org Profile using New-OneShellOrgProfile.')
    }
    else
    {
        $PotentialOrgProfiles
    }

    }

