    Function GetPotentialUserProfiles
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
        throw('You must specify the Path parameter or run Set-OneShellUserProfilePath')
    }
    $JSONProfiles = @(
        foreach ($p in $Path)
        {
            Get-ChildItem -Path "$p\*" -Include '*.json' -Exclude 'OneShellUserSettings.json'
        }
    )
    $PotentialUserProfiles = @(
        foreach ($file in $JSONProfiles)
        {
            Import-JSON -Path $file.fullname |
            Where-Object -FilterScript {$_.Profiletype -eq 'OneShellUserProfile'} |
            Add-Member -MemberType NoteProperty -Name DirectoryPath -Value $File.DirectoryName -PassThru
        }
    )
    if ($PotentialUserProfiles.Count -lt 1)
    {
        throw('You must specify a folder path which contains OneShell User Profiles with the Path parameter and/or you must create at least one User Profile using New-OneShellUserProfile.')
    }
    else
    {
        $PotentialUserProfiles
    }

    }

