    Function AddUserProfileFolder
    {
        
    [cmdletbinding()]
    param
    (
        $UserProfile
    )
    $profileFolder = $UserProfile.ProfileFolder
    if ($null -eq $profileFolder -or [string]::IsNullOrEmpty($profileFolder))
    {throw("User Profile $($UserProfile.Identity) Profile Folder is invalid.")}
    if (-not (Test-Path -Path $profileFolder))
    {
        [void](New-Item -Path $profileFolder -ItemType Directory -ErrorAction Stop)
    }
    $profileSubfolders = $(join-path $profilefolder 'Logs'), $(join-path $profilefolder 'Export'), $(join-path $profileFolder 'InputFiles')
    foreach ($folder in $profileSubfolders)
    {
        if (-not (Test-Path -Path $folder))
        {
            [void](New-Item -Path $folder -ItemType Directory -ErrorAction Stop)
        }
    }

    }

