    Function Set-OneShellUserProfileDirectory
    {
        
    [cmdletbinding()]
    param
    (
        [parameter()]
        [string]$Path #If not specified the Path will default to the DefaultPath of $env:LocalAppData\OneShell
        ,
        [parameter()]
        [switch]$DoNotPersist #By Default, this function tries to persist the UserProfileDirectory to the DefaultPath by writing a JSON file with the setting to that location.  This switch overrides that behavior.
    )
    $DefaultPath = $("$env:LocalAppData\OneShell")
    if ($Path -ne $DefaultPath)
    {
        $message = "The recommended/default location for User specific OneShell User Profile storage is $DefaultPath."
        Write-Verbose -Message $message -Verbose
    }
    if (-not $PSBoundParameters.ContainsKey('Path'))
    {
        $Path = $DefaultPath
    }

    if (-not (Test-Path -Path $Path -PathType Container))
    {
        Write-Verbose -Message "Creating Directory $Path" -Verbose
        try
        {
            [void](New-Item -Path $Path -ItemType Directory -ErrorAction Stop)
        }
        catch
        {
            throw($_)
        }
    }
    if (-not (Test-IsWriteableDirectory -path $path))
    {
        $message = "The specified path exists but does not appear to be writeable. Without elevating or using a different credential this user may be able to use existing OneShell User Profiles in this location but may not be able to edit them."
        Write-Warning -Message $message
    }
    $Script:OneShellUserProfilePath = $Path

    if (-not $PSBoundParameters.ContainsKey('DoNotPersist'))
    {
        if (-not (Test-Path -Path $DefaultPath -PathType Container))
        {
            Write-Verbose -Message "Creating Directory $DefaultPath" -Verbose
            try
            {
                [void](New-Item -Path $DefaultPath -ItemType Directory -ErrorAction Stop)
            }
            catch
            {
                throw($_)
            }
        }
        $PersistObject = [PSCustomObject]@{
            UserProfilePath = $Path
        }
        $PersistFileName = 'OneShellUserSettings.json'
        $PersistFilePath = Join-Path -Path $DefaultPath -ChildPath $PersistFileName
        if ((Test-IsWriteableDirectory -path $DefaultPath))
        {
            $PersistObject | ConvertTo-Json | Out-File -Encoding utf8 -FilePath $PersistFilePath
        }
        else
        {
            $message = "Unable to write file $PersistFilePath. You may have to use Set-OneShellUserProfileDirectory with subsequent uses of the OneShell module."
            Write-Warning -Message $message
        }
    }

    }

