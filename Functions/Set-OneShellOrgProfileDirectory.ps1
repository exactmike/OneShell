    Function Set-OneShellOrgProfileDirectory
    {
        
    [cmdletbinding()]
    param
    (
        [parameter()]
        [string]$Path #If not specified the Path will default to the DefaultPath of $env:ALLUSERSPROFILE\OneShell for OrgProfileDirectoryScope System and to $env:LocalAppData\OneShell for OrgProfileDirectoryScope User
        ,
        [parameter(Mandatory)]
        [validateSet('AllUsers', 'CurrentUser')]
        [string]$OrgProfileDirectoryScope
        ,
        [parameter()]
        [switch]$DoNotPersist #By Default, this function tries to persist the OrgProfileDirectory to the DefaultPath by writing a JSON file with the setting to that location.  This switch overrides that behavior.
    )
    switch ($OrgProfileDirectoryScope)
    {
        'AllUsers'
        {
            $DefaultPath = $("$env:ALLUSERSPROFILE\OneShell")
            if ($Path -ne $DefaultPath)
            {
                $message = "The recommended/default location for AllUsers OneShell Org Profile storage is $DefaultPath."
                Write-Verbose -Message $message -Verbose
            }
            if (-not $PSBoundParameters.ContainsKey('Path'))
            {
                $Path = $DefaultPath
            }
        }
        'CurrentUser'
        {
            $DefaultPath = $("$env:LocalAppData\OneShell")
            if ($Path -ne $DefaultPath)
            {
                $message = "The recommended/default location for User specific OneShell Org Profile storage is $DefaultPath."
                Write-Verbose -Message $message -Verbose
            }
            if (-not $PSBoundParameters.ContainsKey('Path'))
            {
                $Path = $DefaultPath
            }
        }
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
        $message = "The specified path exists but does not appear to be writeable. Without elevating or using a different credential this user may be able to use existing OneShell Org Profiles in this location but may not be able to edit them."
        Write-Warning -Message $message
    }
    $Script:OneShellOrgProfilePath = $Path

    if (-not $PSBoundParameters.ContainsKey('DoNotPersist'))
    {
        $PersistObject = [PSCustomObject]@{
            OrgProfilePath = $Path
        }
        $PersistFileName = 'OneShellSystemSettings.json'
        $PersistFilePath = Join-Path -Path $DefaultPath -ChildPath $PersistFileName
        if ((Test-IsWriteableDirectory -path $DefaultPath))
        {

            $PersistObject | ConvertTo-Json | Out-File -Encoding utf8 -FilePath $PersistFilePath
        }
        else
        {
            $message = "Unable to write file $PersistFilePath. You may have to use Set-OneShellOrgProfileDirectory with subsequent uses of the OneShell module."
            Write-Warning -Message $message
        }
    }

    }

