    Function GetOneShellUserProfileDirectory
    {
        
    [CmdletBinding()]
    param
    ()
    $UserDirectory = $("$env:LocalAppData\OneShell")
    $PersistFileName = 'OneShellUserSettings.json'
    $UserFilePath = Join-Path -Path $UserDirectory -ChildPath $PersistFileName
    if (Test-Path -Path $UserFilePath -PathType Leaf)
    {
        $Script:OneShellUserProfilePath = $(Import-Json -Path $UserFilePath).UserProfilePath
    }
    if ([string]::IsNullOrWhiteSpace($Script:OneShellUserProfilePath))
    {
        $message = 'You must run Set-OneShellUserProfileDirectory. No persisted OneShell User Profile directories found.'
        Write-Warning -Message $message
    }

    }

