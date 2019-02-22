    Function GetOneShellOrgProfileDirectory
    {
        
    [CmdletBinding()]
    param
    ()
    $UserDirectory = $("$env:LocalAppData\OneShell")
    $SystemDirectory = $("$env:ALLUSERSPROFILE\OneShell")
    $PersistFileName = 'OneShellSystemSettings.json'
    $UserFilePath = Join-Path -Path $UserDirectory -ChildPath $PersistFileName
    $SystemFilePath = Join-Path -Path $SystemDirectory -ChildPath $PersistFileName
    if (Test-Path -Path $UserFilePath -PathType Leaf)
    {
        $Script:OneShellOrgProfilePath = $(Import-Json -Path $UserFilePath).OrgProfilePath
    }
    else
    {
        if (Test-Path -Path $SystemFilePath -PathType Leaf)
        {
            $Script:OneShellOrgProfilePath = $(Import-Json -Path $SystemFilePath).OrgProfilePath
        }
    }
    if ([string]::IsNullOrWhiteSpace($Script:OneShellOrgProfilePath))
    {
        $message = 'You must run Set-OneShellOrgProfileDirectory. No persisted OneShell Org Profile directories found.'
        Write-Warning -Message $message
    }

    }

