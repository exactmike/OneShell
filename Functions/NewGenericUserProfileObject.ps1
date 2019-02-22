    Function NewGenericUserProfileObject
    {
        
    [cmdletbinding()]
    param
    (
        $TargetOrgProfile
    )
    [pscustomobject]@{
        Identity            = [guid]::NewGuid()
        ProfileType         = 'OneShellUserProfile'
        ProfileTypeVersion  = 1.4
        Name                = $targetOrgProfile.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME
        Host                = $env:COMPUTERNAME
        User                = $env:USERNAME
        Organization        = [pscustomobject]@{
            Name     = $targetOrgProfile.Name
            Identity = $targetOrgProfile.identity
        }
        ProfileFolder       = ''
        LogFolder           = ''
        ExportDataFolder    = ''
        InputFilesFolder    = ''
        MailFromSMTPAddress = ''
        Systems             = @()
        Credentials         = @()
    }

    }

