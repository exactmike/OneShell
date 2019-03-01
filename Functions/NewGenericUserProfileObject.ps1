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
        Name                = $targetOrgProfile.name + '-' + [Environment]::UserName + '-' + [Environment]::MachineName
        Host                = [Environment]::MachineName
        User                = [Environment]::UserName
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
