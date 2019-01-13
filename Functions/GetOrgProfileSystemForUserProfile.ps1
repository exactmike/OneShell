    Function GetOrgProfileSystemForUserProfile
    {
        
    [cmdletbinding()]
    param($OrgProfile)
    foreach ($s in $OrgProfile.Systems)
    {
        [PSCustomObject]@{
            Identity          = $s.Identity
            AutoConnect       = $null
            AutoImport        = $null
            Credentials       = [PSCustomObject]@{
                PSSession = $null
                Service   = $null
            }
            PreferredEndpoint = $null
            PreferredPrefix   = $null
            UsePSRemoting     = $null
            ProxyEnabled      = $null
            AuthenticationRequired = $null
            UseTLS = $null
            AuthMethod = $null
        }
    }

    }

