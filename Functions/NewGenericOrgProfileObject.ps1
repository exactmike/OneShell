    Function NewGenericOrgProfileObject
    {
        
    [cmdletbinding()]
    param()
    [pscustomobject]@{
        Identity                    = [guid]::NewGuid()
        Name                        = ''
        ProfileType                 = 'OneShellOrgProfile'
        ProfileTypeVersion          = 1.2
        Version                     = .01
        OrganizationSpecificModules = @()
        Systems                     = @()
    }

    }

