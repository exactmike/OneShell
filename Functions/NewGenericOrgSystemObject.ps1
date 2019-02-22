    Function NewGenericOrgSystemObject
    {
        
    [cmdletbinding()]
    param()
    [pscustomobject]@{
        Identity              = [guid]::NewGuid()
        Name                  = ''
        Description           = ''
        ServiceType           = ''
        SystemObjectVersion   = .01
        Version               = .01
        Defaults              = [PSCustomObject]@{
            ProxyEnabled           = $null
            AuthenticationRequired = $true
            UseTLS                 = $null
            AuthMethod             = $null
            CommandPrefix          = $null
            UsePSRemoting          = $true
        }
        Endpoints             = @()
        ServiceTypeAttributes = [PSCustomObject]@{}
    }

    }

