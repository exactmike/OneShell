    Function NewGenericSystemEndpointObject
    {
        
    [cmdletbinding()]
    param()
    [PSCustomObject]@{
        Identity               = [guid]::NewGuid()
        AddressType            = $null
        Address                = $null
        ServicePort            = $null
        UseTLS                 = $null
        ProxyEnabled           = $null
        CommandPrefix          = $null
        AuthenticationRequired = $null
        AuthMethod             = $null
        EndpointGroup          = $null
        Precedence             = $null
        EndpointType           = $null
        ServiceTypeAttributes  = [PSCustomObject]@{}
        ServiceType            = $null
        PSRemoting             = $null
    }

    }

