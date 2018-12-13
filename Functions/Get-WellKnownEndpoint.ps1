function Get-WellKnownEndpoint
{
    [cmdletbinding()]
    param
    (
        $ServiceObject
    )
    $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
    @(
        [PSCustomObject]@{
            Identity               = $ServiceObject.ServiceType + '-WellKnownEndpoint'
            AddressType            = 'URL'
            Address                = $ServiceTypeDefinition.WellKnownEndpointURI
            ServicePort            = $null
            UseTLS                 = $false
            ProxyEnabled           = $ServiceObject.Defaults.ProxyEnabled
            CommandPrefix          = $ServiceObject.Defaults.CommandPrefix
            AuthenticationRequired = $true
            AuthMethod             = $ServiceTypeDefinition.WellKnownEndpointAuthMethod
            EndpointGroup          = $null
            EndpointType           = 'Admin'
            ServiceTypeAttributes  = $null
            ServiceType            = $ServiceObject.ServiceType
            Precedence             = -1
            PSRemoting             = $true
        }
    ) | Group-Object
}
#end function Geg-WellKnownEndpoint