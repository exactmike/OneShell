function GetOneShellSystemEndpointPSSessionParameter
{
    [cmdletbinding()]
    param
    (
        $ServiceObject
        ,
        $Endpoint
    )
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }#end begin
    end
    {
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceObject.ServiceType
        $NewPSSessionParams = @{
            ErrorAction = 'Stop'
            Name        = $($ServiceObject.Identity + '%' + $Endpoint.Identity)
        }
        if ($null -ne $ServiceObject.Credentials.PSSession)
        {
            $NewPSSessionParams.Credential = $ServiceObject.Credentials.PSSession
        }
        #Apply Service Type Defaults
        foreach ($p in $ServiceTypeDefinition.PSRemotingSettings.ConnectCommand.Parameters)
        {
            $Value = $(
                switch ($p.ValueType)
                {
                    'Static'
                    {$p.Value}
                    'ScriptBlock'
                    {
                        & $([scriptblock]::Create($p.Value))
                    }
                }
            )
            $NewPSSessionParams.$($p.Name) = $Value
        }
        #Apply ServiceObject Defaults or their endpoint overrides
        if ($ServiceObject.defaults.ProxyEnabled -eq $true -or $Endpoint.ProxyEnabled -eq $true)
        {
            $NewPSSessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig #-ProxyAuthentication basic
        }
        if ($ServiceObject.defaults.UseTLS -eq $true -or $Endpoint.UseTLS -eq $true)
        {
            $NewPSSessionParams.UseSSL = $true
        }
        if (Test-IsNotNullOrWhiteSpace -string $ServiceObject.defaults.AuthMethod)
        {
            $NewPSSessionParams.Authentication = $ServiceObject.defaults.AuthMethod
        }
        if (Test-IsNotNullOrWhiteSpace -String $endpoint.AuthMethod)
        {
            $NewPSSessionParams.Authentication = $Endpoint.AuthMethod
        }
        #Apply Endpoint only settings
        if (Test-IsNotNullOrWhiteSpace -String $endpoint.ServicePort)
        {
            $NewPSSessionParams.Port = $Endpoint.ServicePort
        }
        $NewPSSessionParams
    }#end end
}
#end function Get-EndpointPSSessionParameter
