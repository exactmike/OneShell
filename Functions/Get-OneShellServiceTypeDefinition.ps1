    Function Get-OneShellServiceTypeDefinition
    {
        
    [cmdletbinding()]
    param
    (
        [parameter()]
        [string]$ServiceType
    )
    $Script:ServiceTypes | where-object -FilterScript {$_.Name -eq $ServiceType -or (Test-IsNullOrWhiteSpace -String $ServiceType)}

    }

