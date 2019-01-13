    Function Get-MicrosoftAzureADTenantID
    {
        
    [cmdletbinding()]
    param(
        [parameter(Mandatory, Position = 1)]
        [string]$TenantSubdomain
    )
    if ($TenantSubdomain -like '*.onmicrosoft.com')
    {$TenantSubdomainFragment = $TenantSubdomain.Split('.')[0]}
    elseif ([char[]]$TenantSubdomain -notcontains '.')
    {$TenantSubdomainFragment = $TenantSubdomain}
    else
    {throw("Unexpected value provided for $TenantSubdomain")}
    Write-Verbose -Message "Calculated URI: $URI"
    $URI = 'https://login.windows.net/' + $TenantSubdomainFragment + '.onmicrosoft.com' + '/.well-known/openid-configuration'
    (Invoke-WebRequest -Uri $URI | ConvertFrom-Json).token_endpoint.Split('/')[3]

    }

