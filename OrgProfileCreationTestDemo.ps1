$NewOrgProfile = New-OrgProfile -Name ExactTest -IsDefault $true -Verbose
$system1 = New-OrgSystem -ServiceType ExchangeOrganization -Name Exact -Description 'Exact On Premises Exchange Organization' -isDefault $true -AuthenticationRequired $true -CommandPrefix 'OP' -ProxyEnabled $false -UseTLS $false
$system1
$system1Endpoint1 = New-OrgSystemEndpoint -ServiceType ExchangeOrganization -AddressType fqdn -Address usgvlve1402.exactsolutions.local -IsDefault $true -UseTLS $false -ProxyEnabled $false -EndPointType Admin
$system1Endpoint1
$system1.Endpoints += $system1Endpoint1
$system1
$NewOrgProfile.Systems += $system1