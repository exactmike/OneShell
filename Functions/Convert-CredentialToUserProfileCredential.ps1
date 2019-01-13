    Function Convert-CredentialToUserProfileCredential
    {
        
    [cmdletbinding()]
    param
    (
        [pscredential]$credential
        ,
        [string]$Identity
    )
    if ($null -eq $Identity -or [string]::IsNullOrWhiteSpace($Identity))
    {$Identity = $(New-OneShellGuid).guid}
    $credential | Add-Member -MemberType NoteProperty -Name 'Identity' -Value $Identity
    $credential | Select-Object -Property @{n = 'Identity'; e = {$_.Identity}}, @{n = 'UserName'; e = {$_.UserName}}, @{n = 'Password'; e = {$_.Password | ConvertFrom-SecureString}}

    }

