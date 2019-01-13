    Function Test-IP
    {
        
    #https://gallery.technet.microsoft.com/scriptcenter/A-short-tip-to-validate-IP-4f039260
    param
    (
        [Parameter(Mandatory)]
        [ValidateScript( {$_ -match [IPAddress]$_})]
        [String]$ip
    )
    $ip

    }

