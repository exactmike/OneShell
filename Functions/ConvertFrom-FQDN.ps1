    Function ConvertFrom-FQDN
    {
        
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string[]]$FQDN
    )
    process
    {
        foreach ($f in $FQDN)
        {
            “DC=$($f.replace(“.”, “,DC=”))”
        }
    }

    }

