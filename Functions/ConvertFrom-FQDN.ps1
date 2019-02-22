    Function ConvertFrom-FQDN
    {

    [cmdletbinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string[]]$FQDN
    )
    process
    {
        foreach ($f in $FQDN)
        {
            "DC=$($f.replace(".", ",DC="))"
        }
    }

    }
