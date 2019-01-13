    Function Test-EmailAddress
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipeline)]
        [string[]]$EmailAddress
    )
    process
    {
        foreach ($ea in $EmailAddress)
        {
            #Regex borrowed from: http://www.regular-expressions.info/email.html
            $ea -imatch '^(?=[A-Z0-9][A-Z0-9@._%+-]{5,253}$)[A-Z0-9._%+-]{1,64}@(?:(?=[A-Z0-9-]{1,63}\.)[A-Z0-9]+(?:-[A-Z0-9]+)*\.){1,8}[A-Z]{2,63}$'
        }
    }

    }

