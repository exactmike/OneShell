    Function Test-ForInstalledModule
    {
        
    Param
    (
        [parameter(Mandatory = $True)]
        [string]$Name
    )
    If
    (
        (Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue) `
            -or (Get-PSSnapin -Name $Name -ErrorAction SilentlyContinue) `
            -or (Get-PSSnapin -Name $Name -Registered -ErrorAction SilentlyContinue)
    )
    {$True}
    Else
    {$False}

    }

