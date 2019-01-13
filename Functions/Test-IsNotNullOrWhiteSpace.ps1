    Function Test-IsNotNullOrWhiteSpace
    {
        
    [cmdletbinding()]
    Param(
        $String
    )
    [string]::IsNullOrWhiteSpace($String) -eq $false

    }

