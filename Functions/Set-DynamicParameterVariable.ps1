    Function Set-DynamicParameterVariable
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [System.Management.Automation.RuntimeDefinedParameterDictionary]$dictionary
    )
    foreach ($p in $Dictionary.Keys)
    {
        Set-Variable -Name $p -Value $Dictionary.$p.value -Scope 1
        #Write-Verbose "Adding/Setting variable for dynamic parameter '$p' with value '$($PSBoundParameters.$p)'"
    }

    }

