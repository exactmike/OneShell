    Function Remove-OneShellVariable
    {
        
    [cmdletbinding()]
    param()
    DynamicParam
    {
        $dictionary = New-DynamicParameter -Name Name -Type $([string]) -Mandatory $true -Position 1 -ValidateSet @(Get-Variable -Scope Script -ErrorAction Stop | Select-Object -ExpandProperty Name)
        $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        Remove-Variable -Scope Script -Name $name
    }

    }

