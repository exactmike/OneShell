    Function Set-OneShellVariable
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [AllowNull()]
        $Value
    )
    DynamicParam
    {
        $dictionary = New-DynamicParameter -Name Name -Type $([string]) -Mandatory $true -Position 1 -ValidateSet @(Get-Variable -Scope Script -ErrorAction Stop | Select-Object -ExpandProperty Name)
        $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        Set-Variable -Scope Script -Name $Name -Value $value
    }

    }

