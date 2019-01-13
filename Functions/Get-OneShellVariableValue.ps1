    Function Get-OneShellVariableValue
    {
        
    [cmdletbinding()]
    param
    (
    )
    DynamicParam
    {
        $dictionary = New-DynamicParameter -Name Name -Type $([string]) -Mandatory $true -Position 1 -ValidateSet @(Get-Variable -Scope Script -ErrorAction Stop | Select-Object -ExpandProperty Name)
        $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        Try
        {
            Get-Variable -Scope Script -Name $name -ErrorAction Stop -ValueOnly
        }
        Catch
        {
            Write-Verbose -Message "Variable $name Not Found" -Verbose
        }
    }

    }

