    Function Get-OneShellVariable
    {
        
    [cmdletbinding()]
    param
    (
    )
    DynamicParam
    {
        $dictionary = New-DynamicParameter -Name Name -Type $([string]) -Mandatory $false -Position 1 -ValidateSet @(Get-Variable -Scope Script -ErrorAction Stop | Select-Object -ExpandProperty Name)
        $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        if ($null -eq $name)
        {
            $name = '*'
        }
        Try
        {
            Get-Variable -Scope Script -Name $name -ErrorAction Stop
        }
        Catch
        {
            Write-Verbose -Message "Variable $name Not Found" -Verbose
        }
    }

    }

