
function Get-OneShellVariable
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
#end function Get-OneShellVariable
function Get-OneShellVariableValue
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
#end function Get-OneShellVariableValue
function Set-OneShellVariable
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
#end function Set-OneShellVariable
function New-OneShellVariable
{
    [cmdletbinding()]
    param
    (
        [string]$Name
        ,
        $Value
    )
    New-Variable -Scope Script -Name $name -Value $Value
}
#end function New-OneShellVariable
function Remove-OneShellVariable
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
#end function Remove-OneShellVariable