    Function Get-ArrayIndexForValue
    {
        
    [cmdletbinding()]
    param(
        [parameter(mandatory = $true)]
        $array #The array for which you want to find a value's index
        ,
        [parameter(mandatory = $true)]
        $value #The Value for which you want to find an index
        ,
        [parameter()]
        $property #The property name for the value for which you want to find an index
    )
    if ([string]::IsNullOrWhiteSpace($Property))
    {
        Write-Verbose -Message 'Using Simple Match for Index'
        [array]::indexof($array, $value)
    }#if
    else
    {
        Write-Verbose -Message 'Using Property Match for Index'
        [array]::indexof($array.$property, $value)
    }#else

    }

