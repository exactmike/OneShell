    Function Get-AllParameter
    {
        
    [cmdletbinding()]
    param
    (
        $BoundParameters #$PSBoundParameters
        ,
        $AllParameters #$MyInvocation.MyCommand.Parameters
        ,
        [switch]$IncludeCommon
    )
    $AllKeys = $($AllParameters.Keys ; $BoundParameters.Keys)
    $AllKeys = $AllKeys | Sort-Object -Unique
    if ($IncludeCommon -ne $true)
    {
        $AllKeys = $AllKeys | Where-Object -FilterScript {$_ -notin @(Get-CommonParameter)}
    }
    $AllKeys

    }

