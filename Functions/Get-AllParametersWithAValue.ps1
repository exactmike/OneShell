    Function Get-AllParametersWithAValue
    {
        
    [cmdletbinding()]
    param
    (
        $BoundParameters #$PSBoundParameters
        ,
        $AllParameters #$MyInvocation.MyCommand.Parameters
        ,
        [switch]$IncludeCommon
        ,
        $Scope = 1
    )
    $getAllParameterParams = @{
        BoundParameters = $BoundParameters
        AllParameters   = $AllParameters
    }
    if ($IncludeCommon -eq $true) {$getAllParametersParams.IncludeCommon = $true}
    $AllParameterKeys = Get-AllParameter @getAllParameterParams
    $AllParametersWithAValue = @(
        foreach ($k in $AllParameterKeys)
        {
            try
            {
                Get-Variable -Name $k -Scope $Scope -ErrorAction Stop | Where-Object -FilterScript {($null -ne $_.Value -and -not [string]::IsNullOrWhiteSpace($_.Value)) -or $BoundParameters.ContainsKey($k)}
            }
            catch
            {
                #don't care if a particular variable is not found
                Write-Verbose -Message "$k was not found"
            }
        }
    )
    $AllParametersWithAValue

    }

