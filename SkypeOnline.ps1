function New-SkypeOnlinePSSession
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $Credential
        ,
        [parameter(Mandatory)]
        $Name
        ,
        [parameter()]
        $SessionOption
    )
    $newCSOnlineSessionParams = @{
        Credential = $Credential
    }
    if ($PSBoundParameters.ContainsKey($SessionOption))
    {
        $newCSOnlineSessionParams.SessionOption = $SessionOption
    }
    $Session = New-CsOnlineSession @newCSOnlineSessionParams
    $session.Name = $Name
    Write-Output -InputObject $Session
}