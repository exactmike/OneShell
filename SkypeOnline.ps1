function New-SkypeOnlinePSSession
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [pscredential]$Credential
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
    $Session
}