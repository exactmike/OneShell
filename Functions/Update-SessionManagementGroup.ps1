Function Update-SessionManagementGroup
{
    [cmdletbinding()]
    Param
    (
        [parameter(Mandatory = $true)]
        $ServiceSession
        , [parameter(Mandatory = $true)]
        [string[]]$ManagementGroups
    )
    foreach ($mg in $ManagementGroups)
    {
        $SessionGroup = $mg + '_PSSessions'
        #Check if the Session Group already exists
        if (Test-Path -Path "variable:\$SessionGroup")
        {
            #since the session group already exists, add the session to it if it is not already present
            $ExistingSessions = Get-Variable -Name $SessionGroup -Scope Global -ValueOnly
            $ExistingSessionNames = $existingSessions | Select-Object -ExpandProperty Name
            if ($ServiceSession.name -in $ExistingSessionNames)
            {
                $NewValue = @($ExistingSessions | Where-Object -FilterScript {$_.Name -ne $ServiceSession.Name})
                $NewValue += $ServiceSession
                Set-Variable -Name $SessionGroup -Value $NewValue -Scope Global
            }
            else
            {
                $NewValue = $ExistingSessions + $ServiceSession
                Set-Variable -Name $SessionGroup -Value $NewValue -Scope Global
            }
        }
        else #since the session group does not exist, create it and add the session to it
        {
            New-Variable -Name $SessionGroup -Value @($ServiceSession) -Scope Global
        }# end else
    }# end foreach
}
#end function Update-SessionManagementGroup