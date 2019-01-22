Function Remove-OneShellOrgProfile
{
    [cmdletbinding(DefaultParameterSetName = "Identity", SupportsShouldProcess)]
    param
    (
        [parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )
    Begin
    {
        $poProfiles = GetPotentialOrgProfiles -path $Path
    }
    Process
    {
        foreach ($i in $Identity)
        {
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $poProfiles -Identity $i -Operation Edit
            $ProfilePath = Join-Path -Path $Path -ChildPath $($OrgProfile.Identity + '.json')
            Remove-Item -Path $ProfilePath
        }#end foreach
    }#End Process
}
