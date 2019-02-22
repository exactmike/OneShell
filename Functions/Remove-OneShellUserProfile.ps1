    Function Remove-OneShellUserProfile
    {
        
    [cmdletbinding(DefaultParameterSetName = "Identity", SupportsShouldProcess)]
    param
    (
        [parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
    )
    Begin
    {
        $paProfiles = GetPotentialUserProfiles -path $Path
    }
    Process
    {
        foreach ($i in $Identity)
        {
            $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $paProfiles -Identity $i -Operation Edit
            $ProfilePath = Join-Path -Path $Path -ChildPath $($UserProfile.Identity + '.json')
            Remove-Item -Path $ProfilePath
        }#end foreach
    }#End Process

    }

