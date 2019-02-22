    Function Get-OneShellUserProfileCredential
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [parameter(Position = 2)]
        [string]$Identity #Credential Identity or UserName
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath

    )#end param
    End
    {
        $getUserProfileParams = @{
            ErrorAction = 'Stop'
            Path        = $Path
        }
        if (-not [string]::IsNullOrEmpty($ProfileIdentity))
        {$getUserProfileParams.Identity = $ProfileIdentity}
        $UserProfile = @(Get-OneShellUserProfile @getUserProfileParams)
        $OutputCredentials = @(
            foreach ($ap in $UserProfile)
            {
                $ProfileName = $ap.Name
                $ProfileIdentity = $ap.Identity
                $ap.Credentials | Select-Object -Property *, @{n = 'UserProfileName'; e = {$ProfileName}}, @{n = 'UserProfileIdentity'; e = {$ProfileIdentity}}
            }
        )
        if (-not [string]::IsNullOrEmpty($Identity))
        {$OutputCredentials = $OutputCredentials | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Username -eq $Identity}}
        $OutputCredentials
    }

    }

