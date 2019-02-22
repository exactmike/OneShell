    Function Remove-OneShellUserProfileCredential
    {
        
    [cmdletbinding(DefaultParameterSetName = 'Select')]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ParameterSetName = 'Identity', Position = 2)]
        [string]$Identity
        ,
        [parameter(Mandatory, ParameterSetName = 'UserName', Position = 2)]
        [string]$Username
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
    )#end param
    End
    {
        #Get/Select the Profile
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellUserProfilePath}
        $puProfiles = GetPotentialUserProfiles -path $Path
        $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $puProfiles -Identity $ProfileIdentity -Operation Edit
        if ($UserProfile.Credentials.Count -eq 0) {throw('There are no credentials to remove')}
        $SelectedCredential = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'Select'
                {
                    Select-OneShellUserProfileCredential -Credential $UserProfile.Credentials -Operation Remove
                }
                'UserName'
                {
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $UserName}
                }
                'Identity'
                {
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $Identity}
                }
            }
        )
        switch ($SelectedCredential.Count)
        {
            0 {throw("Matching credential for value $($Identity;$UserName) not found")}
            1 {}
            default {throw("Multiple credentials with value $($Identity;$UserName) found.")}
        }
        $UserProfile.Credentials = @($UserProfile.Credentials | Where-Object -FilterScript {$_ -ne $SelectedCredential[0]})
        $exportUserProfileParams = @{
            profile     = $UserProfile
            path        = $Path
            ErrorAction = 'Stop'
        }
        Export-OneShellUserProfile @exportUserProfileParams
        #NeededCode:  Remove references to the removed credential from user profile Systems
    }

    }

