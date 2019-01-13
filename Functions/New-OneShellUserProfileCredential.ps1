    Function New-OneShellUserProfileCredential
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Username
        ,
        [parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [securestring]$Password
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
    )#end param
    End
    {
        #Get/Select the Profile
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellUserProfilePath}
        $puProfiles = GetPotentialUserProfiles -path $Path
        $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $puProfiles -Identity $ProfileIdentity -Operation Edit
        $NewCredential = $(
            switch ($PSBoundParameters.ContainsKey('Username'))
            {
                $true
                {
                    switch ($PSBoundParameters.ContainsKey('Password'))
                    {
                        $true
                        {
                            New-Object System.Management.Automation.PSCredential ($Username, $Password)
                        }
                        $false
                        {
                            $host.ui.PromptForCredential('New Credential', 'Specify the Password for the credential', $Username, '')
                        }
                    }
                }
                $false
                {
                    $host.ui.PromptForCredential('New Credential', 'Specify the Username and Password for the credential', '', '')
                }
            }
        )
        if ($NewCredential -is [PSCredential])
        {
            $UserProfileCredential = Convert-CredentialToUserProfileCredential -credential $NewCredential
            $UserProfile.Credentials += $UserProfileCredential
            $exportUserProfileParams = @{
                profile     = $UserProfile
                path        = $Path
                ErrorAction = 'Stop'
            }
            Export-OneShellUserProfile @exportUserProfileParams
        }
    }

    }

