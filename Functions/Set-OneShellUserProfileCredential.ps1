    Function Set-OneShellUserProfileCredential
    {
        
    [cmdletbinding(DefaultParameterSetName = 'Select')]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [parameter(ParameterSetName = 'Identity', Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'UserName', Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Username
        ,
        [parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string]$NewUsername
        ,
        [parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [securestring]$NewPassword
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
        if ($UserProfile.Credentials.Count -eq 0) {throw('There are no credentials to set')}
        $SelectedCredential = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'Select'
                {
                    Select-OneShellUserProfileCredential -Credential $UserProfile.Credentials -Operation Edit
                }
                'Identity'
                {
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $Identity}
                }
                'Username'
                {
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $UserName}
                }
            }
        )
        switch ($SelectedCredential.Count)
        {
            0 {throw("Matching credential for value $($Identity;$UserName) not found")}
            1 {}
            default {throw("Multiple credentials with value $($Identity;$UserName) found.")}
        }
        $EditedCredential = $(
            switch ($SelectedCredential)
            {
                #Both Username and Password Specified - Update Both
                {$PSBoundParameters.ContainsKey('NewUsername') -and $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($NewUsername, $NewPassword)
                }
                #Only Username Specified - Update Username, Preserve Password
                {$PSBoundParameters.ContainsKey('NewUsername') -and -not $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($NewUsername, $($SelectedCredential.Password | ConvertTo-SecureString))
                }
                #Only Password Specified - Update Password, Preserve Username
                {-not $PSBoundParameters.ContainsKey('NewUsername') -and $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($SelectedCredential.Username, $NewPassword)
                }
                #nothing Specified except Identity - suggest preserving username, prompt to update password
                {-not $PSBoundParameters.ContainsKey('NewUsername') -and -not $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    $host.ui.PromptForCredential('Set Credential', 'Specify the Password for the credential', $SelectedCredential.Username, '')
                }
            }
        )
        if ($null -ne $EditedCredential)
        {
            $UserProfileCredential = Convert-CredentialToUserProfileCredential -credential $EditedCredential -Identity $SelectedCredential.Identity
            $Index = Get-ArrayIndexForValue -array $UserProfile.Credentials -value $SelectedCredential.Identity -property Identity -ErrorAction Stop
            $UserProfile.Credentials[$Index] = $UserProfileCredential
            $exportUserProfileParams = @{
                profile     = $UserProfile
                path        = $Path
                ErrorAction = 'Stop'
            }
            Export-OneShellUserProfile @exportUserProfileParams
        }
    }

    }

