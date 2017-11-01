
##############################
#User Interface
function GetOrgProfileMenuMessage
    {
        param($OrgProfile)
        $Message = 
@"
    Oneshell: Org Profile Menu

        Identity: $($OrgProfile.Identity)
        Profile Name: $($OrgProfile.General.Name)
        Default: $($OrgProfile.General.Default)
"@
        Write-Output -InputObject $Message
    }#End Function GetOrgProfileMenuMessage
function Start-OrgProfileBuilder
    {
        [cmdletbinding()]
        param
        (
            [switch]$Passthru
        )
        Write-Verbose -Message 'NOTICE: This function uses interactive windows/dialogs which may sometimes appear underneath the active window.  If things seem to be locked up, check for a hidden window.' -Verbose
        #Build the basic Org profile object
        $OrgProfile = NewGenericOrgProfileObject
        #Let user configure the profile
        $quit = $false
        $choices = 'Profile Name', 'Set Default','Organization Specific Modules','SharePoint Site','Systems','Save','Save and Quit','Cancel'
        do
        {
            $Message = GetOrgProfileMenuMessage -OrgProfile $OrgProfile
            $UserChoice = Read-Choice -Message $message -Choices $choices -Title 'New Org Profile' -Vertical
            switch ($choices[$UserChoice])
            {
                'Profile Name'
                {
                    $ProfileName = Read-InputBoxDialog -Message 'Configure Org Profile Name' -WindowTitle 'Org Profile Name' -DefaultText $OrgProfile.General.Name
                    if ($ProfileName -ne $OrgProfile.General.Name)
                    {
                        $OrgProfile.General.Name = $ProfileName
                    }
                }
                'Set Default'
                {
                    $DefaultChoice = if ($OrgProfile.General.Default -eq $true) {0} elseif ($OrgProfile.General.Default -eq $null) {-1} else {1}
                    $Default = if ((Read-Choice -Message "Should this Org profile be the default Org profile for $($env:ComputerName)?" -Choices 'Yes','No' -DefaultChoice $DefaultChoice -Title 'Default Profile?') -eq 0) {$true} else {$false}
                    if ($Default -ne $OrgProfile.General.Default)
                    {
                        $OrgProfile.General.Default = $Default
                    }
                }
                'Systems'
                {
                    #code/functions to display/add/edit systems in the OrgProfile
                }
                'Save'
                {
                        Try
                        {
                            #SaveAdminUserProfile -AdminUserProfile $AdminUserProfile
                            #if (Get-AdminUserProfile -Identity $AdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $AdminUserProfile.General.ProfileFolder) {
                            #    Write-Log -Message "Admin Profile with Name: $($AdminUserProfile.General.Name) and Identity: $($AdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                            #    Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($AdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                            #}
                        }
                        Catch {
                            #Write-Log -Message "FAILED: An Admin User Profile operation failed for $($AdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
                            #Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
                        }
                }
                'Save and Quit'
                {
                    #Do the saving stuff from above then
                    $quit = $true
                }
                'Cancel'
                {
                    $quit = $true
                }
            }
        }
        until ($quit)
        #return the admin profile raw object to the pipeline
        if ($passthru) {Write-Output -InputObject $OrgProfile}
    }#End Function Start-OrgProfileBuilder
function Start-AdminUserProfileBuilder
{
    Write-Verbose -Message 'NOTICE: This function uses interactive windows/dialogs which may sometimes appear underneath the active window.  If things seem to be locked up, check for a hidden window.' -Verbose
    #Build the basic Admin profile object
    $AdminUserProfile = GetGenericNewAdminsUserProfileObject -OrganizationIdentity $OrganizationIdentity
    #Let user configure the profile
    $quit = $false
    $choices = 'Profile Name', 'Set Default', 'Profile Directory','Mail From Email Address','Mail Relay Endpoint','Credentials','Systems','Save','Save and Quit','Cancel'
    do
    {
        $Message = GetAdminUserProfileMenuMessage -AdminUserProfile $AdminUserProfile
        $UserChoice = Read-Choice -Message $message -Choices $choices -Title 'New Admin User Profile' -Vertical
        switch ($choices[$UserChoice])
        {
            'Profile Name'
            {
                $ProfileName = Read-InputBoxDialog -Message 'Configure Admin Profile Name' -WindowTitle 'Admin Profile Name' -DefaultText $AdminUserProfile.General.Name
                if ($ProfileName -ne $AdminUserProfile.General.Name)
                {
                    $AdminUserProfile.General.Name = $ProfileName
                }
            }
            'Set Default'
            {
                $DefaultChoice = if ($AdminUserProfile.General.Default -eq $true) {0} elseif ($AdminUserProfile.General.Default -eq $null) {-1} else {1}
                $Default = if ((Read-Choice -Message "Should this admin profile be the default admin profile for Organization Profile $($targetorgprofile.general.name)?" -Choices 'Yes','No' -DefaultChoice $DefaultChoice -Title 'Default Profile?') -eq 0) {$true} else {$false}
                if ($Default -ne $AdminUserProfile.General.Default)
                {
                    $AdminUserProfile.General.Default = $Default
                }
            }
            'Profile Directory'
            {
                if (-not [string]::IsNullOrEmpty($AdminUserProfile.General.ProfileFolder))
                {
                    $InitialDirectory = Split-Path -Path $AdminUserProfile.General.ProfileFolder
                    $ProfileDirectory = GetAdminUserProfileFolder -InitialDirectory $InitialDirectory
                } else 
                {
                    $ProfileDirectory = GetAdminUserProfileFolder
                }
                if ($ProfileDirectory -ne $AdminUserProfile.General.ProfileFolder)
                {
                    $AdminUserProfile.General.ProfileFolder = $ProfileDirectory
                }
            }
            'Mail From Email Address'
            {
                $MailFromEmailAddress = GetAdminUserProfileEmailAddress -CurrentEmailAddress $AdminUserProfile.General.MailFrom
                if ($MailFromEmailAddress -ne $AdminUserProfile.General.MailFrom)
                {
                    $AdminUserProfile.General.MailFrom = $MailFromEmailAddress
                }
            }
            'Mail Relay Endpoint'
            {
                $MailRelayEndpointToUse = GetAdminUserProfileMailRelayEndpointToUse -OrganizationIdentity $OrganizationIdentity -CurrentMailRelayEndpoint $AdminUserProfile.General.MailRelayEndpointToUse
                if ($MailRelayEndpointToUse -ne $AdminUserProfile.General.MailRelayEndpointToUse)
                {
                    $AdminUserProfile.General.MailRelayEndpointToUse = $MailRelayEndpointToUse
                }
            }
            'Credentials'
            {
                $systems = @(GetOrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
                if ($AdminUserProfile.Credentials.Count -ge 1)
                {
                    $exportcredentials = @(SetAdminUserProfileCredentials -systems $systems -edit -Credentials $AdminUserProfile.Credentials)
                }
                else
                {
                    $exportcredentials = @(SetAdminUserProfileCredentials -systems $systems)
                }
                $AdminUserProfile.Credentials = $exportcredentials
            }
            'Systems'
            {
                $AdminUserProfile.Systems = GetAdminUserProfileSystemEntries -OrganizationIdentity $OrganizationIdentity -AdminUserProfile $AdminUserProfile
            }
            'Save'
            {
                if ($AdminUserProfile.General.ProfileFolder -eq '')
                {
                    Write-Error -Message 'Unable to save Admin Profile.  Please set a profile directory.'
                }
                else
                {
                    Try
                    {
                        AddAdminUserProfileFolders -AdminUserProfile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.ProfileFolder
                        SaveAdminUserProfile -AdminUserProfile $AdminUserProfile
                        if (Get-AdminUserProfile -Identity $AdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $AdminUserProfile.General.ProfileFolder) {
                            Write-Log -Message "Admin Profile with Name: $($AdminUserProfile.General.Name) and Identity: $($AdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                            Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($AdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                        }
                    }
                    Catch {
                        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($AdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
                        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
                    }
                }
            }
            'Save and Quit'
            {
                if ($AdminUserProfile.General.ProfileFolder -eq '')
                {
                    Write-Error -Message 'Unable to save Admin Profile.  Please set a profile directory.'
                }
                else
                {
                    Try
                    {
                        AddAdminUserProfileFolders -AdminUserProfile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.ProfileFolder
                        SaveAdminUserProfile -AdminUserProfile $AdminUserProfile
                        if (Get-AdminUserProfile -Identity $AdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $AdminUserProfile.General.ProfileFolder) {
                            Write-Log -Message "Admin Profile with Name: $($AdminUserProfile.General.Name) and Identity: $($AdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                            Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($AdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                        }
                    }
                    Catch {
                        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($AdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
                        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
                    }
                    $quit = $true
                }
            }
            'Cancel'
            {
                $quit = $true
            }
        }
    }
    until ($quit)
    #return the admin profile raw object to the pipeline
    if ($passthru) {Write-Output -InputObject $AdminUserProfile}
}
function Start-AdminUserProfileEditor
{
    [cmdletbinding(DefaultParameterSetName="Default")]
    param
    (
        [Parameter(ParameterSetName = 'Object',ValueFromPipeline,Mandatory)]
        [ValidateScript({$_.ProfileType -eq 'OneShellAdminUserProfile'})]
        [psobject]$ProfileObject 
        ,
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'Name')]
        [ValidateScript({Test-DirectoryPath -Path $_})]
        [string[]]$Path = "$env:UserProfile\OneShell\"
        ,
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'Name')]
        [switch]$Passthru
    )
    DynamicParam
    {
        if ($null -eq $Path)
        {
            $path = "$env:UserProfile\OneShell\"
        }
        $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String[]]) -ValidateSet @(GetPotentialAdminUserProfiles -path $Path | Select-Object -ExpandProperty Identity) -ParameterSetName Identity -Mandatory $true
        $dictionary = New-DynamicParameter -Name 'Name' -Type $([String[]]) -ValidateSet @(GetPotentialAdminUserProfiles -path $Path | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue) -Mandatory $true -ParameterSetName Name -DPDictionary $dictionary 
        Write-Output -InputObject $dictionary
    }
    Process
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        switch ($PSCmdlet.ParameterSetName)
        {
            'Object'
            {
                #validate the object
                $AdminUserProfile = $ProfileObject
            }
            'Identity'
            {
                $GetAdminUserProfileParams = @{
                    Identity = $Identity
                }
                if ($PSBoundParameters.ContainsKey('Path'))
                {
                    $GetAdminUserProfileParams.Path = $Path
                }
                $AdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
            }
            'Name'
            {
                $GetAdminUserProfileParams = @{
                    Name = $Name
                }
                if ($PSBoundParameters.ContainsKey('Path'))
                {
                    $GetAdminUserProfileParams.Path = $Path
                }
                $AdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
            }
            'Default'
            {
                $GetAdminUserProfileParams = @{
                    GetDefault = $Name
                }
                $AdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
            }
        }#end switch ParameterSetName
        $OrganizationIdentity = $AdminUserProfile.Organization.Identity
        $targetOrgProfile = @(Get-OrgProfile -Identity $OrganizationIdentity -Verbose)
        #Check the Org Identity for validity (exists, not ambiguous)
        switch ($targetOrgProfile.Count)
        {
            1
            {

            }
            0
            {
                $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $OrganizationIdentity -Message "No matching Organization Profile was found for identity $OrganizationIdentity"
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
            Default
            {
                $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $OrganizationIdentity -Message "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }
        #Update the Admin User Profile if necessary
        $AdminUserProfile = UpdateAdminUserProfileObjectVersion -AdminUserProfile $AdminUserProfile
        Write-Verbose -Message 'NOTICE: This function uses interactive windows/dialogs which may sometimes appear underneath the active window.  If things seem to be locked up, check for a hidden window.' -Verbose
        #Let user configure the profile
        $quit = $false
        $choices = 'Profile Name', 'Set Default', 'Profile Directory','Mail From Email Address','Mail Relay Endpoint','Credentials','Systems','Save','Save and Quit','Cancel'
        do
        {
            $Message = GetAdminUserProfileMenuMessage -AdminUserProfile $AdminUserProfile
            $UserChoice = Read-Choice -Message $message -Choices $choices -Title 'Edit Admin User Profile' -Vertical
            switch ($choices[$UserChoice])
            {
                'Profile Name'
                {
                    $ProfileName = Read-InputBoxDialog -Message 'Configure Admin Profile Name' -WindowTitle 'Admin Profile Name' -DefaultText $AdminUserProfile.General.Name
                    if ($ProfileName -ne $AdminUserProfile.General.Name)
                    {
                        $AdminUserProfile.General.Name = $ProfileName
                    }
                }
                'Set Default'
                {
                    $DefaultChoice = if ($AdminUserProfile.General.Default -eq $true) {0} elseif ($AdminUserProfile.General.Default -eq $null) {-1} else {1}
                    $Default = if ((Read-Choice -Message "Should this admin profile be the default admin profile for Organization Profile $($targetorgprofile.general.name)?" -Choices 'Yes','No' -DefaultChoice $DefaultChoice -Title 'Default Profile?') -eq 0) {$true} else {$false}
                    if ($Default -ne $AdminUserProfile.General.Default)
                    {
                        $AdminUserProfile.General.Default = $Default
                    }
                }
                'Profile Directory'
                {
                    if (-not [string]::IsNullOrEmpty($AdminUserProfile.General.ProfileFolder))
                    {
                        $InitialDirectory = Split-Path -Path $AdminUserProfile.General.ProfileFolder
                        $ProfileDirectory = GetAdminUserProfileFolder -InitialDirectory $InitialDirectory
                    } else 
                    {
                        $ProfileDirectory = GetAdminUserProfileFolder
                    }
                    if ($ProfileDirectory -ne $AdminUserProfile.General.ProfileFolder)
                    {
                        $AdminUserProfile.General.ProfileFolder = $ProfileDirectory
                    }
                }
                'Mail From Email Address'
                {
                    $MailFromEmailAddress = GetAdminUserProfileEmailAddress -CurrentEmailAddress $AdminUserProfile.General.MailFrom
                    if ($MailFromEmailAddress -ne $AdminUserProfile.General.MailFrom)
                    {
                        $AdminUserProfile.General.MailFrom = $MailFromEmailAddress
                    }
                }
                'Mail Relay Endpoint'
                {
                    $MailRelayEndpointToUse = GetAdminUserProfileMailRelayEndpointToUse -OrganizationIdentity $OrganizationIdentity -CurrentMailRelayEndpoint $AdminUserProfile.General.MailRelayEndpointToUse
                    if ($MailRelayEndpointToUse -ne $AdminUserProfile.General.MailRelayEndpointToUse)
                    {
                        $AdminUserProfile.General.MailRelayEndpointToUse = $MailRelayEndpointToUse
                    }
                }
                'Credentials'
                {
                    $systems = @(GetOrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
                    $exportcredentials = @(SetAdminUserProfileCredentials -systems $systems -credentials $AdminUserProfile.Credentials -edit)
                    $AdminUserProfile.Credentials = $exportcredentials
                }
                'Systems'
                {
                    $AdminUserProfile.Systems = GetAdminUserProfileSystemEntries -OrganizationIdentity $OrganizationIdentity -AdminUserProfile $AdminUserProfile
                } 
                'Save'
                {
                    if ($AdminUserProfile.General.ProfileFolder -eq '')
                    {
                        Write-Error -Message 'Unable to save Admin Profile.  Please set a profile directory.'
                    }
                    else
                    {
                        Try
                        {
                            AddAdminUserProfileFolders -AdminUserProfile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.ProfileFolder
                            SaveAdminUserProfile -AdminUserProfile $AdminUserProfile
                            if (Get-AdminUserProfile -Identity $AdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $AdminUserProfile.General.ProfileFolder) {
                                Write-Log -Message "Admin Profile with Name: $($AdminUserProfile.General.Name) and Identity: $($AdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                                Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($AdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                            }
                        }
                        Catch {
                            Write-Log -Message "FAILED: An Admin User Profile operation failed for $($AdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
                            Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
                        }
                    }
                }
                'Save and Quit'
                {
                    if ($AdminUserProfile.General.ProfileFolder -eq '')
                    {
                        Write-Error -Message 'Unable to save Admin Profile.  Please set a profile directory.'
                    }
                    else
                    {
                        Try
                        {
                            AddAdminUserProfileFolders -AdminUserProfile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.ProfileFolder
                            SaveAdminUserProfile -AdminUserProfile $AdminUserProfile -ErrorAction Stop
                            if (Get-AdminUserProfile -Identity $AdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $AdminUserProfile.General.ProfileFolder) {
                                Write-Log -Message "Admin Profile with Name: $($AdminUserProfile.General.Name) and Identity: $($AdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                                Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($AdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                            }
                        }
                        Catch {
                            Write-Log -Message "FAILED: An Admin User Profile operation failed for $($AdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
                            Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
                        }
                        $quit = $true
                    }
                }
                'Cancel'
                {
                    $quit = $true
                }
            }
        }
        until ($quit)
        #return the admin profile raw object to the pipeline
        if ($passthru) {Write-Output -InputObject $AdminUserProfile}
    }#Process
}# Set-AdminUserProfile


