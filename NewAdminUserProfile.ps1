function New-AdminUserProfile
{
[cmdletbinding()]
param
(
    [parameter(Mandatory)]
    [string]$OrganizationIdentity
    ,
    [string]$name
)
    $targetOrgProfile = @(Get-OrgProfile -Identity $OrganizationIdentity -raw)
    switch ($targetOrgProfile.Count)
    {
        1 {}
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
    Write-Verbose -Message 'NOTICE: This function uses interactive windows/dialogs which may sometimes appear underneath the active window.  If things seem to be locked up, check for a hidden window.' -Verbose
    #Build the basic Admin profile object
    $newAdminUserProfile = [ordered]@{
        Identity = [guid]::NewGuid()
        ProfileType = 'OneShellAdminUserProfile'
        General = [ordered]@{
            Name = if ($name) {"$name-" + $targetOrgProfile.general.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME} else {$targetOrgProfile.general.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME}
            Host = $env:COMPUTERNAME
            OrganizationIdentity = $targetOrgProfile.identity
            ProfileFolder = GetAdminUserProfileFolder
            Default = if ((Read-Choice -Message "Should this be the default profile for Organization Profile $($targetorgprofile.general.name)?" -Choices 'Yes','No' -DefaultChoice 1 -Title 'Default Profile?') -eq 0) {$true} else {$false}
        }
        Systems = @()
        Credentials = @()
    }
    #Set the required profile items
    $RequiredValues = @('ProfileDirectory')
    $quit = $false
    $choices = 'Profile Name','Profile Directory','Mail From Email Address','Mail Relay Endpoint','Credentials','Systems'
    do
    {
        $UserChoice = Read-Choice -Message 'New Admin User Profile Menu' -Choices $choices -Title 'New Admin User Profile'
        switch ($choices[$UserChoice])
        {
            'Profile Name'
            {
                $ProfileName = Read-InputBoxDialog -Message 'Configure Admin Profile Name' -WindowTitle 'Admin Profile Name' -DefaultText $newAdminUserProfile.General.Name
                if ($ProfileName -ne $newAdminUserProfile.General.Name)
                {
                    $newAdminUserProfile.General.Name = $ProfileName
                }
            }

        }
    }
    until ($quit)
    #Get the Admin user's email address
    $newAdminUserProfile.General.MailFrom = GetAdminUserProfileEmailAddress
    #Get Org Profile Defined Systems
    $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
    #Select the mail relay endpoint for the profile to use
    $MailRelayEndpoints = @($systems | where-object -FilterScript {$_.SystemType -eq 'MailRelayEndpoints'})
    if ($MailRelayEndpoints.Count -gt 1)
    {
        $Message = "Organization Profile $($targetorgprofile.general.name) defines more than one mail relay endpoint.  Which one would you like to use for this Admin profile?"
        $choices = $MailRelayEndpoints | Select-Object -Property @{n='choice';e={$_.Name + '(' + $_.ServiceAddress + ')'}} | Select-Object -ExpandProperty Choice
        $choice = Read-Choice -Message $Message -Choices $choices -DefaultChoice 1 -Title "Select Mail Relay Endpoint"
        $MailRelayEndpointToUse = $MailRelayEndpoints[$choice] | Select-Object -ExpandProperty Identity
    }
    else
    {
        $MailRelayEndpointToUse = $MailRelayEndpoints[0] | Select-Object -ExpandProperty Identity
    }
    $newAdminUserProfile.General.MailRelayEndpointToUse = $MailRelayEndpointToUse
    #Get the admin User's Credentials
    $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems)
    #Prepare Stored Credentials to associate with one or more systems
    :SysCredAssociation foreach ($sys in $systems) #using the label just to make the use of Continue explicit in the code below
    {
        if ($sys.AuthenticationRequired -eq $false) {Continue SysCredAssociation}
        if ($sys.SystemType -eq 'MailRelayEndpoints')
        {
            if ($sys.Identity -eq $MailRelayEndpointToUse) {$autoConnectChoice = 1}
            else {Continue SysCredAssociation}
        }
        else
        {
            $label = $sys | Select-Object @{n='name';e={$_.SystemType + ': ' + $_.Name}} | Select-Object -ExpandProperty Name
            $prompt = "Do you want to Auto Connect to this system with this admin profile: `n`n$label"
            $autoConnectChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -DefaultChoice 0 -Title 'Auto Connect?'
        }
        switch ($autoConnectChoice) {
            0 {
                $SystemEntry = [ordered]@{'Identity' = $sys.Identity;'Autoconnect' = $true}
                $newAdminUserProfile.Systems += $SystemEntry
                #associate a credential with the autoconnect system
                $prompt = "Which Credential do you want to associate with this system: `n`n$label"
                $choice = Read-Choice -Message $prompt -Choices $exportcredentials.Username -Title "Associate Credential:$label" -DefaultChoice 0
                [array]$currentAssociatedSystems = @($exportcredentials[$choice].Systems)
                $currentAssociatedSystems += $sys.Identity
                $exportcredentials[$choice].Systems = $currentAssociatedSystems
            }
            1 {
                $SystemEntry = [ordered]@{'Identity' = $sys.Identity;'Autoconnect' = $false}
                $newAdminUserProfile.Systems += $SystemEntry
                #ask if user still wants to associate a credential
                $prompt = "Do you want to associate a credential for on demand connections to this system: `n`n$label"
                $AssociateOnDemandCredentialChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -Title "Associate Credential:$label" -DefaultChoice 1
                switch ($AssociateOnDemandCredentialChoice) {
                    0 {
                        #associate a credential with the non-autoconnect system for on demand connections via profile
                        $prompt = "Which Credential do you want to associate with this system: `n`n$label"
                        $choice = Read-Choice -Message $prompt -Choices $exportcredentials.Username -Title "Associate Credential:$label" -DefaultChoice 0
                        [array]$currentAssociatedSystems = @($exportcredentials[$choice].Systems)
                        $currentAssociatedSystems += $sys.Identity
                        $exportcredentials[$choice].Systems = $currentAssociatedSystems
                    }
                    1 {}
                }
            }
        }
        Remove-Variable -Name SystemEntry
    }
    #add the stored and system associated credentials to the profile
    $newAdminUserProfile.Credentials = @($exportcredentials)
    #if necessary, create the Admin Profile File System Folders and export the JSON profile file
    try
    {
        if (Add-AdminUserProfileFolders -AdminUserProfile $newAdminUserProfile -path $newAdminUserProfile.General.profileFolder -ErrorAction Stop)
        {
            if (Export-AdminUserProfile -profile $newAdminUserProfile -ErrorAction Stop -path $newAdminUserProfile.General.profileFolder)
            {
                if (Get-AdminUserProfile -Identity $newAdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $newAdminUserProfile.General.profileFolder)
                {
                    Write-Log -Message "New Admin Profile with Name: $($newAdminUserProfile.General.Name) and Identity: $($newAdminUserProfile.Identity) was successfully configured, exported, and imported." -Verbose -ErrorAction SilentlyContinue -EntryType Notification
                    Write-Log -Message "To initialize the new profile for immediate use, run 'Use-AdminUserProfile -Identity $($newAdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue -EntryType Notification
                }
            }
        }
    }
    catch
    {
        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($newAdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
    }
    #return the admin profile raw object to the pipeline
    Write-Output $newAdminUserProfile
}# New-AdminUserProfile