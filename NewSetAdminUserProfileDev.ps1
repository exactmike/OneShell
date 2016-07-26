function New-AdminUserProfile
{
[cmdletbinding()]
param
(
    [parameter(Mandatory)]
    [string]$OrganizationIdentity
    ,
    [switch]$Passthru
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
        ProfileTypeVersion = 1.0
        General = [ordered]@{
            Name = $targetOrgProfile.general.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME
            Host = $env:COMPUTERNAME
            User = $env:USERNAME
            OrganizationIdentity = $targetOrgProfile.identity
            ProfileFolder = ''
            MailFrom = ''
            MailRelayEndpointToUse = ''
            Default = $false
        }
        Systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity) | ForEach-Object {[pscustomobject]@{'Identity' = $_.Identity;'AutoConnect' = $null;'Credential'=$null}}
        Credentials = @()
    }
    #Set the required profile items
    $RequiredValues = @('ProfileDirectory')
    $quit = $false
    $choices = 'Profile Name', 'Set Default', 'Profile Directory','Mail From Email Address','Mail Relay Endpoint','Credentials','Systems','Save','Save and Quit','Cancel'
    do
    {
        $Message = @"
Oneshell: New Admin User Profile Menu

    Identity: $($newAdminUserProfile.Identity)
    Host: $($newAdminUserProfile.General.Host)
    Profile Name: $($newAdminUserProfile.General.Name)
    Default: $($newAdminUserProfile.General.Default)
    Directory: $($newAdminUserProfile.General.ProfileFolder)
    Mail From: $($newAdminUserProfile.General.MailFrom)
    Credential Count: $($newAdminUserProfile.Credentials.Count)
    Credentials:
    $(foreach ($c in $newAdminUserProfile.Credentials) {"`t$($c.Username)`r`n"})
    Count of Systems with Associated Credentials: $(@($newAdminUserProfile.Systems | Where-Object {$_.credential -ne $null}).count)
    Count of Systems Configured for AutoConnect: $(@($newAdminUserProfile.Systems | Where-Object {$_.AutoConnect -eq $true}).count)

"@
        $UserChoice = Read-Choice -Message $message -Choices $choices -Title 'New Admin User Profile' -Vertical
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
            'Set Default'
            {
                $DefaultChoice = if ($newAdminUserProfile.General.Default -eq $true) {0} elseif ($newAdminUserProfile.General.Default -eq $null) {-1} else {1}
                $Default = if ((Read-Choice -Message "Should this admin profile be the default admin profile for Organization Profile $($targetorgprofile.general.name)?" -Choices 'Yes','No' -DefaultChoice $DefaultChoice -Title 'Default Profile?') -eq 0) {$true} else {$false}
                if ($Default -ne $newAdminUserProfile.General.Default)
                {
                    $newAdminUserProfile.General.Default = $Default
                }
            }
            'Profile Directory'
            {
                if (-not [string]::IsNullOrEmpty($newAdminUserProfile.General.ProfileFolder))
                {
                    $InitialDirectory = Split-Path $newAdminUserProfile.General.ProfileFolder
                    $ProfileDirectory = GetAdminUserProfileFolder -InitialDirectory $InitialDirectory
                } else 
                {
                    $ProfileDirectory = GetAdminUserProfileFolder
                }
                if ($ProfileDirectory -ne $newAdminUserProfile.General.ProfileFolder)
                {
                    $newAdminUserProfile.General.ProfileFolder = $ProfileDirectory
                }
            }
            'Mail From Email Address'
            {
                $MailFromEmailAddress = GetAdminUserProfileEmailAddress -CurrentEmailAddress $newAdminUserProfile.General.MailFrom
                if ($MailFromEmailAddress -ne $newAdminUserProfile.General.MailFrom)
                {
                    $newAdminUserProfile.General.MailFrom = $MailFromEmailAddress
                }
            }
            'Mail Relay Endpoint'
            {
                $MailRelayEndpointToUse = GetAdminUserProfileMailRelayEndpointToUse -OrganizationIdentity $OrganizationIdentity -CurrentMailRelayEndpoint $newAdminUserProfile.General.MailRelayEndpointToUse
                if ($MailRelayEndpointToUse -ne $newAdminUserProfile.General.MailRelayEndpointToUse)
                {
                    $newAdminUserProfile.General.MailRelayEndpointToUse = $MailRelayEndpointToUse
                }
            }
            'Credentials'
            {
                $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
                $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems)
                $newAdminUserProfile.Credentials = $exportcredentials
            }
            'Systems'
            {
                $newAdminUserProfile.Systems = GetAdminUserProfileSystemEntries -existingSystemEntries $newAdminUserProfile.Systems -OrganizationIdentity $OrganizationIdentity
            }
            'Save'
            {
                if ($newAdminUserProfile.General.ProfileFolder -eq '')
                {
                    Write-Error -Message "Unable to save Admin Profile.  Please set a profile directory."
                }
                else
                {
                    Try
                    {
                        Add-AdminUserProfileFolders -AdminUserProfile $newAdminUserProfile -ErrorAction Stop -path $newAdminUserProfile.General.ProfileFolder
                        SaveAdminUserProfile -AdminUserProfile $newAdminUserProfile
                        if (Get-AdminUserProfile -Identity $newAdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $newAdminUserProfile.General.ProfileFolder) {
                            Write-Log -Message "Admin Profile with Name: $($newAdminUserProfile.General.Name) and Identity: $($newAdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                            Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($editAdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                        }
                    }
                    Catch {
                        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($newAdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
                        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
                    }
            }
            'Save and Quit'
            {
                if ($newAdminUserProfile.General.ProfileFolder -eq '')
                {
                    Write-Error -Message "Unable to save Admin Profile.  Please set a profile directory."
                }
                else
                {
                    Add-AdminUserProfileFolders -AdminUserProfile $newAdminUserProfile -ErrorAction Stop -path $newAdminUserProfile.General.ProfileFolder
                    SaveAdminUserProfile -AdminUserProfile $newAdminUserProfile
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
    if ($passthru) {Write-Output $newAdminUserProfile}
}# New-AdminUserProfile
function Set-AdminUserProfile
{
    [cmdletbinding()]
    param(
        [parameter(ParameterSetName = 'Object')]
        [psobject]$profile 
        ,
        [parameter(ParameterSetName = 'Identity',Mandatory = $true)]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript({Test-DirectoryPath -Path $_})]
        [string[]]$Path
        ,
        [switch]$Passthru
    )
    switch ($PSCmdlet.ParameterSetName) {
        'Object' {$editAdminUserProfile = $profile}
        'Identity'
        {
            $GetAdminUserProfileParams = @{
                Identity = $Identity
                Raw = $true
            }
            if ($PSBoundParameters.ContainsKey('Path'))
            {
                $GetAdminUserProfileParams.Path = $Path
            }
            $editAdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
        }
    }
    $OrganizationIdentity = $editAdminUserProfile.General.OrganizationIdentity
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
    #Set Admin Profile to Default or Not Default
    if ($editAdminUserProfile.General.Default) {
        $prompt = "This admin profile is currently the Default Admin Profile.`n`nShould this be the default profile for Organization Profile $($targetorgprofile.general.name)?"
        $defaultChoiceDefault = 0
    }
    else {
        $prompt = "This admin profile is currently NOT the Default Admin Profile.`n`nShould this be the default profile for Organization Profile $($targetorgprofile.general.name)?"
        $defaultChoiceDefault = 1
    }
    $editAdminUserProfile.General.Default = if ((Read-Choice -Message $prompt -Choices 'Yes','No' -DefaultChoice $defaultChoiceDefault -Title 'Default Profile?') -eq 0) {$true} else {$false}
    #Get the Admin user's email address
    if (Test-Member -InputObject $editAdminUserProfile.General -Name MailFrom)
    {
        $currentEmailAddress = $editAdminUserProfile.General.MailFrom
    }
    else
    {
        $editAdminUserProfile.General | Add-Member -MemberType NoteProperty -Name MailFrom -Value $null
    }
    $editAdminUserProfile.General.MailFrom = GetAdminUserProfileEmailAddress -CurrentEmailAddress $currentEmailAddress
    #Get Org Profile Defined Systems
    $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
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
    if (-not (Test-Member -InputObject $editAdminUserProfile.General -Name MailRelayEndpointToUse))
    {
        $editAdminUserProfile.General | Add-Member -MemberType NoteProperty -Name MailRelayEndpointToUse -Value $MailRelayEndpointToUse
    }
    $editAdminUserProfile.General.MailRelayEndpointToUse = $MailRelayEndpointToUse
    #Get User's Credentials
    $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems -credentials $editAdminUserProfile.Credentials -edit)
    #Prepare Stored Credentials to associate with one or more systems
    $exportcredentials | foreach {$_.systems=@()}
    #Prepare Edited System Entries variable:
    $EditedSystemEntries = @()
    :SysCredAssociation foreach ($sys in $systems) {
        if ($sys.AuthenticationRequired -eq $false) {Continue SysCredAssociation}
        if ($sys.SystemType -eq 'MailRelayEndpoints')
        {
            if ($sys.Identity -eq $MailRelayEndpointToUse) {$autoConnectChoice = 1}
        }
        else
        {
            $label = $sys | Select-Object @{n='name';e={$_.SystemType + ': ' + $_.Name}} | Select-Object -ExpandProperty Name
            $currentAutoConnect = $editAdminUserProfile.Systems | Where-Object -FilterScript {$_.Identity -eq $Sys.Identity} | Foreach-Object {$_.Autoconnect}
            [string]$currentCredential = $editAdminUserProfile.Credentials | Where-Object -FilterScript {$_.systems-contains $sys.Identity} | Foreach-Object {$_.UserName}
            switch ($currentAutoConnect) {
                $true {
                    $prompt = "This system currently is set to Auto Connect in this profile.`n`nDo you want to Auto Connect to this system with this admin profile? `n`n$label"
                    $DefaultChoiceAC = 0
                }
                $false {
                    $prompt = "This system currently is NOT set to Auto Connect in this profile.`n`nDo you want to Auto Connect to this system with this admin profile? `n`n$label"
                    $DefaultChoiceAC = 1
                }
                Default {
                    $prompt = "Do you want to Auto Connect to this system with this admin profile? `n`n$label"
                    $DefaultChoiceAC = -1
                }
            }
            $autoConnectChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -DefaultChoice $DefaultChoiceAC -Title 'Auto Connect?'
        }
        switch ($autoConnectChoice) {
            0 {
                $SystemEntry = [ordered]@{'Identity' = $sys.Identity;'Autoconnect' = $true}
                $EditedSystemEntries += $SystemEntry
                #associate a credential with the autoconnect system
                if (-not [string]::IsNullOrWhiteSpace($currentCredential)) {
                    $prompt = "This system is currently configured to use Credential: $currentCredential`n`nWhich Credential do you want to associate with this system: `n`n$label"
                    $defaultchoicecred = Get-ArrayIndexForValue -array $exportcredentials -value $currentCredential -property UserName
                }#if
                else {
                    $defaultchoicecred = -1
                    $prompt = "Which Credential do you want to associate with this system: `n`n$label"
                }
                $choice = Read-Choice -Message $prompt -Choices $exportcredentials.Username -Title "Associate Credential:$label" -DefaultChoice $defaultchoicecred
                [array]$currentAssociatedSystems = @($exportcredentials[$choice].Systems)
                $currentAssociatedSystems += $sys.Identity
                $exportcredentials[$choice].Systems = $currentAssociatedSystems
            }
            1 {
                $SystemEntry = [ordered]@{'Identity' = $sys.Identity;'Autoconnect' = $false}
                $EditedSystemEntries += $SystemEntry
                #ask if user still wants to associate a credential
                $prompt = "Do you want to associate a credential for on demand connections to this system: `n`n$label"
                $AssociateOnDemandCredentialChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -Title "Associate Credential:$label" -DefaultChoice 1
                switch ($AssociateOnDemandCredentialChoice) {
                    0 {
                        #associate a credential with the autoconnect system
                        if (-not [string]::IsNullOrWhiteSpace($currentCredential)) {
                            $prompt = "This system is currently configured to use Credential: $currentCredential`n`nWhich Credential do you want to associate with this system: `n`n$label"                
                            $defaultchoicecred = Get-ArrayIndexForValue -array $exportcredentials -value $currentCredential -property UserName
                        }#if
                        else {
                            $defaultchoicecred = -1                
                            $prompt = "Which Credential do you want to associate with this system: `n`n$label"
                        }
                        $choice = Read-Choice -Message $prompt -Choices $exportcredentials.Username -Title "Associate Credential:$label" -DefaultChoice $defaultchoicecred
                        [string[]]$currentAssociatedSystems = @($exportcredentials[$choice].Systems)
                        $currentAssociatedSystems += $sys.Identity
                        $exportcredentials[$choice].Systems = $currentAssociatedSystems
                    }
                    1 {}
                }
            }
        }
        Remove-Variable -Name SystemEntry
    }
    $editAdminUserProfile.Credentials = @($exportcredentials)
    $editAdminUserProfile.Systems = $EditedSystemEntries
    #<#
    try {
        if (Add-AdminUserProfileFolders -AdminUserProfile $editAdminUserProfile -ErrorAction Stop -path $editAdminUserProfile.General.ProfileFolder) {
            if (Export-AdminUserProfile -profile $editAdminUserProfile -ErrorAction Stop -path $editAdminUserProfile.General.ProfileFolder) {
                if (Get-AdminUserProfile -Identity $editAdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $editAdminUserProfile.General.ProfileFolder) {
                    Write-Log -Message "Edited Admin Profile with Name: $($editAdminUserProfile.General.Name) and Identity: $($editAdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                    Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($editAdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                }
            }
        }
        $editAdminUserProfile    
    }
    catch {
        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($editAdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
    }
    ##>
}# Set-AdminUserProfile