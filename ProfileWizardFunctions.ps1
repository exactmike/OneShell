
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
    $AdminUserProfile = GetGenericNewAdminsUserProfileObject -TargetOrgProfile $OrganizationIdentity
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

function Start-AdminUserProfileCredentialEditor
{
    [cmdletbinding(DefaultParameterSetName='New')]
    param(
        [parameter(ParameterSetName='New',Mandatory = $true)]
        [parameter(ParameterSetName='Edit',Mandatory = $true)]
        $systems
        ,
        [parameter(ParameterSetName='Edit')]
        [switch]$edit
        ,
        [parameter(ParameterSetName='Edit',Mandatory = $true)]
        [psobject[]]$Credentials
        ,
        [switch]$UseGUI
    )
    switch ($PSCmdlet.ParameterSetName)
    {
        'Edit' {
            $editableCredentials = @($Credentials | Select-Object -Property @{n='Identity';e={$_.Identity}},@{n='UserName';e={$_.UserName}},@{n='Password';e={$_.Password | ConvertTo-SecureString}})
        }
        'New' {$editableCredentials = @()}
    }
    #$systems = $systems | Where-Object -FilterScript {$_.AuthenticationRequired -eq $null -or $_.AuthenticationRequired -eq $true} #null is for backwards compatibility if the AuthenticationRequired property is missing.
    $labels = $systems | Select-Object -Property @{n='name';e={$_.ServiceType + ': ' + $_.Name}}
    do
    {
        $prompt = GetAdminUserProfileCredentialPrompt -labels $labels -editableCredentials $editableCredentials
        $response = 
            switch ($UseGUI -or $host.Name -notlike 'Console*')
            {
                $true
                {Read-Choice -Message $prompt -Choices 'Add','Edit','Remove','Done' -DefaultChoice 0 -Title 'Add/Edit/Remove Credential'}
                $false
                {Read-PromptForChoice -Message $prompt -Choices 'Add','Edit','Remove','Done' -DefaultChoice 0 -Title 'Add/Edit/Remove Credential'}
            }
        switch ($response)
        {
            0
            {#Add
                $NewCredential = $host.ui.PromptForCredential('Add Credential','Specify the Username and Password for your credential','','')
                if ($NewCredential -is [PSCredential])
                {
                    $NewCredential | Add-Member -MemberType NoteProperty -Name 'Identity' -Value $(New-Guid).guid
                    $editableCredentials += $NewCredential
                }
            }
            1 {#Edit
                if ($editableCredentials.Count -lt 1) {Write-Error -Message 'There are no credentials to edit'}
                else {
                    $CredChoices = @($editableCredentials.UserName)
                    $whichcred = 
                        switch ($UseGUI -or $host.Name -notlike 'Console*')
                        {
                            $true
                            {Read-Choice -Message 'Select a credential to edit' -Choices $CredChoices -DefaultChoice 0 -Title 'Select Credential to Edit'}
                            $false
                            {Read-PromptForChoice -Message 'Select a credential to edit' -Choices $CredChoices -DefaultChoice 0 -Title 'Select Credential to Edit'}
                        }
                    $OriginalCredential = $editableCredentials[$whichcred]
                    $NewCredential = $host.ui.PromptForCredential('Edit Credential','Specify the Username and Password for your credential',$editableCredentials[$whichcred].UserName,'')
                    if ($NewCredential -is [PSCredential])
                    {
                        $NewCredential | Add-Member -MemberType NoteProperty -Name 'Identity' -Value $OriginalCredential.Identity
                        $editableCredentials[$whichcred] = $NewCredential
                    }
                }
            }
            2 {#Remove
                if ($editableCredentials.Count -lt 1) {Write-Error -Message 'There are no credentials to remove'}
                else {
                    $CredChoices = @($editableCredentials.UserName)
                    switch ($UseGUI -or $host.Name -notlike 'Console*')
                    {
                        $true
                        {Read-Choice -Message 'Select a credential to remove' -Choices $CredChoices -DefaultChoice 0 -Title 'Select Credential to Remove'}
                        $false
                        {Read-PromptForChoice -Message 'Select a credential to remove' -Choices $CredChoices -DefaultChoice 0 -Title 'Select Credential to Remove'}
                    }
                    $editableCredentials = @($editableCredentials | Where-Object -FilterScript {$editableCredentials[$whichcred] -ne $_})
                }
                
            }
            3 {$noMoreCreds = $true} #Done
        }
    }
    until ($noMoreCreds -eq $true)
    $exportcredentials = @($editableCredentials | Select-Object -Property @{n='Identity';e={$_.Identity}},@{n='UserName';e={$_.UserName}},@{n='Password';e={$_.Password | ConvertFrom-SecureString}})#,@{n='Systems';e={[string[]]@()}}
    Write-Output -InputObject $exportcredentials
}
function GetAdminUserProfileMenuMessage
{
  param($AdminUserProfile)
  $Message = @"
Oneshell: Admin User Profile Menu

    Identity: $($AdminUserProfile.Identity)
    Host: $($AdminUserProfile.General.Host)
    User: $($AdminUserProfile.General.User)
    Profile Name: $($AdminUserProfile.General.Name)
    Default: $($AdminUserProfile.General.Default)
    Directory: $($AdminUserProfile.General.ProfileFolder)
    Mail From: $($AdminUserProfile.General.MailFrom)
    Credential Count: $($AdminUserProfile.Credentials.Count)
    Credentials:
    $(foreach ($c in $AdminUserProfile.Credentials) {"`t$($c.Username)`r`n"})
    Count of Systems with Associated Credentials: $(@($AdminUserProfile.Systems | Where-Object -FilterScript {$_.credential -ne $null}).count)
    Count of Systems Configured for AutoConnect: $(@($AdminUserProfile.Systems | Where-Object -FilterScript {$_.AutoConnect -eq $true}).count)

"@
  $Message
} #GetAdminUserProfileMenuMessage
function GetAdminUserProfileFolder
{
  Param(
    $InitialDirectory = 'MyComputer'
  )
    if ([string]::IsNullOrEmpty($InitialDirectory)) {$InitialDirectory = 'MyComputer'}
    $message = "Select a location for your admin user profile directory. A sub-directory named 'OneShell' will be created in the selected directory if one does not already exist. The user profile $($env:UserProfile) is the recommended location.  Additionally, under the OneShell directory, sub-directories for Logs, Input, and Export files will be created."
    Do
    {
        $UserChosenPath = Read-FolderBrowserDialog -Description $message -InitialDirectory $InitialDirectory
        if (Test-IsWriteableDirectory -Path $UserChosenPath)
        {
            $ProfileFolderToCreate = Join-Path -Path $UserChosenPath -ChildPath 'OneShell'
            $IsWriteableFilesystemDirectory = $true
        }
    }
    Until
    (
        $IsWriteableFilesystemDirectory
    )
    Write-Output -InputObject $ProfileFolderToCreate
}#function GetAdminUserProfileFolder
function GetAdminUserProfileEmailAddress
{
  [cmdletbinding()]
  param(
    $CurrentEmailAddress
  )
  $ReadInputBoxDialogParams = @{
    Message = 'Specify a valid E-mail address to be associated with this Admin profile for the sending/receiving of email messages.'
    WindowTitle =  'OneShell Admin Profile E-mail Address'
  }
  if ($PSBoundParameters.ContainsKey('CurrentEmailAddress'))
  {
    $ReadInputBoxDialogParams.DefaultText = $CurrentEmailAddress
  } 
  do
  {
    $address = Read-InputBoxDialog @ReadInputBoxDialogParams
  }
  until
  (Test-EmailAddress -EmailAddress $address)
  $address
}
function GetAdminUserProfileMailRelayEndpointToUse
{
  param(
    $OrganizationIdentity
    ,
    $CurrentMailRelayEndpoint
  )
    $systems = @(GetOrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
    $MailRelayEndpoints = @($systems | where-object -FilterScript {$_.SystemType -eq 'MailRelayEndpoints'})
    switch ($MailRelayEndpoints.Count)
  {
    {$_ -gt 1}
    {
          $DefaultChoice = if ($CurrentMailRelayEndpoint -eq $Null) {-1} else {Get-ArrayIndexForValue -array $MailRelayEndpoints -value $CurrentMailRelayEndpoint -property Identity}
      $Message = "Organization Profile $($targetorgprofile.general.name) defines more than one mail relay endpoint.  Which one would you like to use for this Admin profile?"
      $choices = $MailRelayEndpoints | Select-Object -Property @{n='choice';e={$_.Name + '(' + $_.ServiceAddress + ')'}} | Select-Object -ExpandProperty Choice
      $choice = Read-Choice -Message $Message -Choices $choices -DefaultChoice $DefaultChoice -Title 'Select Mail Relay Endpoint'
      $MailRelayEndpointToUse = $MailRelayEndpoints[$choice] | Select-Object -ExpandProperty Identity
    }
    {$_ -eq 1}
    {
      $choice = $MailRelayEndpoints | Select-Object -Property @{n='choice';e={$_.Name + '(' + $_.ServiceAddress + ')'}} | Select-Object -ExpandProperty Choice
      Write-Verbose -Message "Only one Mail Relay Endpoint is defined in Organization Profile $($targetorgprofile.general.name). Setting Mail Relay Endpoint to $choice." -Verbose
      $MailRelayEndpointToUse = $MailRelayEndpoints[0] | Select-Object -ExpandProperty Identity
    }
    {$_ -eq 0}
    {
      Write-Verbose -Message "No Mail Relay Endpoint(s) defined in Organization Profile $($targetorgprofile.general.name)." -Verbose
      $MailRelayEndpointToUse = $null
    }
  }
    Write-Output -InputObject $MailRelayEndpointToUse
}
function GetAdminUserProfileSystemEntries
{
  [cmdletbinding()]
  param(
    $OrganizationIdentity
    ,
    $AdminUserProfile
  )

  $systems = @(GetOrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
  #Preserve existing entries and add any new ones from the Org Profile
  $existingSystemEntriesIdentities = $AdminUserProfile.systems | Select-Object -ExpandProperty Identity
  $OrgProfileSystemEntriesIdentities = $systems | Select-Object -ExpandProperty Identity
  $SystemEntries = @($systems | Where-Object -FilterScript {$_.Identity -notin $existingSystemEntriesIdentities} | ForEach-Object {[pscustomobject]@{'Identity' = $_.Identity;'AutoConnect' = $null;'Credential'=$null}})
  $SystemEntries = @($AdminUserProfile.systems + $SystemEntries)
  #filters out systems that have been removed from the OrgProfile
  $SystemEntries = @($SystemEntries | Where-Object -FilterScript {$_.Identity -in $OrgProfileSystemEntriesIdentities})
  #Build the system labels for use in the read-choice dialog
  $SystemLabels = @(
    foreach ($s in $SystemEntries)
    {
        $system = $systems | Where-Object -FilterScript {$_.Identity -eq $s.Identity}
        "$($system.SystemType):$($system.Name)"
    } 
  ) #| Sort-Object
  $SystemLabels += 'Done'
  $SystemChoicePrompt = 'Configure the systems below for Autoconnect and/or Associated Credentials:'
  $SystemChoiceTitle = 'Configure Systems'
  $SystemsDone = $false
  Do {
    $SystemChoice = Read-Choice -Message $SystemChoicePrompt -Title $SystemChoiceTitle -Choices $SystemLabels -Vertical -Numbered
    if ($SystemLabels[$SystemChoice] -eq 'Done')
    {
        $SystemsDone = $true
    } else
    {
        Do {
            $EditTypePrompt = @"
Edit AutoConnect or Associated Credential for this system: $($SystemLabels[$SystemChoice])
Current Settings
AutoConnect: $($SystemEntries[$SystemChoice].AutoConnect)
Credential: $($AdminUserProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $SystemEntries[$SystemChoice].Credential} | Select-Object -ExpandProperty UserName)
"@
            $EditTypes = 'AutoConnect','Associate Credential','Done'
            $EditTypeChoice = $null
            $EditTypeChoice = Read-Choice -Message $EditTypePrompt -Choices $editTypes -DefaultChoice -1 -Title "Edit System $($SystemLabels[$SystemChoice])"
            switch ($editTypes[$EditTypeChoice])
            {
                'AutoConnect'
                {
                    Write-Verbose -Message 'Running AutoConnect Prompt'
                    $AutoConnectPrompt = "Do you want to Auto Connect to this system: $($SystemLabels[$SystemChoice])?"
                    $DefaultChoice = if ($SystemEntries[$SystemChoice].AutoConnect -eq $true) {0} elseif ($SystemEntries[$SystemChoice].AutoConnect -eq $null) {-1} else {1}
                    $AutoConnectChoice = Read-Choice -Message $AutoConnectPrompt -Choices 'Yes','No' -DefaultChoice $DefaultChoice -Title "AutoConnect System $($SystemLabels[$SystemChoice])?"
                    switch ($AutoConnectChoice)
                    {
                        0
                        {
                            $SystemEntries[$SystemChoice].AutoConnect = $true
                        }
                        1
                        {
                            $SystemEntries[$SystemChoice].AutoConnect = $false
                        }
                    }
                    $EditsDone = $false
                }
                'Associate Credential'
                {
                    if ($AdminUserProfile.Credentials.Count -ge 1)
                    {
                        $CredPrompt = "Which Credential do you want to associate with this system: $($SystemLabels[$SystemChoice])?"
                        $DefaultChoice = if ($SystemEntries[$SystemChoice].Credential -eq $null) {-1} else {Get-ArrayIndexForValue -value $SystemEntries[$SystemChoice].Credential -array $AdminUserProfile.Credentials -property Identity}
                        $CredentialChoice = Read-Choice -Message $CredPrompt -Choices $AdminUserProfile.Credentials.Username -Title "Associate Credential to System $($SystemLabels[$SystemChoice])" -DefaultChoice $DefaultChoice -Vertical
                        $SystemEntries[$SystemChoice].Credential = $AdminUserProfile.Credentials[$CredentialChoice].Identity
                    } else
                    {
                        Write-Error -Message 'No Credentials exist in the Admin User Profile.  Please add one or more credentials.' -Category InvalidData -ErrorId 0
                    }
                    $EditsDone = $false
                }
                'Done'
                {
                    $EditsDone = $true
                }
            }
        }
        Until
        ($EditsDone -eq $true)
    }
  }
  Until
  ($SystemsDone)
  $SystemEntries
}
function GetAdminUserProfileCredentialPrompt
{
    [cmdletbinding()]
    param
    (
        $labels
        ,
        $editableCredentials
    )
$prompt = 
@"
You may associate a credential with each of the following systems for auto connection or on demand connections/usage:

$($labels.name -join "`n")

You have created the following credentials so far:
$($editableCredentials.UserName -join "`n")

In the next step, you may modify the association of these credentials with the systems above.

Would you like to add, edit, or remove a credential?"
"@
    Write-Output -InputObject $prompt
}
function SaveAdminUserProfile
{
[cmdletbinding()]
  param
  (
    $AdminUserProfile
  )
    try
    {
        if (AddAdminUserProfileFolders -AdminUserProfile $AdminUserProfile -path $AdminUserProfile.General.profileFolder -ErrorAction Stop)
        {
            if (Export-AdminUserProfile -profile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.profileFolder)
            {
                if (Get-AdminUserProfile -Identity $AdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $AdminUserProfile.General.profileFolder)
                {
                    Write-Log -Message "New Admin Profile with Name: $($AdminUserProfile.General.Name) and Identity: $($AdminUserProfile.Identity) was successfully saved to $($AdminUserProfile.General.ProfileFolder)." -Verbose -ErrorAction SilentlyContinue -EntryType Notification
                    Write-Log -Message "To initialize the new profile for immediate use, run 'Use-AdminUserProfile -Identity $($AdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue -EntryType Notification
                }
            }
        }
    }
    catch
    {
        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($AdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
    }
}