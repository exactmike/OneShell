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
    $AdminUserProfile = GetGenericNewAdminsUserProfileObject
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
                    $InitialDirectory = Split-Path $AdminUserProfile.General.ProfileFolder
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
                $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
                $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems)
                $AdminUserProfile.Credentials = $exportcredentials
            }
            'Systems'
            {
                $AdminUserProfile.Systems = GetAdminUserProfileSystemEntries -existingSystemEntries $AdminUserProfile.Systems -OrganizationIdentity $OrganizationIdentity -AdminProfile $AdminProfile
            }
            'Save'
            {
                if ($AdminUserProfile.General.ProfileFolder -eq '')
                {
                    Write-Error -Message "Unable to save Admin Profile.  Please set a profile directory."
                }
                else
                {
                    Try
                    {
                        Add-AdminUserProfileFolders -AdminUserProfile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.ProfileFolder
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
                    Write-Error -Message "Unable to save Admin Profile.  Please set a profile directory."
                }
                else
                {
                    Try
                    {
                        Add-AdminUserProfileFolders -AdminUserProfile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.ProfileFolder
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
    if ($passthru) {Write-Output $AdminUserProfile}
} #New-AdminUserProfile
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
    'Object' {$AdminUserProfile = $profile}
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
        $AdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
    }
}
$OrganizationIdentity = $AdminUserProfile.General.OrganizationIdentity
$targetOrgProfile = @(Get-OrgProfile -Identity $OrganizationIdentity -raw)
#Check the Org Identity for validity (exists, not ambiguous)
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
#Update the Admin User Profile if necessary
$AdminUserProfile = UpdateAdminUserProfileObjectVersion -AdminUserProfile $AdminUserProfile
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
                    $InitialDirectory = Split-Path $AdminUserProfile.General.ProfileFolder
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
                $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
                $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems -credentials $AdminUserProfile.Credentials -edit)
                $AdminUserProfile.Credentials = $exportcredentials
            }
            'Systems'
            {
                $AdminUserProfile.Systems = GetAdminUserProfileSystemEntries -existingSystemEntries $AdminUserProfile.Systems -OrganizationIdentity $OrganizationIdentity
            }
            'Save'
            {
                if ($AdminUserProfile.General.ProfileFolder -eq '')
                {
                    Write-Error -Message "Unable to save Admin Profile.  Please set a profile directory."
                }
                else
                {
                    Try
                    {
                        Add-AdminUserProfileFolders -AdminUserProfile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.ProfileFolder
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
                    Write-Error -Message "Unable to save Admin Profile.  Please set a profile directory."
                }
                else
                {
                    Try
                    {
                        Add-AdminUserProfileFolders -AdminUserProfile $AdminUserProfile -ErrorAction Stop -path $AdminUserProfile.General.ProfileFolder
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
    if ($passthru) {Write-Output $AdminUserProfile}
 }# Set-AdminUserProfile
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
    Count of Systems with Associated Credentials: $(@($AdminUserProfile.Systems | Where-Object {$_.credential -ne $null}).count)
    Count of Systems Configured for AutoConnect: $(@($AdminUserProfile.Systems | Where-Object {$_.AutoConnect -eq $true}).count)

"@
$Message
} #GetAdminUserProfileMenuMessage
function GetGenericNewAdminsUserProfileObject
{
param(
$OrganizationIdentity
)
[pscustomobject]@{
        Identity = [guid]::NewGuid()
        ProfileType = 'OneShellAdminUserProfile'
        ProfileTypeVersion = 1.0
        General = [pscustomobject]@{
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
} #GetGenericNewAdminsUserProfileObject
function UpdateAdminUserProfileObjectVersion
{
param($AdminUserProfile)

    Write-Verbose -Message 'NOTICE: This function uses interactive windows/dialogs which may sometimes appear underneath the active window.  If things seem to be locked up, check for a hidden window.' -Verbose
   #Profile Version Upgrades
    #MailFrom
    if (-not (Test-Member -InputObject $AdminUserProfile.General -Name MailFrom))
    {
        $AdminUserProfile.General | Add-Member -MemberType NoteProperty -Name MailFrom -Value $null
    }
    #UserName
    if (-not (Test-Member -InputObject $AdminUserProfile.General -Name User))
    {
        $AdminUserProfile.General | Add-Member -MemberType NoteProperty -Name User -Value $env:USERNAME
    }
    #MailRelayEndpointToUse
    if (-not (Test-Member -InputObject $AdminUserProfile.General -Name MailRelayEndpointToUse))
    {
        $AdminUserProfile.General | Add-Member -MemberType NoteProperty -Name MailRelayEndpointToUse -Value $null
    }
    #ProfileTypeVersion
    if (-not (Test-Member -InputObject $AdminUserProfile -MemberType NoteProperty -Name ProfileTypeVersion))
    {
        $AdminUserProfile | Add-Member -MemberType NoteProperty -Name ProfileTypeVersion -Value 1.0
    }
$AdminUserProfile
} #UpdateAdminUserProfileObjectVersion