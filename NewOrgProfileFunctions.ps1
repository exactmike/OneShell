function GetGenericNewOrgProfileObject
{
param(
)
[pscustomobject]@{
        Identity = [guid]::NewGuid()
        ProfileType = 'OneShellOrgProfile'
        ProfileTypeVersion = 1.0
        General = [pscustomobject]@{
            Name = ''
            Default = $null
            OrganizationSpecificModules = @()
            SharePointSite = ''
        }
        Systems = @()
    }
} #GetGenericNewOrgProfileObject
function GetOrgProfileMenuMessage
{
param($OrgProfile)
$Message = @"
Oneshell: Org Profile Menu

    Identity: $($OrgProfile.Identity)
    Profile Name: $($OrgProfile.General.Name)
    Default: $($OrgProfile.General.Default)
"@
$Message
} #GetOrgProfileMenuMessage
function New-OrgProfile
{
[cmdletbinding()]
param
(
    [switch]$Passthru
)
    Write-Verbose -Message 'NOTICE: This function uses interactive windows/dialogs which may sometimes appear underneath the active window.  If things seem to be locked up, check for a hidden window.' -Verbose
    #Build the basic Org profile object
    $OrgProfile = GetGenericNewOrgProfileObject
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
                $AdminUserProfile.Systems = GetAdminUserProfileSystemEntries -OrganizationIdentity $OrganizationIdentity -AdminUserProfile $AdminUserProfile
            }
            'Save'
            {
                if ($OrgProfile.General.ProfileFolder -eq '')
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
} #New-AdminUserProfile
function New-OrgProfileSystem
{
[cmdletbinding()]
param
(
[parameter(Mandatory)]
[ValidateSet('PowerShellSystems','SQLDatabases','ExchangeOrganizations','AADSyncServers','AzureADTenants','Office365Tenants','ActiveDirectoryInstances','MailRelayEndpoints','SkypeOrganizations')]
[string]$SystemCategory
,
[parameter(Mandatory)]
[string]$Name
,
[parameter()]
[string]$Description
,
[Alias('Server')]
[parameter()]
[string]$ComputerName

)
}