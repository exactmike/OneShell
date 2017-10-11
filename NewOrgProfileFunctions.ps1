function NewGenericOrgProfileObject
    {
        [cmdletbinding()]
        param()
        [pscustomobject]@{
                Identity = [guid]::NewGuid()
                Name = ''
                ProfileType = 'OneShellOrgProfile'
                ProfileTypeVersion = 1.2
                Version = .01
                IsDefault = $null
                OrganizationSpecificModules = @()
                Systems = @()
        }
    } #GetGenericNewOrgProfileObject
function New-OrgProfile
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory,ParameterSetName = 'default')]
            [string]$Name
            ,
            [parameter(Mandatory,ParameterSetName = 'default')]
            [bool]$IsDefault
            ,
            [parameter(Mandatory,ParameterSetName = 'OrgProfileBuilder')]
            [switch]$OrgProfileBuilder
        )
        $GenericOrgProfileObject = NewGenericOrgProfileObject
        $GenericOrgProfileObject.Name = $Name
        $GenericOrgProfileObject.IsDefault = $IsDefault
        Write-Output -InputObject $GenericOrgProfileObject
    }
function NewGenericOrgSystemObject
    {
        [cmdletbinding()]
        param()
        [pscustomobject]@{
            Identity = [guid]::NewGuid()
            Name = ''
            Description = ''
            ServiceType = ''
            SystemObjectVersion = .01
            Version = .01
            IsDefault = $null
            RequiredModule = @()
            Defaults = [PSCustomObject]@{
                ProxyEnabled = $null
                AuthenticationRequired = $null
                UseTLS = $null
                AuthMethod = $null
                CommandPrefix = $null
            }
            Endpoints = @()
            ServiceTypeAttributes = [PSCustomObject]@{}
        }
    }#end function NewGenericOrgSystemObject
function AddServiceTypeAttributesToGenericOrgSystemObject
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory)]
            $OrgSystemObject
            ,
            [parameter(Mandatory)]
            $ServiceType
        )#end param
        switch ($ServiceType)
        {
            #one entry for each ServiceType with ServiceTypeAttributes
            'Office365Tenant'
            {$OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'TenantSubDomain' -Value $null}
            'AzureADTenant'
            {$OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'TenantSubDomain' -Value $null}
            'ExchangeOrganization'
            {$OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'OrgType' -Value $null}
            'ActiveDirectoryInstance'
            {
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'InstanceType' -Value $null
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'GlobalCatalog' -Value $null
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'UserAttributes' -Value @()
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'GroupAttributes' -Value @()
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'ContactAttributes' -Value @()
            }
            'PowerShell'
            {
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'SessionManagementGroups' -Value @()
            }
            'SQLDatabase'
            {
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'InstanceType' -Value @()
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'Database' -Value @()
            }
            'AADSyncServer'
            {

            }
        }#end switch
        Write-Output -InputObject $OrgSystemObject
    }#end function AddServiceTypeAttributesToGenericOrgSystemObject
function New-OrgSystem
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            [ValidateSet('PowerShell','SQLDatabase','ExchangeOrganization','AADSyncServer','AzureADTenant','Office365Tenant','ActiveDirectoryInstance','MailRelayEndpoint','SkypeOrganization')] #convert to dynamic parameter sourced from single place to ease adding systems types later
            [string]$ServiceType
            ,
            [parameter(Mandatory)]
            [string]$Name
            ,
            [parameter()]
            [string]$Description
            ,
            [parameter()]
            [bool]$isDefault
            ,
            [parameter()]
            [bool]$AuthenticationRequired
            ,
            [parameter()]
            [ValidateLength(2,5)]
            [string]$CommandPrefix
            ,
            [parameter()]
            [bool]$ProxyEnabled
            ,
            [parameter()]
            [bool]$UseTLS
        )#end param
        $GenericSystemObject = NewGenericOrgSystemObject
        $GenericSystemObject.ServiceType = $ServiceType
        $GenericSystemObject.Name = $Name
        if (-not [string]::IsNullOrWhiteSpace($Description)) {$GenericSystemObject.Description = $Description}
        if ($isDefault -ne $null) {$GenericSystemObject.IsDefault = $isDefault}
        if ($AuthenticationRequired -ne $null) {$GenericSystemObject.Defaults.AuthenticationRequired = $AuthenticationRequired}
        if ($commandPrefix -ne $null) {$GenericSystemObject.Defaults.CommandPrefix = $CommandPrefix}
        if ($ProxyEnabled -ne $null) {$GenericSystemObject.Defaults.ProxyEnabled = $ProxyEnabled}
        if ($UseTLS -ne $null) {$GenericSystemObject.Defaults.UseTLS = $UseTLS}                
        $GenericSystemObject = AddServiceTypeAttributesToGenericOrgSystemObject -OrgSystemObject $GenericSystemObject -ServiceType $ServiceType
        Write-Output -InputObject $GenericSystemObject
    }#end function New-OrgSystemObject

function NewGenericSystemEndpointObject
    {
        [cmdletbinding()]
        param()
        [PSCustomObject]@{
            Identity = [guid]::NewGuid()
            AddressType = $null
            Address = $null
            ServicePort = $null
            IsDefault = $null
            UseTLS = $null
            ProxyEnabled = $null
            CommandPrefix = $null
            AuthenticationRequired = $null
            AuthMethod = $null
            EndPointGroup = $null
            EndPointType = $null
            ServiceTypeAttributes = [PSCustomObject]@{}
            ServiceType = $null
        }
    }#end function NewGenericSystemEndpointObject
function New-OrgSystemEndpoint
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            [ValidateSet('PowerShell','SQLDatabase','ExchangeOrganization','AADSyncServer','AzureADTenant','Office365Tenant','ActiveDirectoryInstance','MailRelayEndpoint','SkypeOrganization')] #convert to dynamic parameter sourced from single place to ease adding systems types later            
            [string]$ServiceType
            ,
            [Parameter(Mandatory)]
            [ValidateSet('URL','IPAddress','FQDN')]
            [String]$AddressType
            ,
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [String]$Address
            ,
            [Parameter()]
            [AllowNull()]
            [ValidatePattern("^\d{1,5}$")]
            $ServicePort
            ,
            [parameter()]
            [AllowNull()]
            [ValidateSet($true,$false,$null)]
            $IsDefault
            ,
            [parameter()]
            [AllowNull()]
            [ValidateSet($true,$false,$null)]
            $UseTLS
            ,
            [parameter()]
            [AllowNull()]
            [validateSet($true,$false,$null)]
            $ProxyEnabled = $false
            ,
            [parameter()]
            [ValidateLength(2,5)]
            $CommandPrefix
            ,
            [parameter()]
            [AllowNull()]
            [validateSet($true,$false,$null)]
            $AuthenticationRequired
            ,
            [parameter()]
            [ValidateSet('Basic','Kerberos','Integrated')]
            $AuthMethod
            ,
            [parameter()]
            $EndPointGroup
            ,
            [parameter()]
            [ValidateSet('Admin','MRSProxyServer')]
            [string]$EndPointType = 'Admin'
        )
        DynamicParam
        {
            #build any service typ specific parameters that may be needed
            switch ($ServiceType)
            {
                'ExchangeOrganization'
                {
                    $Dictionary = New-DynamicParameter -Name 'PreferredDomainControllers' -Type $([string[]]) -Mandatory:$false
                    Write-Output -InputObject $dictionary
                 }
            }
        }#End DynamicParam
        End
        {
            $GenericEndpointObject = NewGenericSystemEndpointObject
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            foreach ($vp in $AllValuedParameters)
            {
                $GenericEndpointObject.$($vp.name) = $($vp.value)
            }
            #Add any servicetype specific attributes that were specified
            if (-not $null -eq $Dictionary)
            {
                Set-DynamicParameterVariable -dictionary $Dictionary
            }
            switch ($ServiceType)
            {
                'ExchangeOrganization'
                {
                    $GenericEndpointObject.ServiceTypeAttributes | Add-Member -Name 'PreferredDomainControllers' -Value $PreferredDomainControllers -MemberType NoteProperty
                }
            }
            Write-Output -InputObject $GenericEndpointObject            
        }
    }
    #ExchangeEndpoints
##Needs PreferredDomainControllers
##Needs MRSProxyServer Endpoints and AdministrativePowershell Endpoints

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
    $Message
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


