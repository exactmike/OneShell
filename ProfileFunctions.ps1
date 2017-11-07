##########################################################################################################
#Profile and Environment Initialization Functions
##########################################################################################################
Function Initialize-AdminEnvironment
    {
    [cmdletbinding(defaultparametersetname = 'AutoConnect')]
    param(
        [parameter(ParameterSetName = 'AutoConnect')]
        [switch]$AutoConnect
        ,
        [parameter(ParameterSetName = 'ShowMenu')]
        [switch]$ShowMenu
        ,
        [parameter(ParameterSetName = 'SpecifiedProfile',Mandatory)]
        $OrgProfileIdentity
        ,
        [parameter(ParameterSetName = 'SpecifiedProfile',Mandatory)]
        $AdminUserProfileIdentity
        ,
        [parameter()]
        [ValidateScript({Test-DirectoryPath -path $_})]
        [string[]]$OrgProfilePath
        ,
        [parameter()]
        [ValidateScript({Test-DirectoryPath -path $_})]
        [string[]]$AdminProfilePath
        ,
        [switch]$NoConnections
    )
    Process
    {
        $GetOrgProfileParams = @{
        ErrorAction = 'Stop'
        }
        $GetAdminUserProfileParams = @{
        ErrorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('OrgProfilePath'))
        {
        $GetOrgProfileParams.Path = $OrgProfilePath
        }
        if ($PSBoundParameters.ContainsKey('AdminProfilePath'))
        {
        $GetAdminUserProfileParams.Path = $AdminProfilePath
        }
        Switch ($PSCmdlet.ParameterSetName)
        {
        'AutoConnect'
        {
            $DefaultOrgProfile = Get-OrgProfile @GetOrgProfileParams -GetDefault
            [bool]$OrgProfileLoaded = Use-OrgProfile -Profile $DefaultOrgProfile -ErrorAction Stop
            if ($OrgProfileLoaded)
            {
                $DefaultAdminUserProfile = Get-AdminUserProfile @GetAdminUserProfileParams -GetDefault
                $message = "Admin user profile has been set to Name:$($DefaultAdminUserProfile.General.Name), Identity:$($DefaultAdminUserProfile.Identity)."
                Write-Log -Message $message -Verbose -ErrorAction SilentlyContinue -EntryType Notification
                [bool]$AdminUserProfileLoaded = Use-AdminUserProfile -AdminUserProfile $DefaultAdminUserProfile
                if ($AdminUserProfileLoaded)
                {
                    if ($NoConnections)
                    {}
                    else
                    {
                        Write-Log -Message 'Running Connect-RemoteSystems' -EntryType Notification
                        Connect-RemoteSystems
                    }
                }#if
            }#If $OrgProfileLoaded
        }#AutoConnect
        'ShowMenu'
        {
            #Getting Organization Profile(s)
            try
            {
                $Message = 'Getting Organization Profile(s)'
                Write-Log -Message $message -EntryType Attempting
                $OrgProfiles = Get-OrgProfile @GetOrgProfileParams
                Write-Log -Message $message -EntryType Succeeded
                if ($OrgProfiles.Count -eq 0) {
                    throw "No OrgProfile(s) found in the specified location(s) $($OrgProfilePath -join ';')"
                }
            }
            catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                $PSCmdlet.ThrowTerminatingError($myError)
            }
            #Get the User Organization Profile Choice
            try
            {
                $message = 'Get the User Organization Profile Choice'
                Write-Log -Message $message -EntryType Attempting 
                $Choices = @($OrgProfiles | ForEach-Object {"$($_.General.Name)`r`n$($_.Identity)"})
                $UserChoice = Read-Choice -Title 'Select OrgProfile' -Message 'Select an organization profile to load:' -Choices $Choices -DefaultChoice -1 -Vertical -ErrorAction Stop
                $OrgProfile = $OrgProfiles[$UserChoice]
                Use-OrgProfile -profile $OrgProfile -ErrorAction Stop  > $null
                Write-Log -Message $message -EntryType Succeeded
            }
            catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                $PSCmdlet.ThrowTerminatingError($myError)
            }
            #Get Admin User Profiles for Current Org Profile
            Try
            {
                $message = 'Get Admin User Profiles for Current Org Profile'
                Write-Log -Message $message -EntryType Attempting
                $AdminUserProfiles = @(Get-AdminUserProfile @GetAdminUserProfileParams -OrgIdentity $OrgProfile.Identity)
                Write-Log -Message $message -EntryType Succeeded
            }
            catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                $PSCmdlet.ThrowTerminatingError($myError)
            }
            #Get the User Admin User Profile Choice OR Create a new Admin User Profile if none exists
            Try
            {
                switch ($AdminUserProfiles.Count) 
                {
                    {$_ -ge 1}
                    {
                        $message = 'Get the User Admin User Profile Choice'
                        Write-Log -Message $message -EntryType Attempting
                        $Choices = @($AdminUserProfiles | ForEach-Object {"$($_.General.Name)`r`n$($_.Identity)"})
                        $UserChoice = Read-Choice -Title 'Select AdminUserProfile' -Message 'Select an Admin User Profile to load:' -Choices $Choices -DefaultChoice -1 -Vertical -ErrorAction Stop
                        $AdminUserProfile = $AdminUserProfiles[$UserChoice]
                        Write-Log -Message $message -EntryType Succeeded
                    }
                    {$_ -lt 1}
                    {
                        $ShouldCreateNewProfile = Read-Choice -Title 'Create new profile?' -Message "No Admin User profile exists for the following Org Profile:`r`nIdentity:$($OrgProfile.Identity)`r`nName$($OrgProfile.General.Name)" -Choices 'Yes','No' -ReturnChoice
                        switch ($ShouldCreateNewProfile)
                        {
                            'Yes'
                            {$AdminUserProfile = New-AdminUserProfile -OrganizationIdentity $CurrentOrgProfile.Identity}
                            'No'
                            {throw "No Admin User Profile exists for auto connection to Org Profile with Identity $($OrgProfile.Identity) and Name $($OrgProfile.General.Name)"}
                        }
                    }
                }#Switch
            }#Try
            catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                $PSCmdlet.ThrowTerminatingError($myError)
            }
            #Load/"Use" User Selected Admin User Profile
            Try
            {
                $message = 'Load User Selected Admin User Profile'
                Write-Log -Message $message -EntryType Attempting
                [bool]$AdminUserProfileLoaded = Use-AdminUserProfile -AdminUserProfile $AdminUserProfile -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
            }
            catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                $PSCmdlet.ThrowTerminatingError($myError)
            }
            if ($AdminUserProfileLoaded)
            {
                    if ($NoConnections)
                    {}
                    else
                    {
                        Write-Log -Message 'Running Connect-RemoteSystems' -EntryType Notification
                        Connect-RemoteSystems
                    }
            }
        }
        'SpecifiedProfile'
        {
            #Getting Organization Profile(s)
            try
            {
                $GetOrgProfileParams.Identity = $OrgProfileIdentity
                $Message = 'Getting Organization Profile'
                Write-Log -Message $message -EntryType Attempting
                $OrgProfile = @(Get-OrgProfile @GetOrgProfileParams)
                Write-Log -Message $message -EntryType Succeeded
                switch ($OrgProfile.Count)
                {
                    0
                    {throw "No OrgProfile(s) found in the specified location(s) $($OrgProfilePath -join ';')"}
                    1
                    {
                        $OrgProfile = $OrgProfile[0]
                        Use-OrgProfile -profile $OrgProfile -ErrorAction Stop  > $null
                    }
                    Default
                    {throw "Multiple OrgProfile(s) with Identity $OrgProfileIdentity found in the specified location(s) $($OrgProfilePath -join ';')"}
                }
            }
            catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                $PSCmdlet.ThrowTerminatingError($myError)
            }
            #Get Admin User Profile
            Try
            {
                $GetAdminUserProfileParams.Identity = $AdminUserProfileIdentity
                $message = 'Get Admin User Profile specified for Current Org Profile'
                Write-Log -Message $message -EntryType Attempting
                $AdminUserProfile = @(Get-AdminUserProfile @GetAdminUserProfileParams -OrgIdentity $OrgProfile.Identity)
                Write-Log -Message $message -EntryType Succeeded
                switch ($AdminUserProfile.Count)
                {
                    0
                    {throw "No AdminUserProfile(s) found in the specified location(s) $($AdminProfilePath -join ';')"}
                    1
                    {
                        $AdminUserProfile = $AdminUserProfile[0]
                    }
                    Default
                    {throw "Multiple OrgProfile(s) with Identity $OrgProfileIdentity found in the specified location(s) $($OrgProfilePath -join ';')"}
                }
            }
            catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                $PSCmdlet.ThrowTerminatingError($myError)
            }
            #Load/"Use" User Selected Admin User Profile
            Try
            {
                $message = 'Load User Selected Admin User Profile'
                Write-Log -Message $message -EntryType Attempting
                [bool]$AdminUserProfileLoaded = Use-AdminUserProfile -AdminUserProfile $AdminUserProfile -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
            }
            catch
            {
                $myError = $_
                Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
                $PSCmdlet.ThrowTerminatingError($myError)
            }
            if ($AdminUserProfileLoaded)
            {
                    if ($NoConnections)
                    {}
                    else
                    {
                        Write-Log -Message 'Running Connect-RemoteSystems' -EntryType Notification
                        Connect-RemoteSystems
                    }
            }
        }
        }#Switch
    }#Process
    }
function GetPotentialOrgProfiles
    {
        [cmdletbinding()]
        param
        (
            [string[]]$path
        )
        $JSONProfiles = @(
            foreach ($loc in $Path)
            {
                Write-Verbose -Message "Getting JSON Files From $loc"
                (Get-ChildItem -Path $loc -Filter *.json)
            }
        )
        $PotentialOrgProfiles = @(foreach ($file in $JSONProfiles) {Get-Content -Path $file.fullname -Raw | ConvertFrom-Json})
        Write-Verbose -Message "Found $($PotentialOrgProfiles.count) Potential Org Profiles"
        Write-Output -InputObject $PotentialOrgProfiles
    }
function GetOrgServiceTypes
    {
        #change this list in other functions as well when you modify here.  
        'PowerShell','SQLDatabase','ExchangeOrganization','AADSyncServer','AzureADTenant','Office365Tenant','ActiveDirectoryInstance','MailRelayEndpoint','SkypeOrganization'
    }
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
            [parameter(Mandatory)]
            [string]$Name
            ,
            [parameter(Mandatory)]
            [bool]$IsDefault
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
            ,
            [parameter()]
            $dictionary
        )#end param
        if ($null -ne $dictionary)
        {
            Set-DynamicParameterVariable -dictionary $dictionary
        }
        switch ($ServiceType)
        {
            #one entry for each ServiceType with ServiceTypeAttributes
            'Office365Tenant'
            {$OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'TenantSubDomain' -Value $TenantSubDomain}
            'AzureADTenant'
            {$OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'TenantSubDomain' -Value $TenantSubDomain}
            'ExchangeOrganization'
            {$OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'ExchangeOrgType' -Value $ExchangeOrgType}
            'ActiveDirectoryInstance'
            {
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'ADInstanceType' -Value $ADInstanceType
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'GlobalCatalog' -Value $GlobalCatalog
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'ADUserAttributes' -Value $ADUserAttributes
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'ADGroupAttributes' -Value $ADGroupAttributes
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'ADContactAttributes' -Value $ADContactAttributes
            }
            'PowerShell'
            {
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'SessionManagementGroups' -Value $SessionManagementGroups
            }
            'SQLDatabase'
            {
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'SQLInstanceType' -Value @()
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
        DynamicParam
        {
            #build any service typ specific parameters that may be needed
            switch -Wildcard ($ServiceType)
            {
                'ExchangeOrganization'
                {
                    $Dictionary = New-DynamicParameter -Name 'ExchangeOrgType' -Type $([string]) -Mandatory:$true -ValidateSet 'OnPremises','Online','ComplianceCenter'

                }
                '*Tenant'
                {
                    $Dictionary = New-DynamicParameter -Name 'TenantSubdomain' -Type $([string]) -Mandatory:$true
                }
                'ActiveDirectoryInstance'
                {
                    $Dictionary = New-DynamicParameter -Name 'ADInstanceType' -Type $([string]) -Mandatory:$true -ValidateSet 'AD','ADLDS'
                    $Dictionary = New-DynamicParameter -Name 'GlobalCatalog' -Type $([bool]) -Mandatory:$true -ValidateSet $true,$false -DPDictionary $Dictionary
                    $Dictionary = New-DynamicParameter -Name 'ADUserAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
                    $Dictionary = New-DynamicParameter -Name 'ADGroupAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
                    $Dictionary = New-DynamicParameter -Name 'ADContactAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
                }
                'PowerShell'
                {
                    $Dictionary = New-DynamicParameter -Name 'SessionManagementGroups' -Type $([string[]]) -Mandatory:$false
                }
                'SQLDatabase'
                {
                    $Dictionary = New-DynamicParameter -Name 'SQLInstanceType' -Type $([string]) -Mandatory:$true -ValidateSet 'OnPremises','AzureSQL'
                    $Dictionary = New-DynamicParameter -Name 'Database' -Type $([string]) -Mandatory:$true -DPDictionary $Dictionary
                }
            }
            if ($null -ne $Dictionary)
            {
                Write-Output -InputObject $dictionary
            }
        }#End DynamicParam
        End
        {
            $GenericSystemObject = NewGenericOrgSystemObject
            $GenericSystemObject.ServiceType = $ServiceType
            $GenericSystemObject.Name = $Name
            if (-not [string]::IsNullOrWhiteSpace($Description)) {$GenericSystemObject.Description = $Description}
            if ($isDefault -ne $null) {$GenericSystemObject.IsDefault = $isDefault}
            if ($AuthenticationRequired -ne $null) {$GenericSystemObject.Defaults.AuthenticationRequired = $AuthenticationRequired}
            if ($commandPrefix -ne $null) {$GenericSystemObject.Defaults.CommandPrefix = $CommandPrefix}
            if ($ProxyEnabled -ne $null) {$GenericSystemObject.Defaults.ProxyEnabled = $ProxyEnabled}
            if ($UseTLS -ne $null) {$GenericSystemObject.Defaults.UseTLS = $UseTLS}
            $addServiceTypeAttributesParams = @{
                OrgSystemObject = $GenericSystemObject
                ServiceType = $ServiceType
            }
            if ($null -ne $Dictionary)
            {$addServiceTypeAttributesParams.Dictionary = $Dictionary}
            $GenericSystemObject = AddServiceTypeAttributesToGenericOrgSystemObject @addServiceTypeAttributesParams
            Write-Output -InputObject $GenericSystemObject    
        }   
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
function GetPotentialAdminUserProfiles
    {
        [cmdletbinding()]
        param
        (
            [string[]]$path
        )
        $JSONProfiles =@(
            foreach ($loc in $Path)
            {
                Get-ChildItem -Path $Loc -Filter *.JSON -ErrorAction Continue
            }
        )    
        $PotentialAdminUserProfiles = @(foreach ($file in $JSONProfiles) {Get-Content -Path $file.fullname -Raw | ConvertFrom-Json})
        Write-Output -InputObject $PotentialAdminUserProfiles
    }
Function Export-OrgProfile
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory=$true)]
            $profile
            ,
            [parameter(Mandatory=$true)]
            [validateset('New','Update')]
            $operation
            ,
            [parameter()]
            [AllowNull()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            $ProfileExportFolderPath
        )
        $name = [string]$($profile.Identity.tostring()) + '.json'
        if ($null -eq $ProfileExportFolderPath)
        {
            Write-Verbose -Message "Using Default Profile Location"
            $path = Join-Path $script:OneShellOrgProfilePath[0] $name
        }
        else
        {
            $path = Join-Path $ProfileExportFolderPath $name
        }
        Write-Verbose -Message "Profile File Export Path is $path"
        $JSONparams=@{
            InputObject = $profile
            ErrorAction = 'Stop'
            Depth = 3
        }
        $OutParams = @{
            ErrorAction = 'Stop'
            FilePath = $path
            Encoding = 'ascii'
        }
        switch ($operation)
        {
            'Update' {$OutParams.Force = $true}
            'New' {$OutParams.NoClobber = $true}
        }#end switch
        try
        {
            ConvertTo-Json @JSONparams | Out-File @OutParams
        }#end try
        catch
        {
            $_
            throw "FAILED: Could not write Org Profile data to $path"
        }#end catch
    }#Function Export-OrgProfile
Function Get-OrgProfile
    {
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param(
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'GetDefault')]
        [ValidateScript({Test-DirectoryPath -path $_})]
        [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'GetDefault')]
        $OrgProfileType = 'OneShellOrgProfile'
        , 
        [parameter(ParameterSetName = 'GetCurrent')]
        [switch]$GetCurrent
        ,
        [parameter(ParameterSetName = 'GetDefault')]
        [switch]$GetDefault
    )
    DynamicParam
    {
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
        $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
        $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
        $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $true -Position 1 -ParameterSetName 'Identity'
        Write-Output -InputObject $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        $outputprofiles = @(
            Write-Verbose -Message "Parameter Set is $($pscmdlet.ParameterSetName)"
            switch ($PSCmdlet.ParameterSetName)
            {
            'GetCurrent'
            {
                $Script:CurrentOrgProfile
            }
            Default
            {
                $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $path)
                if ($PotentialOrgProfiles.Count -ge 1)
                {
                    $FoundOrgProfiles = @($PotentialOrgProfiles | Where-Object {$_.ProfileType -eq $OrgProfileType})
                    Write-Verbose -Message "Found $($FoundOrgProfiles.Count) Org Profiles."
                    switch ($PSCmdlet.ParameterSetName)
                    {
                        'Identity'
                        {
                            Write-Verbose -Message "Identity is set to $($identity -join ',')"
                            $OrgProfiles = @($FoundOrgProfiles | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Name -eq $Identity})
                            Write-Output -inputobject $OrgProfiles
                        }#Identity
                        'All'
                        {
                            $OrgProfiles = @($FoundOrgProfiles)
                            Write-Output -inputobject $OrgProfiles
                        }#All
                        'GetDefault'
                        {
                            $OrgProfiles = @($FoundOrgProfiles | Where-Object -FilterScript {$_.IsDefault -eq $true})
                            switch ($OrgProfiles.Count)
                            {
                                {$_ -eq 1}
                                {
                                    Write-Output -inputobject $OrgProfiles[0]
                                }
                                {$_ -gt 1}
                                {
                                    throw "FAILED: Multiple Org Profiles Are Set as Default: $($OrgProfiles.Identity -join ',')"
                                }
                                {$_ -lt 1}
                                {
                                    throw 'FAILED: No Org Profiles Are Set as Default'
                                }
                            }#Switch $DefaultOrgProfile.Count
                        }
                    }#switch
                }#if
            }#Default
            }#switch
        )
        #output the profiles
        write-output -InputObject $outputprofiles

    }#end End
    }#Function Get-OrgProfile
Function Get-OrgProfileSystem
    {
        [cmdletbinding(DefaultParameterSetName = 'All')]
        param
        (
            [parameter()]
            [switch]$IsDefault
            ,
            [parameter(ParameterSetName = 'Identity')]
            [parameter(ParameterSetName = 'All')]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
            ,
            [parameter(ParameterSetName = 'GetCurrent')]
            [switch]$GetCurrent
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'OrgIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $true -Position 1 -ParameterSetName 'Identity'
            $dictionary = New-DynamicParameter -Name 'ServiceType' -Type $([string[]]) -ValidateSet @(getorgservicetypes) -HelpMessage 'Specify one or more system types to include' -Mandatory $false -DPDictionary $dictionary
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            $profiles = @(
                switch ($PSCmdlet.ParameterSetName)
                {
                    'GetCurrent'
                    {
                        Get-OrgProfile -GetCurrent -ErrorAction Stop
                    }
                    'Identity'
                    {
                        Get-OrgProfile -Identity $OrgIdentity -ErrorAction Stop
                    }
                    'All'
                    {
                        Get-OrgProfile -ErrorAction Stop
                    }
                }
            )
            $OutputSystems = @(
                foreach ($p in $profiles)
                {
                    $p.systems | Select-Object -Property *,@{n='OrgName';e={$p.Name}},@{n='OrgIdentity';e={$p.Identity}}
                }
            )
            #Filter outputSystems if required by specified parameters
            if ($null -ne $ServiceType)
            {
                $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.ServiceType -in $ServiceType})
            }
            if ($IsDefault -eq $true)
            {
                $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.IsDefault -eq $true})
            }
            Write-Output -InputObject $OutputSystems
        }
    }
Function Use-OrgProfile
    {
        [cmdletbinding(DefaultParameterSetName = 'Identity')]
        param
        (
            [parameter(ParameterSetName = 'Object')]
            $profile 
            ,
            [parameter(ParameterSetName = 'Identity')]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $true -Position 1 -ParameterSetName 'Identity'
            Write-Output -InputObject $dictionary
        }  
        end
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            switch ($PSCmdlet.ParameterSetName)
            {
                'Object'
                {}
                'Identity'
                {
                    $profile = Get-OrgProfile -Identity $Identity
                }
            }# end switch
            if ($null -ne $script:CurrentOrgProfile -and $profile.Identity -ne $script:CurrentOrgProfile.Identity)
            {
                $script:CurrentOrgProfile = $profile
                Write-Log -message "Org Profile has been changed to $($script:CurrentOrgProfile.Identity), $($script:CurrentOrgProfile.name).  Remove PSSessions and select an Admin Profile to load." -EntryType Notification -Verbose
            }
            else
            {
                $script:CurrentOrgProfile = $profile
                Write-Log -Message "Org Profile has been set to $($script:CurrentOrgProfile.Identity), $($script:CurrentOrgProfile.name)." -EntryType Notification -Verbose
            }    
        }
    }# end function Use-OrgProfile
Function Get-AdminUserProfile
    {
        [cmdletbinding(DefaultParameterSetName='All')]
        param
        (
            [parameter(ParameterSetName = 'All')]
            [parameter(ParameterSetName = 'Identity')]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter(ParameterSetName = 'All')]
            [parameter(ParameterSetName = 'Identity')]
            $ProfileType = 'OneShellAdminUserProfile'
            ,
            [parameter(ParameterSetName = 'All')]
            [parameter(ParameterSetName = 'Identity')]
            [ValidateScript({Test-DirectoryPath -Path $_})]        
            [string[]]$OrgProfilePath
            ,
            [parameter(ParameterSetName = 'GetCurrent')]
            [switch]$GetCurrent
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            if ($null -eq $OrgProfilePath -or [string]::IsNullOrEmpty($OrgProfilePath)) {$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $OrgProfilePath)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'OrgProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $AdminProfileIdentities -ParameterSetName Identity -DPDictionary $dictionary -Mandatory $true
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            $outputprofiles = @(
                switch ($PSCmdlet.ParameterSetName)
                {
                    'GetCurrent'
                    {
                        $script:CurrentAdminUserProfile
                    }
                    Default
                    {
                        $PotentialAdminUserProfiles = GetPotentialAdminUserProfiles -path $Path
                        $FoundAdminUserProfiles = @($PotentialAdminUserProfiles | Where-Object {$_.ProfileType -eq $ProfileType})
                        if ($FoundAdminUserProfiles.Count -ge 1)
                        {
                            switch ($PSCmdlet.ParameterSetName)
                            {
                                'All'
                                {
                                    $FoundAdminUserProfiles
                                }
                                'Identity'
                                {
                                    $FoundAdminUserProfiles | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Name -eq $Identity}
                                }
                            }#end Switch
                        }#end if
                    }#end Default
                }#end Switch
            )#end outputprofiles
            #filter the found profiles for OrgIdentity if specified
            if (-not [string]::IsNullOrWhiteSpace($OrgProfileIdentity))
            {
                $outputprofiles = $outputprofiles | Where-Object -FilterScript {$_.organization.identity -eq $OrgProfileIdentity -or $_.organization.Name -eq $OrgProfileIdentity}
            }
            #output the found profiles
            Write-Output -InputObject $outputprofiles
        }#end End
    }#Get-AdminUserProfile
Function Get-AdminUserProfileSystem
    {
        [cmdletbinding(DefaultParameterSetName='All')]
        param
        (
            [parameter(ParameterSetName = 'All')]
            [parameter(ParameterSetName = 'Identity')]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter()]
            [string[]]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"
            ,
            [parameter(ParameterSetName = 'GetCurrent')]
            [switch]$GetCurrent
        )#end param
        DynamicParam
        {
            if ($null -eq $Path)
            {
                $path = "$env:UserProfile\OneShell\"
            }
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $AdminProfileIdentities -ParameterSetName Identity
            $dictionary = New-DynamicParameter -Name 'ServiceType' -Type $([string[]]) -ValidateSet $(GetOrgServiceTypes) -DPDictionary $dictionary -Mandatory $false
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            $auprofiles = @(
                switch ($PSCmdlet.ParameterSetName)
                {
                    'GetCurrent'
                    {
                        $script:CurrentAdminUserProfile
                    }
                    Default
                    {
                        $GetAdminUserProfileParams = @{
                            ErrorAction = 'Stop'
                        }
                        if ($PSBoundParameters.ContainsKey('Path'))
                        {
                            $GetAdminUserProfileParams.Path = $Path
                        }
                        switch ($PSCmdlet.ParameterSetName)
                        {
                            'Identity'
                            {
                                $GetAdminUserProfileParams.Identity = $Identity
                            }
                            'All'
                            {
                                #nothing additional
                            }
                        }
                        Get-AdminUserProfile @GetAdminUserProfileParams
                    }#end Default
                }#end Switch
            )#end auprofiles
            $outputSystems = @(
                foreach ($aup in $auprofiles)
                {
                    $orgProfile = Get-OrgProfile -Identity $aup.organization.Identity -ErrorAction Stop -Path $OrgProfilePath
                    foreach ($as in $aup.systems)
                    {
                        $os = $orgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $as.identity}
                        $as | Select-Object -Property *,@{n='ServiceType';e={$os.ServiceType}},@{n='Name';e={$os.name}},@{n='AdminProfileName';e={$aup.Name}},@{n='AdminProfileIdentity';e={$aup.Identity}},@{n='OrgName';e={$orgProfile.Name}},@{n='OrgIdentity';e={$orgProfile.Identity}}
                    }
                }
            )
            if ($null -eq $ServiceType)
            {Write-Output -inputobject $outputSystems}
            else 
            {
                $outputSystems | Where-Object -FilterScript {$_.ServiceType -in $ServiceType}
            }
        }#end End
    }#Get-AdminUserProfile
function New-AdminUserProfile
    {
        [cmdletbinding(DefaultParameterSetName = 'OrgName')]
        param
        (
            [Parameter(Mandatory)]
            [ValidateScript({Test-IsWriteableDirectory -path $_})]
            [string]$ProfileFolder #The folder to use for logs, exports, etc.
            ,
            [Parameter(Mandatory)]
            [string]$MailFromSMTPAddress #email address to use for sending notification emails
            ,
            [Parameter()]
            [pscredential[]]$Credentials = @()
            ,
            [Parameter()]
            [psobject[]]$Systems = @()
            ,
            [Parameter()]
            [string]$Name #Overrides the default name of Org-Machine-User
            ,
            [Parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string]$OrgProfilePath
            ,
            [bool]$IsDefault #sets this profile as the default for the specified Organization
        )
        DynamicParam
        {
            if ($null -eq $OrgProfilePath -or [string]::IsNullOrEmpty($OrgProfilePath))
            {
                Write-Verbose -Message "Populating the OrgProfilePath with the default value" -Verbose
                $OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"
            }
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $OrgProfilePath)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'OrgProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $true -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            $GetOrgProfileParams = @{
                ErrorAction = 'Stop'
                Identity = $OrgProfileIdentity
            }
            if ($PSBoundParameters.ContainsKey('OrgProfilePath')) {$GetOrgProfileParams.Path = $OrgProfilePath}
            $targetOrgProfile = @(Get-OrgProfile @GetOrgProfileParams)
            switch ($targetOrgProfile.Count)
            {
                1 {}
                0
                {
                    $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $OrgIDUsed -Message "No matching Organization Profile was found for identity $OrgIDUsed"
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
                Default
                {
                    $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $OrgIDUsed -Message "Multiple matching Organization Profiles were found for identity $OrgIDUsed"
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            }
            $AdminUserProfile = GetGenericNewAdminsUserProfileObject -TargetOrgProfile $targetOrgProfile
            foreach ($p in $PSBoundParameters.GetEnumerator())
            {
                if ($p.key -in 'ProfileFolder','Name','MailFromSMTPAddress','IsDefault','Credentials','Systems')
                {$AdminUserProfile.$($p.key) = $p.value}
            }#end foreach
            Write-Output -InputObject $AdminUserProfile
        }#end End
    }#end function New-AdminUserProfile

function Update-AdminUserProfileTypeVersion
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory=$true)]
            $Identity
            ,
            $Path
        )
        $GetAdminUserProfileParams = @{
            Identity = $Identity
            errorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Path'))
        {
            $GetAdminUserProfileParams.Path = $Path
        }
        $AdminUserProfile = Get-AdminUserProfile @GetAdminUserProfileParams
        $BackupProfileUserChoice = Read-Choice -Title 'Backup Profile?' -Message "Create a backup copy of the Admin User Profile $($AdminUserProfile.General.Name)?`r`nYes is Recommended." -Choices 'Yes','No' -DefaultChoice 0 -ReturnChoice -ErrorAction Stop
        if ($BackupProfileUserChoice -eq 'Yes')
        {
            $Folder = Read-FolderBrowserDialog -Description "Choose a directory to contain the backup copy of the Admin User Profile $($AdminUserProfile.General.Name). This should NOT be the current location of the Admin User Profile." -ErrorAction Stop
            if (Test-IsWriteableDirectory -Path $Folder -ErrorAction Stop)
            {
                if ($Folder -ne $AdminUserProfile.General.ProfileFolder -and $folder -ne $AdminUserProfile.ProfileFolder)
                {
                    Export-AdminUserProfile -profile $AdminUserProfile -path $Folder -ErrorAction Stop  > $null
                }
                else
                {
                    throw 'Choose a different directory.'
                }
            }
        }
        $UpdatedAdminUserProfile = UpdateAdminUserProfileObjectVersion -AdminUserProfile $AdminUserProfile
        Export-AdminUserProfile -profile $UpdatedAdminUserProfile -path $AdminUserProfile.profilefolder  > $null
    }
Function Export-AdminUserProfile
    {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        $profile
        ,
        $path = "$($Env:USERPROFILE)\OneShell\"
    )
        if ($profile.Identity -is 'GUID')
        {$name = $($profile.Identity.Guid) + '.JSON'} 
        else
        {$name = $($profile.Identity) + '.JSON'}
        $fullpath = Join-Path -Path $path -ChildPath $name
        $ConvertToJsonParams =@{
            InputObject = $profile
            ErrorAction = 'Stop'
            Depth = 4
        }
        try
        {
            ConvertTo-Json @ConvertToJsonParams | Out-File -FilePath $fullpath -Encoding ascii -ErrorAction Stop -Force 
        }#try
        catch
        {
            $_
            throw "FAILED: Could not write Admin User Profile data to $path"
        }#catch
    }


function GetGenericNewAdminsUserProfileObject
    {
        [cmdletbinding()]
        param
        (
            $TargetOrgProfile
        )
        [pscustomobject]@{
            Identity = [guid]::NewGuid()
            ProfileType = 'OneShellAdminUserProfile'
            ProfileTypeVersion = 1.1
            Name = $targetOrgProfile.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME
            Host = $env:COMPUTERNAME
            User = $env:USERNAME
            Organization = [pscustomobject]@{
                Name = $targetOrgProfile.Name
                Identity = $targetOrgProfile.identity
            }
            ProfileFolder = ''
            MailFromSMTPAddress = ''
            IsDefault = $false
            Systems = @(GetOrgProfileSystemForAdminProfile -OrganizationIdentity $TargetOrgProfile)
            Credentials = @()
        }
    }#end function GetGenericNewAdminsUserProfileObject
function GetOrgProfileSystemForAdminProfile
    {
        [cmdletbinding()]
        param($OrgProfile)
        foreach ($s in $OrgProfile.Systems)
        {
            [PSCustomObject]@{
                Identity = $s.Identity
                AutoConnect = $null
                Credential = $null
                PreferredEndpoint = $null
                PreferredPrefix = $null
            }
        }
    }
function UpdateAdminUserProfileObjectVersion
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            $AdminUserProfile
            ,
            $DesiredProfileTypeVersion = 1.1
        )
        do
        {
            switch ($AdminUserProfile.ProfileTypeVersion)
            {
                {$_ -lt 1}
                {
                    #Upgrade ProfileVersion to 1
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
                    if (-not (Test-Member -InputObject $AdminUserProfile -Name ProfileTypeVersion))
                    {
                        $AdminUserProfile | Add-Member -MemberType NoteProperty -Name ProfileTypeVersion -Value 1.0
                    }
                    #Credentials add Identity
                    foreach ($Credential in $AdminUserProfile.Credentials)
                    {
                        if (-not (Test-Member -InputObject $Credential -Name Identity))
                        {
                            $Credential | Add-Member -MemberType NoteProperty -Name Identity -Value $(New-Guid).guid
                        }
                    }
                    #SystemEntries
                    foreach ($se in $AdminUserProfile.Systems)
                    {
                        if (-not (Test-Member -InputObject $se -Name Credential))
                        {
                            $se | Add-Member -MemberType NoteProperty -Name Credential -Value $null
                        }
                        foreach ($credential in $AdminUserProfile.Credentials)
                        {
                            if (Test-Member -InputObject $credential -Name Systems)
                            {
                                if ($se.Identity -in $credential.systems)
                                {$se.credential = $credential.Identity}
                            }
                        }
                    }
                    #Credentials Remove Systems
                    $UpdatedCredentialObjects = @(
                        foreach ($Credential in $AdminUserProfile.Credentials)
                        {
                            if (Test-Member -InputObject $Credential -Name Systems)
                            {
                                $UpdatedCredential = $Credential | Select-Object -Property Identity,Username,Password
                                $UpdatedCredential
                            }
                            else
                            {
                                $Credential
                            }
                        }
                    )
                    $AdminUserProfile.Credentials = $UpdatedCredentialObjects   
                }#end $_ -lt 1
                {$_ -eq 1}
                {
                    $NewMembers = ('ProfileFolder','Name','MailFromSMTPAddress','IsDefault')
                    foreach ($nm in $NewMembers)
                    {
                        if (-not (Test-Member -InputObject $AdminUserProfile -Name $nm))
                        {
                            $AdminUserProfile | Add-Member -MemberType NoteProperty -Name $nm -Value $null
                        }
                        switch ($nm)
                        {
                            'MailFromSMTPAddress'
                            {$AdminUserProfile.$nm = $AdminUserProfile.General.MailFrom}
                            'IsDefault'
                            {$AdminUserProfile.$nm = $AdminUserProfile.general.default}
                            Default
                            {$AdminUserProfile.$nm = $AdminUserProfile.General.$nm}
                        }
                    }
                    $AdminUserProfile | Add-Member -MemberType NoteProperty -Value $([pscustomobject]@{Identity = $null;Name = $null}) -name Organization
                    $AdminUserProfile.Organization.Identity = $AdminUserProfile.General.OrganizationIdentity
                    $AdminUserProfile | Remove-member -member General
                    $AdminUserProfile.ProfileTypeVersion = 1.1
                }
            }#end switch
        }
        Until ($AdminUserProfile.ProfileTypeVersion -eq $DesiredProfileTypeVersion)
        Write-Output -InputObject $AdminUserProfile
    } #UpdateAdminUserProfileObjectVersion





function AddAdminUserProfileFolders
    {
        [cmdletbinding()]
        param
        (
        $AdminUserProfile
        )
        $profileFolder = $AdminUserProfile.ProfileFolder
        if ($null -eq $profileFolder -or [string]::IsNullOrEmpty($profileFolder))
        {throw("Admin User Profile $($AdminUserProfile.Identity) Profile Folder is invalid.")}
        if (-not (Test-Path -Path $profileFolder))
        {
            New-Item -Path $profileFolder -ItemType Directory -ErrorAction Stop | Out-Null
        }
        $profileSubfolders =  $(join-path $profilefolder 'Logs'), $(join-path $profilefolder 'Export'),$(join-path $profileFolder 'InputFiles')
        foreach ($folder in $profileSubfolders)
        {
            if (-not (Test-Path -Path $folder))
            {
                New-Item -Path $folder -ItemType Directory -ErrorAction Stop | Out-Null
            }
        }
    }
function New-AdminUserProfileCredential
{
    [cmdletbinding()]
    param
    (
        #Add Location Validation to Parameter validation script
        [string[]]$Path = "$env:UserProfile\OneShell\"
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Username
        ,
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [securestring]$Password
    )#end param
    DynamicParam
    {
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
        $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
        $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -DPDictionary $dictionary -Mandatory $true        
        Write-Output -InputObject $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        $getAdminUserProfileParams = @{
            ErrorAction = 'Stop'
            Path = $Path
            Identity = $ProfileIdentity
        }
        $AdminProfile = Get-AdminUserProfile @getAdminUserProfileParams
        $NewCredential = $(
            switch ($PSBoundParameters.ContainsKey('Username'))
            {
                $true
                {
                    switch ($PSBoundParameters.ContainsKey('Password'))
                    {
                        $true
                        {
                            New-Object System.Management.Automation.PSCredential ($Username,$Password)
                        }
                        $false
                        {
                            $host.ui.PromptForCredential('New Credential','Specify the Password for the credential',$Username,'')
                        }
                    }
                }
                $false
                {
                    $host.ui.PromptForCredential('New Credential','Specify the Username and Password for the credential','','')
                }
            }
        )
        if ($NewCredential -is [PSCredential])
        {
            $AdminProfileCredential = Convert-CredentialToAdminProfileCredential -credential $NewCredential
            $AdminProfile.Credentials += $AdminProfileCredential
            $exportAdminUserProfileParams = @{
                profile = $AdminProfile
                path = $Path
                ErrorAction = 'Stop'
            }
            Export-AdminUserProfile @exportAdminUserProfileParams
        }
    }
}
function Remove-AdminUserProfileCredential
{
    [cmdletbinding(DefaultParameterSetName = 'ProfileNameCredentialUserName')]
    param
    (
        #Add Location Validation to Parameter validation script
        [parameter(ParameterSetName = 'ProfileIdentityCredentialIdentity')]
        [parameter(ParameterSetName = 'ProfileIdentityCredentialUserName')]
        [parameter(ParameterSetName = 'ProfileNameCredentialUserName')]
        [parameter(ParameterSetName = 'ProfileNameCredentialIdentity')]
        #[ValidateScript({AddAdminUserProfileFolders -path $_; Test-DirectoryPath -Path $_})]
        [string[]]$Path = "$env:UserProfile\OneShell\"
        ,
        [parameter(ParameterSetName = 'ProfileIdentityCredentialIdentity')]
        [parameter(ParameterSetName = 'ProfileNameCredentialIdentity')]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'ProfileIdentityCredentialUserName')]
        [parameter(ParameterSetName = 'ProfileNameCredentialUserName')]
        [string]$Username
    )#end param
    DynamicParam
    {
        if ($null -eq $Path)
        {
            $path = "$env:UserProfile\OneShell\"
        }
        switch -Wildcard ($PSCmdlet.ParameterSetName)
        {
            'ProfileName*'
            {
                $profileNames = @(GetPotentialAdminUserProfiles -path $Path | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue)
                $dictionary = New-DynamicParameter -Name 'ProfileName' -Type $([String[]]) -ValidateSet $profileNames 
            }
            'ProfileIdentity*'
            {
                $profileIdentities = @(GetPotentialAdminUserProfiles -path $Path | Select-Object -ExpandProperty Identity)                
                $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String[]]) -ValidateSet $profileIdentities
            }
        }
        Write-Output -InputObject $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        $getAdminUserProfileParams = @{
            ErrorAction = 'Stop'
        }
        if ($null -ne $path)
        {$getAdminUserProfileParams.path = $path}
        switch -Wildcard ($PSCmdlet.ParameterSetName)
        {
            'ProfileName*'
            {
                $getAdminUserProfileParams.Name = $ProfileName
            }
            'ProfileIdentity*'
            {
                $getAdminUserProfileParams.identity = $ProfileIdentity
            }
        }
        $AdminProfile = Get-AdminUserProfile @getAdminUserProfileParams
        if ($AdminProfile.Credentials.Count -eq 0) {throw('There are no credentials to remove')}
        if (-not $PSBoundParameters.ContainsKey('Identity') -and -not $PSBoundParameters.ContainsKey('UserName'))
        {
            $SelectedCredential = Select-AdminUserProfileCredential -Credentials $AdminProfile.Credentials -Operation Remove
        }
        else
        {
            switch -Wildcard ($PSCmdlet.ParameterSetName)
            {
                '*CredentialUserName'
                {
                    $SelectedCredential = $AdminProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $UserName}
                }
                '*CredentialIdentity'
                {
                    $SelectedCredential = $AdminProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                }
            }
        }
        $adminProfile.Credentials = @($AdminProfile.Credentials | Where-Object -FilterScript {$_ -ne $SelectedCredential})
        $exportAdminUserProfileParams = @{
            profile = $AdminProfile
            path = $Path
            ErrorAction = 'Stop'
        }
        Export-AdminUserProfile @exportAdminUserProfileParams
    }
}
function Set-AdminUserProfileCredential
{
    [cmdletbinding(DefaultParameterSetName = 'ProfileName')]
    param
    (
        #Add Location Validation to Parameter validation script
        [parameter(ParameterSetName = 'ProfileName')]
        [parameter(ParameterSetName = 'ProfileIdentity')]
        [string[]]$Path = "$env:UserProfile\OneShell\"
        ,
        [parameter(ParameterSetName = 'ProfileName')]
        [parameter(ParameterSetName = 'ProfileIdentity')]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'ProfileName')]
        [ValidateNotNullOrEmpty()]
        [parameter(ParameterSetName = 'ProfileIdentity')]
        [ValidateNotNullOrEmpty()]
        [string]$Username
        ,
        [parameter(ParameterSetName = 'ProfileName')]
        [ValidateNotNullOrEmpty()]
        [parameter(ParameterSetName = 'ProfileIdentity')]
        [ValidateNotNullOrEmpty()]
        [string]$NewUsername
        ,
        [parameter(ParameterSetName = 'ProfileName')]
        [ValidateNotNullOrEmpty()]
        [parameter(ParameterSetName = 'ProfileIdentity')]
        [ValidateNotNullOrEmpty()]
        [securestring]$NewPassword
    )#end param
    DynamicParam
    {
        if ($null -eq $Path)
        {
            $path = "$env:UserProfile\OneShell\"
        }
        $profileNames = @(GetPotentialAdminUserProfiles -path $Path | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue)
        $profileIdentities = @(GetPotentialAdminUserProfiles -path $Path | Select-Object -ExpandProperty Identity)
        $dictionary = New-DynamicParameter -Name 'ProfileName' -Type $([String[]]) -ValidateSet $profileNames -ParameterSetName 'ProfileName'
        $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String[]]) -ValidateSet $profileIdentities -DPDictionary $dictionary -ParameterSetName 'ProfileIdentity'
        Write-Output -InputObject $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        $getAdminUserProfileParams = @{
            ErrorAction = 'Stop'
        }
        if ($null -ne $path)
        {$getAdminUserProfileParams.path = $path}
        switch ($PSCmdlet.ParameterSetName)
        {
            'ProfileName'
            {
                $getAdminUserProfileParams.Name = $ProfileName
            }
            'ProfileIdentity'
            {
                $getAdminUserProfileParams.identity = $ProfileIdentity
            }
        }
        $AdminProfile = Get-AdminUserProfile @getAdminUserProfileParams
        if ($AdminProfile.Credentials.Count -eq 0) {throw('There are no credentials to set')}
        $SelectedCredential = $(
            if (-not $PSBoundParameters.ContainsKey('Identity') -and -not $PSBoundParameters.ContainsKey('UserName'))
            {
                Select-AdminUserProfileCredential -Credentials $AdminProfile.Credentials -Operation Remove
            }
            else
            {
                switch ('')
                {
                    {$PSBoundParameters.ContainsKey('Identity')}
                    {
                        $AdminProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                        break
                    }
                    {$PSBoundParameters.ContainsKey('Username')}
                    {
                        $AdminProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $UserName} | Select-Object -First 1
                        break
                    }
                }
            }
        )
        if ($null -eq $SelectedCredential) {throw('No cedential found')}
        $EditedCredential = $(
            switch ($SelectedCredential)
            {
                #Both Username and Password Specified - Update Both
                {$PSBoundParameters.ContainsKey('NewUsername') -and $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($NewUsername,$NewPassword)
                }
                #Only Username Specified - Update Username, Preserve Password
                {$PSBoundParameters.ContainsKey('NewUsername') -and -not $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($NewUsername,$($SelectedCredential.Password | ConvertTo-SecureString))
                }
                #Only Password Specified - Update Password, Preserve Username
                {-not $PSBoundParameters.ContainsKey('NewUsername') -and $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($SelectedCredential.Username,$Password)
                }
                #nothing Specified except Identity - suggest preserving username, prompt to update password
                {-not $PSBoundParameters.ContainsKey('NewUsername') -and -not $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    $host.ui.PromptForCredential('Set Credential','Specify the Password for the credential',$SelectedCredential.Username,'')
                }
            }
        )
        $AdminProfileCredential = Convert-CredentialToAdminProfileCredential -credential $EditedCredential -Identity $SelectedCredential.Identity
        $Index = Get-ArrayIndexForValue -array $AdminProfile.Credentials -value $SelectedCredential.Identity -property Identity -ErrorAction Stop
        $adminProfile.Credentials[$Index] = $AdminProfileCredential
        $exportAdminUserProfileParams = @{
            profile = $AdminProfile
            path = $Path
            ErrorAction = 'Stop'
        }
        Export-AdminUserProfile @exportAdminUserProfileParams
    }
}
function Get-AdminUserProfileCredential
{
    [cmdletbinding(DefaultParameterSetName = 'Name')]
    param
    (
        #Add Location Validation to Parameter validation script
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'Name')]
        #[ValidateScript({AddAdminUserProfileFolders -path $_; Test-DirectoryPath -Path $_})]
        [string[]]$Path = "$env:UserProfile\OneShell\"
        ,
        [string]$Identity
        ,
        [string]$UserName
    )#end param
    DynamicParam
    {
        if ($null -eq $Path)
        {
            $path = "$env:UserProfile\OneShell\"
        }
        $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String[]]) -ValidateSet @(GetPotentialAdminUserProfiles -path $Path | Select-Object -ExpandProperty Identity) -ParameterSetName Identity
        $dictionary = New-DynamicParameter -Name 'ProfileName' -Type $([String[]]) -ValidateSet @(GetPotentialAdminUserProfiles -path $Path | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue) -ParameterSetName Name -DPDictionary $dictionary
        Write-Output -InputObject $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        $getAdminUserProfileParams = @{
            ErrorAction = 'Stop'
        }
        if ($null -ne $path)
        {$getAdminUserProfileParams.path = $path}
        switch ($PSCmdlet.ParameterSetName)
        {
            'Name'
            {
                $getAdminUserProfileParams.Name = $ProfileName
            }
            'Identity'
            {
                $getAdminUserProfileParams.identity = $ProfileIdentity
            }
        }
        $AdminProfile = Get-AdminUserProfile @getAdminUserProfileParams        
        if (-not [string]::IsNullOrEmpty($Identity) -or -not [string]::IsNullOrEmpty($UserName))
        {$AdminProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Username -eq $username}}
        else
        {$adminProfile.Credentials}
    }
}
function Convert-CredentialToAdminProfileCredential
{
    [cmdletbinding()]
    param
    (
        $credential
        ,
        [string]$Identity
    )
    if ($null -eq $Identity -or [string]::IsNullOrWhiteSpace($Identity))
    {$Identity = $(New-Guid).guid}
    $credential | Add-Member -MemberType NoteProperty -Name 'Identity' -Value $Identity
    $credential | Select-Object -Property @{n='Identity';e={$_.Identity}},@{n='UserName';e={$_.UserName}},@{n='Password';e={$_.Password | ConvertFrom-SecureString}}
}
function Select-AdminUserProfileCredential
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $Credentials
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove','Edit')]
        [string]$Operation
    )
    $message = "Select credential to $Operation"
    $CredChoices = @($Credentials.UserName)
    $whichcred = 
        switch ($host.Name -notlike 'Console*')
        {
            $true
            {Read-Choice -Message $message -Choices $CredChoices -DefaultChoice 0 -Title $message -Numbered}
            $false
            {Read-PromptForChoice -Message $message -Choices $CredChoices -DefaultChoice 0 -Title $message -Numbered}
        }
    Write-Output -InputObject $credentials[$whichcred]
}

$AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
#################################################
# Need to update
#################################################
Function Use-AdminUserProfile
{
  [cmdletbinding()]
  param(
    [parameter(ParameterSetName = 'Object',ValueFromPipeline=$true)]
    $AdminUserProfile
    ,
    [parameter(ParameterSetName = 'Identity',ValueFromPipelineByPropertyname = $true)]
    [ValidateScript({Test-DirectoryPath -Path $_})]
    [string[]]$Path
  )
  DynamicParam
  {
      if ($null -eq $Path)
      {
          $path = "$env:UserProfile\OneShell\"
      }
      $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
      $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $AdminProfileIdentities -ParameterSetName Identity -Mandatory $true -ValueFromPipelineByPropertyName
      Write-Output -InputObject $dictionary
  }  
  begin
  {
    switch ($PSCmdlet.ParameterSetName)
    {
        'Object'
        {}
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
    }
    #Check Admin User Profile Version
    $RequiredVersion = 1
    if (! $AdminUserProfile.ProfileTypeVersion -ge $RequiredVersion)
    {
        throw "The selected Admin User Profile $($AdminUserProfile.General.Name) is an older version. Please Run Set-AdminUserProfile -Identity $($AdminUserProfile.Identity) or Update-AdminUserProfileTypeVersion -Identity $($AdminUserProfile.Identity) to update it to version $RequiredVersion."
    }
  }#begin
  process{
    #check if there is already a "Current" admin profile and if it is different from the one being used/applied by this run of the function
    #need to add some clean-up functionality for sessions when there is a change, or make it always optional to reset all sessions with this function
    if (($script:CurrentAdminUserProfile -ne $null) -and $AdminUserProfile.Identity -ne $script:CurrentAdminUserProfile.Identity) 
    {
        $script:CurrentAdminUserProfile = $AdminUserProfile
        Write-Warning -Message "Admin User Profile has been changed to $($script:CurrentAdminUserProfile.Identity). Remove PSSessions and then re-establish connectivity using Connect-RemoteSystems."
    }
    else {
        $script:CurrentAdminUserProfile = $AdminUserProfile
        Write-Verbose -Message "Admin User Profile has been set to $($script:CurrentAdminUserProfile.Identity), $($script:CurrentAdminUserProfile.general.name)."
    }
    #Retrieve the systems from the current org profile
    $systems = GetOrgProfileSystem -OrganizationIdentity $AdminUserProfile.general.OrganizationIdentity
    #Build the autoconnect property and the mapped credentials for each system and store in the CurrentOrgAdminProfileSystems Script variable
    $Script:CurrentOrgAdminProfileSystems = 
    @(
        foreach ($sys in $systems) {
            $sys | Add-Member -MemberType NoteProperty -Name Autoconnect -Value $null
            $sys | Add-Member -MemberType NoteProperty -Name Credential -value $null
            $adminUserProfileSystem = $AdminUserProfile.systems | Where-Object -FilterScript {$sys.Identity -eq $_.Identity}
            $sys.AutoConnect = $adminUserProfileSystem.AutoConnect
            $PreCredential = @($AdminUserProfile.credentials | Where-Object -FilterScript {$_.Identity -eq $adminUserProfileSystem.Credential})
            if ($PreCredential.count -eq 1)
            {
                $SSPassword = $PreCredential[0].password | ConvertTo-SecureString
                $Credential = New-Object System.Management.Automation.PSCredential($PreCredential[0].Username,$SSPassword)
            }
            else
            {$Credential = $null}
            $sys.Credential = $Credential
            $sys
        }
    )
    #set folder paths
    $script:OneShellAdminUserProfileFolder = $script:CurrentAdminUserProfile.general.ProfileFolder
    #Log Folder and Log Paths
    if ([string]::IsNullOrEmpty($script:CurrentAdminUserProfile.general.LogFolder))
    {
        $Script:LogFolderPath = "$script:OneShellAdminUserProfileFolder\Logs"
    }
    else
    {
        $Script:LogFolderPath = $script:CurrentAdminUserProfile.general.LogFolder
    }
    $Script:LogPath = "$Script:LogFolderPath\$Script:Stamp" + '-AdminOperations.log'
    $Script:ErrorLogPath = "$Script:LogFolderPath\$Script:Stamp" +  '-AdminOperations-Errors.log'
    #Input Files Path
    if ([string]::IsNullOrEmpty($script:CurrentAdminUserProfile.general.InputFilesFolder))
    {
        $Script:InputFilesPath = "$script:OneShellAdminUserProfileFolder\InputFiles\"
    }
    else
    {
        $Script:InputFilesPath = $script:CurrentAdminUserProfile.general.InputFilesFolder + '\'
    }
    #Export Data Path
    if ([string]::IsNullOrEmpty($script:CurrentAdminUserProfile.general.ExportDataFolder))
    {
        $Script:ExportDataPath = "$script:OneShellAdminUserProfileFolder\Export\"
    }
    else
    {
            $Script:ExportDataPath = $script:CurrentAdminUserProfile.general.ExportDataFolder + '\'
    }    
    Write-Output -InputObject $true
  }#process
}
function Set-AdminUserProfile
{
    [cmdletbinding(DefaultParameterSetName="Identity")]
    param
    (
        [Parameter(ParameterSetName = 'Object',ValueFromPipeline,Mandatory)]
        [ValidateScript({$_.ProfileType -eq 'OneShellAdminUserProfile'})]
        [psobject]$ProfileObject 
        ,
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript({Test-DirectoryPath -Path $_})]
        [string[]]$Path = "$env:UserProfile\OneShell\"
    )
    DynamicParam
    {
        if ($null -eq $Path)
        {
            $path = "$env:UserProfile\OneShell\"
        }
        $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
        $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $AdminProfileIdentities -ParameterSetName 'Identity' -Mandatory $true
        Write-Output -InputObject $dictionary
    }
    End
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
                    ErrorAction = 'Stop'
                    Identity = $Identity
                }
                if ($PSBoundParameters.ContainsKey('Path'))
                {
                    $GetAdminUserProfileParams.Path = $Path
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
        #Put the actual editing code here:
    }#End End
}# Set-AdminUserProfile