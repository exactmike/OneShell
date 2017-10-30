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
        [parameter(ParameterSetName = 'OrgName')]
        [parameter(ParameterSetName = 'GetDefault')]
        [ValidateScript({Test-DirectoryPath -path $_})]
        [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'OrgName')]
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
        if ($null -eq $local:Path) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
        $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String[]]) -ValidateSet @(GetPotentialOrgProfiles -path $local:Path | Select-Object -ExpandProperty Identity) -ParameterSetName Identity
        $dictionary = New-DynamicParameter -Name 'OrgName' -Type $([String[]]) -ValidateSet @(GetPotentialOrgProfiles -path $local:Path | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue) -ParameterSetName OrgName -DPDictionary $dictionary
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
                            $OrgProfiles = @($FoundOrgProfiles | Where-Object -FilterScript {$_.Identity -in $Identity})
                            Write-Output -inputobject $OrgProfiles
                        }#Identity
                        'OrgName'
                        {
                            $OrgProfiles = @($FoundOrgProfiles | Where-Object -FilterScript {$_.Name -in $OrgName})
                            Write-Output -inputobject $OrgProfiles
                        }#OrgName
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
        [cmdletbinding(DefaultParameterSetName = 'GetCurrent')]
        param
        (
            [parameter()]
            [switch]$IsDefault
            ,
            [parameter(ParameterSetName = 'Identity')]
            [parameter(ParameterSetName = 'OrgName')]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        )
        DynamicParam
        {
            if ($null -eq $Path) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $dictionary = New-DynamicParameter -Name 'OrgIdentity' -Type $([String[]]) -ValidateSet @(GetPotentialOrgProfiles -path $Path | Select-Object -ExpandProperty Identity) -ParameterSetName Identity
            $dictionary = New-DynamicParameter -Name 'OrgName' -Type $([String[]]) -ValidateSet @(GetPotentialOrgProfiles -path $Path | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue) -ParameterSetName OrgName -DPDictionary $dictionary
            $dictionary = New-DynamicParameter -Name 'ServiceType' -Type $([string[]]) -ValidateSet @(getorgservicetypes) -HelpMessage 'Specify one or more system types to include' -Mandatory $false -DPDictionary $dictionary
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            switch ($PSCmdlet.ParameterSetName)
            {
                'GetCurrent'
                {
                    $profile = Get-OrgProfile -GetCurrent
                }
                'Identity'
                {
                    $profile = Get-OrgProfile -Identity $OrgIdentity
                }
                'OrgName'
                {
                    $profile = Get-OrgProfile -OrgName $OrgName
                }
            }
            $OutputSystems = @($profile.systems)
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
  [cmdletbinding(DefaultParameterSetName = 'Object')]
  param
  (
    [parameter(ParameterSetName = 'Object')]
    $profile 
    ,
    [parameter(ParameterSetName = 'Identity')]
    [parameter(ParameterSetName = 'OrgName')]
    [ValidateScript({Test-DirectoryPath -path $_})]
    [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
  )
    DynamicParam
    {
        if ($null -eq $Path) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
        $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String[]]) -ValidateSet @(GetPotentialOrgProfiles -path $Path | Select-Object -ExpandProperty Identity) -ParameterSetName Identity
        $dictionary = New-DynamicParameter -Name 'OrgName' -Type $([String[]]) -ValidateSet @(GetPotentialOrgProfiles -path $Path | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue) -ParameterSetName OrgName -DPDictionary $dictionary
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
            'OrgName'
            {
                $profile = Get-OrgProfile -OrgName $OrgName
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
function GetOrgProfileSystem
    {
        [cmdletbinding()]
        param
        (
            $OrganizationIdentity
        )
        $targetOrgProfile = @(Get-OrgProfile -Identity $OrganizationIdentity)
        switch ($targetOrgProfile.Count)
        {
            1
            {}
            0
            {throw "No matching Organization Profile was found for identity $OrganizationIdentity"}
            Default 
            {throw "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"}
        }
        Write-Output -InputObject $targetOrgProfile.systems
    }
Function Use-AdminUserProfile
{
  [cmdletbinding()]
  param(
    [parameter(ParameterSetName = 'Object',ValueFromPipeline=$true)]
    $AdminUserProfile 
    ,
    [parameter(ParameterSetName = 'Identity',ValueFromPipelineByPropertyname = $true, Mandatory = $true)]
    [string]$Identity
    ,
    [parameter(ParameterSetName = 'Identity',ValueFromPipelineByPropertyname = $true)]
    [ValidateScript({Test-DirectoryPath -Path $_})]
    [string[]]$Path
  )
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
Function Get-AdminUserProfile
{
    [cmdletbinding(DefaultParameterSetName='All')]
    param
    (
        #Add Location Validation to Parameter validation script
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'Name')]
        [parameter(ParameterSetName ='GetDefault')]
        #[ValidateScript({AddAdminUserProfileFolders -path $_; Test-DirectoryPath -Path $_})]
        [string[]]$Path = "$env:UserProfile\OneShell\"
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'Name')]
        [parameter(ParameterSetName = 'GetDefault')]
        $ProfileType = 'OneShellAdminUserProfile'
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'Name')]
        [parameter(ParameterSetName = 'GetDefault')]
        $OrgIdentity
        ,
        [parameter(ParameterSetName = 'GetCurrent')]
        [switch]$GetCurrent
        ,
        [parameter(ParameterSetName = 'GetDefault')]
        [switch]$GetDefault
    )#end param
    DynamicParam
    {
        if ($null -eq $Path)
        {
            $path = "$env:UserProfile\OneShell\"
        }
        $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String[]]) -ValidateSet @(GetPotentialAdminUserProfiles -path $Path | Select-Object -ExpandProperty Identity) -ParameterSetName Identity
        $dictionary = New-DynamicParameter -Name 'Name' -Type $([String[]]) -ValidateSet @(GetPotentialAdminUserProfiles -path $Path | foreach-Object -Process {$_.General.Name} -ErrorAction SilentlyContinue) -ParameterSetName Name -DPDictionary $dictionary
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
                'GetDefault'
                {
                    if ($PSBoundParameters.ContainsKey('OrgIdentity'))
                    {$OrgProfile = Get-OrgProfile -Identity $OrgIdentity}
                    elseif ($null -ne $script:CurrentOrgProfile)
                    {$OrgProfile = $script:CurrentOrgProfile}
                    else
                    {
                        $OrgProfile = Get-OrgProfile -GetDefault
                    }
                    $DefaultAdminUserProfile = GetDefaultAdminUserProfile -OrgIdentity $OrgProfile.Identity -path $path
                    Write-Output -InputObject $DefaultAdminUserProfile
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
                                $FoundAdminUserProfiles | Where-Object -FilterScript {$_.Identity -eq $Identity}
                            }
                            'Name'
                            {
                                $FoundAdminUserProfiles | Where-Object -FilterScript {$_.General.Name -eq $Name}
                            }
                        }#end Switch
                    }#end if
                }#end Default
            }#end Switch
        )#end outputprofiles
        #filter the found profiles for OrgIdentity if specified
        if (-not [string]::IsNullOrWhiteSpace($OrgIdentity))
        {
            if ($OrgIdentity -eq 'CurrentOrg')
            {$OrgIdentity = $script:CurrentOrgProfile.Identity}
            $outputprofiles = $outputprofiles | Where-Object -FilterScript {$_.general.organizationidentity -eq $OrgIdentity}
        }
        #output the found profiles
        Write-Output -InputObject $outputprofiles
    }#end End
}#Get-AdminUserProfile
function New-AdminUserProfile
{
    [cmdletbinding(DefaultParameterSetName = 'OrgName')]
    param
    (
        [Parameter(Mandatory,ParameterSetName = 'OrgName')]
        [Parameter(Mandatory,ParameterSetName = 'OrgIdentity')]
        [ValidateScript({Test-IsWriteableDirectory -path $_})]
        [string]$ProfileDirectory #The folder to use for logs, exports, etc.
        ,
        [Parameter(Mandatory,ParameterSetName = 'OrgName')]
        [Parameter(Mandatory,ParameterSetName = 'OrgIdentity')]
        [string]$MailFromEmailAddress
        ,
        [Parameter(ParameterSetName = 'OrgName')]
        [Parameter(ParameterSetName = 'OrgIdentity')]        
        [pscredential[]]$Credentials = @()
        ,
        [Parameter(ParameterSetName = 'OrgName')]
        [Parameter(ParameterSetName = 'OrgIdentity')]        
        [psobject[]]$Systems = @()
        ,
        [Parameter(ParameterSetName = 'OrgName')]
        [Parameter(ParameterSetName = 'OrgIdentity')]        
        [string]$Name #Overrides the default name of Org-Machine-User
        ,
        [Parameter(ParameterSetName = 'OrgName')]
        [Parameter(ParameterSetName = 'OrgIdentity')]
        [ValidateScript({Test-DirectoryPath -path $_})]
        #[parameter(ParameterSetName = 'OrgIdentity')]
        #[ValidateScript({Test-DirectoryPath -path $_})]
        [string]$OrgProfilePath
        ,
        [Parameter(ParameterSetName = 'OrgName')]
        [Parameter(ParameterSetName = 'OrgIdentity')]
        [bool]$IsDefault = $false #sets this profile as the default for the specified Organization
        ,
        [Parameter(ParameterSetName = 'OrgName')]
        [Parameter(ParameterSetName = 'OrgIdentity')]
        [switch]$Passthru
    )
    DynamicParam
    {
        if ($null -eq $OrgProfilePath -or [string]::IsNullOrEmpty($OrgProfilePath))
        {
            Write-Verbose -Message "Populating the OrgProfilePath with the default value" -Verbose
            $OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"
        }
        $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $OrgProfilePath)
        $Names = @($PotentialOrgProfiles.Name | Where-Object -FilterScript {-not [string]::IsNullOrWhiteSpace($_)})
        $Identities = @($PotentialOrgProfiles.Identity | Where-Object -FilterScript {-not [string]::IsNullOrWhiteSpace($_)})
        switch ($PSCmdlet.ParameterSetName)
        {
            'OrgName'
            {$dictionary = New-DynamicParameter -Name 'OrgName' -Type $([String]) -ValidateSet $Names -Mandatory $true -Position 1 -ParameterSetName 'OrgName'}
            'OrgIdentity'
            {$dictionary = New-DynamicParameter -Name 'OrgIdentity' -Type $([String]) -ValidateSet $Identities -Mandatory $true -Position 1 -ParameterSetName 'OrgIdentity'}
        }
        Write-Output -InputObject $dictionary
    }
    End
    {
        Set-DynamicParameterVariable -dictionary $dictionary
        $GetOrgProfileParams = @{ErrorAction = 'Stop'}
        if ($PSBoundParameters.ContainsKey('OrgProfilePath')) {$GetOrgProfileParams.Path = $OrgProfilePath}
        switch ($PSCmdlet.ParameterSetName)
        {
            'OrgName'
            {
                $OrgIDUsed = $OrgName
                $GetOrgProfileParams.OrgName = $OrgName
            }
            'OrgIdentity'
            {
                $OrgIDUsed = $OrgIdentity
                $GetOrgProfileParams.Identity = $OrgIdentity
            }
        }
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
        $AdminUserProfile = GetGenericNewAdminsUserProfileObject -OrganizationIdentity $targetOrgProfile.Identity
        if ($Passthru -eq $true)
        {
            Write-Output -InputObject $AdminUserProfile
        }
    }#end End
}#end function New-AdminUserProfile
function Set-AdminUserProfile
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
        $dictionary = New-DynamicParameter -Name 'Name' -Type $([String[]]) -ValidateSet @(GetPotentialAdminUserProfiles -path $Path | foreach-Object -Process {$_.General.Name} -ErrorAction SilentlyContinue) -Mandatory $true -ParameterSetName Name -DPDictionary $dictionary 
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
        $OrganizationIdentity = $AdminUserProfile.General.OrganizationIdentity
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
function Update-AdminUserProfileTypeVersion
{
  [cmdletbinding()]
  param(
    [parameter(Mandatory=$true)]
    $Identity
    ,
  $Path)
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
        if ($Folder -ne $AdminUserProfile.General.ProfileFolder)
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
  Export-AdminUserProfile -profile $UpdatedAdminUserProfile -path $AdminUserProfile.general.profilefolder  > $null
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
        Write-Output -InputObject $true
    }#try
    catch
    {
        $_
        throw "FAILED: Could not write Admin User Profile data to $path"
    }#catch
}
#Admin Profile Helper Functions - not exported
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
function GetGenericNewAdminsUserProfileObject
{
    [cmdletbinding()]
    param
    (
        $OrganizationIdentity
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
        MailFrom = ''
        Default = $false
        Systems = @(GetOrgProfileSystemForAdminProfile -OrganizationIdentity $OrganizationIdentity)
        Credentials = @()
    }
}#end function GetGenericNewAdminsUserProfileObject
function GetOrgProfileSystemForAdminProfile
{
    [cmdletbinding()]
    param($OrganizationIdentity)
    $OrgProfileSystems = GetOrgProfileSystem -OrganizationIdentity $OrganizationIdentity
    foreach ($s in $OrgProfileSystems)
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
  param($AdminUserProfile)
  #Check Admin User Profile Version
  $RequiredVersion = 1
  if (! $AdminUserProfile.ProfileTypeVersion -ge $RequiredVersion) {
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
  }
  Write-Output -InputObject $AdminUserProfile
} #UpdateAdminUserProfileObjectVersion
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
function SaveAdminUserProfile
{
[cmdletbinding()]
  param(
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
function AddAdminUserProfileFolders
{
  [cmdletbinding()]
  param
  (
    $AdminUserProfile
    ,
    $path = $env:USERPROFILE + '\OneShell'
  )
  $AdminUserJSONProfileFolder = $path
  if (-not (Test-Path -Path $AdminUserJSONProfileFolder))
  {
    New-Item -Path $AdminUserJSONProfileFolder -ItemType Directory -ErrorAction Stop
  }
  $profilefolder = $AdminUserProfile.General.ProfileFolder 
  $profilefolders =  $($profilefolder + '\Logs'), $($profilefolder + '\Export'),$($profilefolder + '\InputFiles')
  foreach ($folder in $profilefolders)
  {
    if (-not (Test-Path -Path $folder))
    {
        New-Item -Path $folder -ItemType Directory -ErrorAction Stop
    }
  }
  $true
}
function SetAdminUserProfileCredentials
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
    )
    switch ($PSCmdlet.ParameterSetName)
    {
        'Edit' {
            $editableCredentials = @($Credentials | Select-Object -Property @{n='Identity';e={$_.Identity}},@{n='UserName';e={$_.UserName}},@{n='Password';e={$_.Password | ConvertTo-SecureString}})
        }
        'New' {$editableCredentials = @()}
    }
    #$systems = $systems | Where-Object -FilterScript {$_.AuthenticationRequired -eq $null -or $_.AuthenticationRequired -eq $true} #null is for backwards compatibility if the AuthenticationRequired property is missing.
    $labels = $systems | Select-Object -Property @{n='name';e={$_.SystemType + ': ' + $_.Name}}
    do {
        $prompt = @"
You may associate a credential with each of the following systems for auto connection or on demand connections/usage:

$($labels.name -join "`n")

You have created the following credentials so far:
$($editableCredentials.UserName -join "`n")

In the next step, you may modify the association of these credentials with the systems above.

Would you like to add, edit, or remove a credential?"
"@
        $response = Read-Choice -Message $prompt -Choices 'Add','Edit','Remove','Done' -DefaultChoice 0 -Title 'Add/Remove Credential?'
        switch ($response) {
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
                    $whichcred = Read-Choice -Message 'Select a credential to edit' -Choices $CredChoices -DefaultChoice 0 -Title 'Select Credential to Edit'
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
                    $whichcred = Read-Choice -Message 'Select a credential to remove' -Choices $CredChoices -DefaultChoice 0 -Title 'Select Credential to Remove'
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
Function GetDefaultAdminUserProfile
{
  [cmdletbinding()]
  param(
    [string[]]$path
    ,
    $OrgIdentity
  )
  $GetAdminUserProfileParams=@{
    ErrorAction = 'Stop'
  }
  if ($PSBoundParameters.ContainsKey('OrgIdentity')) {$GetAdminUserProfileParams.OrgIdentity = $OrgIdentity}
  if ($PSBoundParameters.ContainsKey('path')) {$GetAdminUserProfileParams.path = $path}
  $AdminUserProfiles = @(Get-AdminUserProfile @GetAdminUserProfileParams)
  if ($AdminUserProfiles.count -ge 1)
  {
    $DefaultAdminUserProfiles = @($AdminUserProfiles | Where-Object -FilterScript {$_.General.Default -eq $true})
    switch ($DefaultAdminUserProfiles.Count) 
    {
        {$_ -eq 1}
        {
            $DefaultAdminUserProfile = $DefaultAdminUserProfiles[0]
            $DefaultAdminUserProfile
        }
        {$_ -gt 1}
        {
            throw "FAILED: Multiple Admin User Profiles Are Set as Default for $OrgIdentity`: $($DefaultAdminUserProfile.Identity -join ',')"
        }
        {$_ -lt 1}
        {
            throw "FAILED: No Admin User Profiles Are Set as Default for $OrgIdentity"
        }
    }#Switch
  }
  else
  {
    throw "FAILED: Find Default Admin User Profile Set as Default for $OrgIdentity"
  }
}
