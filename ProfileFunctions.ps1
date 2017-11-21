##########################################################################################################
#Profile and Environment Initialization Functions
##########################################################################################################
#################################################
# Private Functions
#################################################
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
#end funciton GetPotentialOrgProfiles
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
#End function GetPotentialAdminUserProfiles
function GetOrgProfileSystemServiceTypes
    {
        #change this list in other functions as well when you modify here.
        'PowerShell','SQLDatabase','ExchangeOnPremises','ExchangeOnline','ExchangeComplianceCenter','AADSyncServer','AzureADTenant','Office365Tenant','ActiveDirectoryDomain','ActiveDirectoryGlobalCatalog','ActiveDirectoryLDS','MailRelayEndpoint','SkypeOrganization'
    }
#end function GetOrgProfileSystemServiceTypes
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
                OrganizationSpecificModules = @()
                Systems = @()
        }
    }
#end function GetGenericNewOrgProfileObject
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
            Defaults = [PSCustomObject]@{
                ProxyEnabled = $null
                AuthenticationRequired = $true
                UseTLS = $null
                AuthMethod = $null
                CommandPrefix = $null
            }
            Endpoints = @()
            ServiceTypeAttributes = [PSCustomObject]@{}
        }
    }
#end function NewGenericOrgSystemObject
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
        switch -Wildcard ($ServiceType)
        {
            #one entry for each ServiceType with ServiceTypeAttributes
            '*Tenant'
            {$OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name 'TenantSubDomain' -Value $TenantSubDomain}
            'Exchange*'
            {
            }
            'ActiveDirectory*'
            {
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
    }
#end function AddServiceTypeAttributesToGenericOrgSystemObject
function NewGenericSystemEndpointObject
    {
        [cmdletbinding()]
        param()
        [PSCustomObject]@{
            Identity = [guid]::NewGuid()
            AddressType = $null
            Address = $null
            ServicePort = $null
            UseTLS = $null
            ProxyEnabled = $null
            CommandPrefix = $null
            AuthenticationRequired = $null
            AuthMethod = $null
            EndPointGroup = $null
            Precedence = $null
            EndPointType = $null
            ServiceTypeAttributes = [PSCustomObject]@{}
            ServiceType = $null
            PSRemoting = $null
            AllowRedirection = $null
        }
    }
#end function NewGenericSystemEndpointObject
function NewGenericAdminsUserProfileObject
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
            Systems = @()
            Credentials = @()
        }
    }#end function NewGenericAdminsUserProfileObject
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
    }#end function GetOrgProfileSystemForAdminProfile
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
                    $NewMembers = ('ProfileFolder','Name','MailFromSMTPAddress')
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
#################################################
# Public Functions
#################################################
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
                        }#switch
                    }#if
                }#Default
                }#switch
            )
            #output the profiles
            write-output -InputObject $outputprofiles
        }#end End
    }
#end Function Get-OrgProfile
function New-OrgProfile
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            [string]$Name
            ,
            [paramter()]
            [string[]]$OrganizationSpecificModules
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        )
        $GenericOrgProfileObject = NewGenericOrgProfileObject
        $GenericOrgProfileObject.Name = $Name
        $GenericOrgProfileObject.OrganizationSpecificModules = $OrganizationSpecificModules
        Export-OrgProfile -profile $GenericOrgProfileObject -path $path -erroraction Stop
    }
#end function New-OrgProfile
function Set-OrgProfile
    {
        [cmdletbinding(DefaultParameterSetName = 'Identity')]
        param
        (
            [parameter(ParameterSetName = 'Object')]
            [ValidateScript({$_.ProfileType -eq 'OneShellOrgProfile'})]
            [psobject]$OrgProfile
            ,
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$Name
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1 -ParameterSetName 'Identity'
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            switch ($PSCmdlet.ParameterSetName)
            {
                'Identity'
                {
                    if ($null -eq $Identity)
                    {
                        $OrgProfile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
                    }
                    else
                    {
                        #Get the Org Profile
                        $GetOrgProfileParams = @{
                            ErrorAction = 'Stop'
                            Identity = $Identity
                            Path = $Path
                        }
                        $OrgProfile = $(Get-OrgProfile @GetOrgProfileParams)
                    }
                }
                'Object'
                {
                }
            }#end Switch
            Write-Verbose -Message "Selected Org Profile is $($orgProfile.Name)"
            foreach ($p in $PSBoundParameters.GetEnumerator())
            {
                if ($p.key -in @('Name'))
                {
                    $OrgProfile.$($p.key) = $p.value
                }
            }
            Export-OrgProfile -profile $OrgProfile -Path $Path -ErrorAction 'Stop'
        }
    }
#end function Set-OrgProfile
Function Export-OrgProfile
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory=$true)]
            $profile
            ,
            [parameter()]
            [AllowNull()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            $Path
        )
        $name = [string]$($profile.Identity.tostring()) + '.json'
        if ($null -eq $Path)
        {
            Write-Verbose -Message "Using Default Profile Location"
            $FilePath = Join-Path $script:OneShellOrgProfilePath[0] $name
        }
        else
        {
            $FilePath = Join-Path $Path $name
        }
        Write-Verbose -Message "Profile File Export Path is $FilePath"
        $JSONparams=@{
            InputObject = $profile
            ErrorAction = 'Stop'
            Depth = 6
        }
        $OutParams = @{
            ErrorAction = 'Stop'
            FilePath = $FilePath
            Encoding = 'ascii'
            Force = $true
        }
        try
        {
            ConvertTo-Json @JSONparams | Out-File @OutParams
        }#end try
        catch
        {
            $_
            throw "FAILED: Could not write Org Profile data to $FilePath"
        }#end catch
    }
#end Function Export-OrgProfile
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
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1 -ParameterSetName 'Identity'
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
                    if ($null -eq $Identity)
                    {
                        $Profile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
                    }
                    else
                    {
                        #Get the Org Profile
                        $GetOrgProfileParams = @{
                            ErrorAction = 'Stop'
                            Identity = $Identity
                            Path = $Path
                        }
                        $Profile = $(Get-OrgProfile @GetOrgProfileParams)
                    }
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
    }
#end function Use-OrgProfile
function New-OrgProfileSystem
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            [string]$Name
            ,
            [parameter()]
            [string]$Description
            ,
            [parameter(Mandatory)]
            [ValidateSet('PowerShell','SQLDatabase','ExchangeOnPremises','AADSyncServer','AzureADTenant','Office365Tenant','ActiveDirectoryDomain','ActiveDirectoryGlobalCatalog','ActiveDirectoryLDS','MailRelayEndpoint','SkypeOrganization','ExchangeOnline','ExchangeComplianceCenter')] #convert to dynamic parameter sourced from single place to ease adding systems types later
            [string]$ServiceType
            
            ,
            [parameter()]
            [validateset('$true','$false')]
            [bool]$ProxyEnabled
            ,
            [parameter()]
            [validateset('$true','$false')]
            [bool]$AuthenticationRequired
            ,
            [parameter()]
            [validateset('$true','$false')]
            [bool]$UseTLS
            ,
            [parameter()]
            [ValidateSet('Basic','Kerberos','Integrated')]
            $AuthMethod
            ,
            [parameter()]
            [ValidateLength(2,5)]
            [string]$CommandPrefix
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles.Name;$PotentialOrgProfiles.Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            #build any service type specific parameters that may be needed
            switch -Wildcard ($ServiceType)
            {
                '*Tenant'
                {
                    $Dictionary = New-DynamicParameter -Name 'TenantSubdomain' -Type $([string]) -Mandatory:$true -DPDictionary $dictionary
                }
                'ActiveDirectory*'
                {
                    $Dictionary = New-DynamicParameter -Name 'ADUserAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
                    $Dictionary = New-DynamicParameter -Name 'ADGroupAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
                    $Dictionary = New-DynamicParameter -Name 'ADContactAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
                }
                'PowerShell'
                {
                    $Dictionary = New-DynamicParameter -Name 'SessionManagementGroups' -Type $([string[]]) -Mandatory:$false -DPDictionary $dictionary
                }
                'SQLDatabase'
                {
                    $Dictionary = New-DynamicParameter -Name 'SQLInstanceType' -Type $([string]) -Mandatory:$true -ValidateSet 'OnPremises','AzureSQL' -DPDictionary $dictionary
                    $Dictionary = New-DynamicParameter -Name 'Database' -Type $([string]) -Mandatory:$true -DPDictionary $Dictionary
                }
            }
            Write-Output -InputObject $dictionary
        }#End DynamicParam
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            if ($null -eq $ProfileIdentity)
            {
                $OrgProfile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
            }
            else
            {
                #Get the Org Profile
                $GetOrgProfileParams = @{
                    ErrorAction = 'Stop'
                    Identity = $ProfileIdentity
                    Path = $Path
                }                
                $OrgProfile = $(Get-OrgProfile @GetOrgProfileParams)
            }
            #Build the System Object
            $GenericSystemObject = NewGenericOrgSystemObject
            $GenericSystemObject.ServiceType = $ServiceType
            #Edit the selected System
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            #Set the common System Attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'Name','Description')
                {$GenericSystemObject.$($vp.name) = $($vp.value)}
            }
            #set the default System Attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'UseTLS','ProxyEnabled','CommandPrefix','AuthenticationRequired','AuthMethod')
                {$GenericSystemObject.defaults.$($vp.name) = $($vp.value)}
            }
            $addServiceTypeAttributesParams = @{
                OrgSystemObject = $GenericSystemObject
                ServiceType = $ServiceType
            }
            if ($null -ne $Dictionary)
            {$addServiceTypeAttributesParams.Dictionary = $Dictionary}
            $GenericSystemObject = AddServiceTypeAttributesToGenericOrgSystemObject @addServiceTypeAttributesParams
            $OrgProfile.Systems += $GenericSystemObject
            Export-OrgProfile -profile $OrgProfile -Path $Path
        }
    }
#end function New-OrgSystemObject
function Set-OrgProfileSystem
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string[]]$Identity #System Identity or Name
            ,
            [parameter()]
            [string]$Name
            ,
            [parameter()]
            [string]$Description
            ,
            [parameter()]
            [validateset('$true','$false')]
            [bool]$ProxyEnabled
            ,
            [parameter()]
            [validateset('$true','$false')]
            [bool]$AuthenticationRequired
            ,
            [parameter()]
            [validateset('$true','$false')]
            [bool]$UseTLS
            ,
            [parameter()]
            [ValidateSet('Basic','Kerberos','Integrated')]
            $AuthMethod
            ,
            [parameter()]
            [ValidateLength(2,5)]
            [string]$CommandPrefix
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1 
            $dictionary = New-DynamicParameter -Name 'ServiceType' -Type $([string]) -ValidateSet $(GetOrgProfileSystemServiceTypes) -DPDictionary $dictionary
            #build  service type specific parameters that may be needed
            $Dictionary = New-DynamicParameter -Name 'TenantSubdomain' -Type $([string]) -Mandatory:$false -DPDictionary $dictionary
            $Dictionary = New-DynamicParameter -Name 'ADUserAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
            $Dictionary = New-DynamicParameter -Name 'ADGroupAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
            $Dictionary = New-DynamicParameter -Name 'ADContactAttributes' -Type $([string[]]) -Mandatory:$false -DPDictionary $Dictionary
            $Dictionary = New-DynamicParameter -Name 'SessionManagementGroups' -Type $([string[]]) -Mandatory:$false -DPDictionary $dictionary
            $Dictionary = New-DynamicParameter -Name 'SQLInstanceType' -Type $([string]) -Mandatory:$false -ValidateSet 'OnPremises','AzureSQL' -DPDictionary $dictionary
            $Dictionary = New-DynamicParameter -Name 'Database' -Type $([string]) -Mandatory:$false -DPDictionary $Dictionary
            Write-Output -InputObject $dictionary
        }#End DynamicParam
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Org Profile
            if ($null -eq $ProfileIdentity)
            {
                $OrgProfile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
            }
            else
            {
                $GetOrgProfileParams = @{
                    ErrorAction = 'Stop'
                    Identity = $ProfileIdentity
                    Path = $Path
                }                
                $OrgProfile = $(Get-OrgProfile @GetOrgProfileParams)
            }
            #Get/Select the System
            $System = $(
                if ($PSBoundParameters.ContainsKey('Identity'))
                {
                    if ($Identity -in $OrgProfile.systems.Identity -or $Identity -in $OrgProfile.systems.Name)
                    {$OrgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Name -eq $Identity}}
                    else
                    {throw("Invalid SystemIdentity $Identity was provided.  No such system exists in OrgProfile $ProfileIdentity.")}
                }
                else
                {
                    Select-ProfileSystem -Systems $OrgProfile.Systems -Operation Edit
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            #Edit the selected System
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            #Set the common System Attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'Name','Description','ServiceType')
                {$System.$($vp.name) = $($vp.value)}
            }
            #set the default System Attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'UseTLS','ProxyEnabled','CommandPrefix','AuthenticationRequired','AuthMethod')
                {$System.defaults.$($vp.name) = $($vp.value)}
            }            
            #Set the ServiceType Specific System Attributes
            $ServiceTypeSpecificAttributeNames = @('TenantSubDomain','ADUserAttributes','ADGroupAttributes','ADContactAttributes','SessionManagementGroups','SQLInstanceType','Database')
            $SystemServiceTypeSpecificAttributeNames = $System.ServiceTypeAttributes | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in $ServiceTypeSpecificAttributeNames -and $vp.name -in $SystemServiceTypeSpecificAttributeNames)
                {$System.ServiceTypeAttributes.$($vp.name) = $($vp.value)}
            }
            #update the system entry in the org profile
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OrgProfile -profile $OrgProfile -Path $Path
        }
    }
#end function Set-OrgSystemObject
Function Get-OrgProfileSystem
    {
        [cmdletbinding(DefaultParameterSetName = 'All')]
        param
        (
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string[]]$Identity #System Identity or Name
            ,
            [parameter(ParameterSetName = 'ProfileIdentity')]
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
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $true -Position 1 -ParameterSetName 'ProfileIdentity'
            $dictionary = New-DynamicParameter -Name 'ServiceType' -Type $([string[]]) -ValidateSet @(GetOrgProfileSystemServiceTypes) -HelpMessage 'Specify one or more system types to include' -Mandatory $false -DPDictionary $dictionary -Position 2
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
                    'ProfileIdentity'
                    {
                        Get-OrgProfile -Identity $ProfileIdentity -ErrorAction Stop
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
            if ($null -ne $Identity)
            {
                $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.Identity -in $Identity -or $_.Name -in $Identity})
            }
            Write-Output -InputObject $OutputSystems
        }
    }
#end function Get-OrgProfileSystem
Function Remove-OrgProfileSystem
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string[]]$Identity #System Identity or Name
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = @("$env:ALLUSERSPROFILE\OneShell")
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1 -ParameterSetName 'ProfileIdentity'
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Org Profile
            if ($null -eq $ProfileIdentity)
            {
                $OrgProfile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
            }
            else
            {
                $GetOrgProfileParams = @{
                    ErrorAction = 'Stop'
                    Identity = $ProfileIdentity
                    Path = $Path
                }                
                $OrgProfile = $(Get-OrgProfile @GetOrgProfileParams)
            }
            #Get/Select the System
            $System = $(
                if ($PSBoundParameters.ContainsKey('Identity'))
                {
                    if ($Identity -in $OrgProfile.systems.Identity)
                    {$OrgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $Identity}}
                    else
                    {throw("Invalid SystemIdentity $Identity was provided.  No such system exists in OrgProfile $ProfileIdentity.")}
                }
                else
                {
                    Select-ProfileSystem -Systems $OrgProfile.Systems -Operation Remove
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            #Remove the system from the Org Profile
            $OrgProfile = Remove-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OrgProfile -profile $OrgProfile -Path $path -ErrorAction Stop
        }
    }
#end function Remove-OrgProfileSystem
function New-OrgProfileSystemEndpoint
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$SystemIdentity
            ,
            [parameter()]
            [ValidateSet('PowerShell','SQLDatabase','ExchangeOnPremises','AADSyncServer','AzureADTenant','Office365Tenant','ActiveDirectoryDomain','ActiveDirectoryGlobalCatalog','ActiveDirectoryLDS','MailRelayEndpoint','SkypeOrganization','ExchangeOnline','ExchangeComplianceCenter')]
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
            [string]$EndPointGroup
            ,
            [parameter()]
            [int16]$Precedence
            ,
            [parameter()]
            [ValidateSet('Admin','MRSProxyServer')]
            [string]$EndPointType = 'Admin'
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string]$Path = "$env:ALLUSERSPROFILE\OneShell\"
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            #build any service type specific parameters that may be needed and warn for Exchange* variants that don't need endpoints added
            switch ($ServiceType)
            {
                'ExchangeOnPremises'
                {
                    $Dictionary = New-DynamicParameter -Name 'PreferredDomainControllers' -Type $([string[]]) -Mandatory:$false -DPDictionary $dictionary
                }
                'ExchangeOnline'
                {Write-Warning -Message "Exchange Online systems in OneShell use a dynamic default endpoint. This endpoint will be ignored when connecting to this system."}
                'ExchangeComplianceCenter'
                {Write-Warning -Message "Exchange Compliance Center systems in OneShell use a dynamic default endpoint. This endpoint will be ignored when connecting to this system."}
            }
            Write-Output -InputObject $dictionary
        }#End DynamicParam
        End
        {
            Set-DynamicParameterVariable -dictionary $Dictionary
            #Get/Select the Org Profile
            if ($null -eq $ProfileIdentity)
            {
                $OrgProfile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
            }
            else
            {
                $GetOrgProfileParams = @{
                    ErrorAction = 'Stop'
                    Identity = $ProfileIdentity
                    Path = $Path
                }                
                $OrgProfile = $(Get-OrgProfile @GetOrgProfileParams)
            }
            #Get/Select the System
            $System = $(
                if ($PSBoundParameters.ContainsKey('SystemIdentity'))
                {
                    if ($SystemIdentity -in $OrgProfile.systems.Identity -or $SystemIdentity -in $OrgProfile.systems.Name)
                    {$OrgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $SystemIdentity -or $_.Name -eq $SystemIdentity}}
                    else
                    {throw("Invalid SystemIdentity $SystemIdentity was provided.  No such system exists in OrgProfile $ProfileIdentity.")}
                }
                else
                {
                    Select-ProfileSystem -Systems $OrgProfile.Systems -Operation Edit
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            if ($PSBoundParameters.ContainsKey('ServiceType'))
            {
                if ($ServiceType -ne $system.ServiceType)
                {throw("Invalid ServiceType $serviceType specified (does not match system ServiceType $($system.servicetype))")}
            }
            else
            {
                $ServiceType = $system.ServiceType
            }
            #Get the new endpoint object
            $GenericEndpointObject = NewGenericSystemEndpointObject
            #Set the new endpoint object attributes
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'AddressType','Address','ServicePort','UseTLS','ProxyEnabled','CommandPrefix','AuthenticationRequired','AuthMethod','EndPointGroup','EndPointType','ServiceType','Precedence')
                {$GenericEndpointObject.$($vp.name) = $($vp.value)}
            }
            #Add any servicetype specific attributes that were specified
            switch ($ServiceType)
            {
                'ExchangeOnPremises'
                {
                    $GenericEndpointObject.ServiceTypeAttributes | Add-Member -Name 'PreferredDomainControllers' -Value $PreferredDomainControllers -MemberType NoteProperty
                }
            }
            #Add the endpoint object to the system
            $system.endpoints += $GenericEndpointObject
            #update the system on the profile object
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName 'Systems' -IdentityAttributeName 'Identity'
            Export-OrgProfile -profile $OrgProfile -Path $Path -ErrorAction Stop
        }
    }
#end function New-OrgProfileSystemEndpoint
function Remove-OrgProfileSystemEndpoint
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$Identity
            ,
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$SystemIdentity
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string]$Path = "$env:ALLUSERSPROFILE\OneShell\"
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $Dictionary
            #Get/Select the Org Profile
            if ($null -eq $ProfileIdentity)
            {
                $OrgProfile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
            }
            else
            {
                $GetOrgProfileParams = @{
                    ErrorAction = 'Stop'
                    Identity = $ProfileIdentity
                    Path = $Path
                }                
                $OrgProfile = $(Get-OrgProfile @GetOrgProfileParams)
            }
            #Get/Select the System
            $System = $(
                if ($PSBoundParameters.ContainsKey('SystemIdentity'))
                {
                    if ($SystemIdentity -in $OrgProfile.systems.Identity)
                    {$OrgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $SystemIdentity}}
                    else
                    {throw("Invalid SystemIdentity $SystemIdentity was provided.  No such system exists in OrgProfile $ProfileIdentity.")}
                }
                else
                {
                    Select-ProfileSystem -Systems $OrgProfile.Systems -Operation Edit
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            #Get/Select the Endpoint
            $endPoint = $(
                if ($PSBoundParameters.ContainsKey('Identity'))
                {
                    if ($Identity -in $system.endpoints.Identity)
                    {$system.Endpoints | Where-Object -FilterScript {$_.Identity -eq $Identity}}
                    else
                    {throw("Invalid EndPoint Identity $Identity was provided.  No such endpoint exists for System $($system.identity).")}
                }
                else
                {
                    Select-OrgProfileSystemEndpoint -Endpoints $System.EndPoints -Operation Remove
                }
            )
            if ($null -eq $endPoint) {throw("No valid endpoint was selected.")}
            $System = Remove-ExistingObjectFromMultivaluedAttribute -ParentObject $System -ChildObject $endPoint -MultiValuedAttributeName Endpoints -IdentityAttributeName Identity
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OrgProfile -Path $Path -profile $OrgProfile -ErrorAction Stop
        }
    }
#end function Remove-OrgProfileSystemEndpoint
function Set-OrgProfileSystemEndpoint
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$Identity
            ,
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$SystemIdentity
            ,
            [Parameter()]
            [ValidateSet('URL','IPAddress','FQDN')]
            [String]$AddressType
            ,
            [Parameter()]
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
            [int16]$Precedence
            ,
            [parameter()]
            [ValidateSet('Admin','MRSProxyServer')]
            [string]$EndPointType = 'Admin'
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string]$Path = "$env:ALLUSERSPROFILE\OneShell\"
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $Dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            $Dictionary = New-DynamicParameter -Name 'PreferredDomainControllers' -Type $([string[]]) -Mandatory:$false -DPDictionary $dictionary
            Write-Output -InputObject $Dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $Dictionary
            #Get/Select the Org Profile
            if ($null -eq $ProfileIdentity)
            {
                $OrgProfile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
            }
            else
            {
                $GetOrgProfileParams = @{
                    ErrorAction = 'Stop'
                    Identity = $ProfileIdentity
                    Path = $Path
                }                
                $OrgProfile = $(Get-OrgProfile @GetOrgProfileParams)
            }
            #Get/Select the System
            $System = $(
                if ($PSBoundParameters.ContainsKey('SystemIdentity'))
                {
                    if ($SystemIdentity -in $OrgProfile.systems.Identity)
                    {$OrgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $SystemIdentity}}
                    else
                    {throw("Invalid SystemIdentity $SystemIdentity was provided.  No such system exists in OrgProfile $ProfileIdentity.")}
                }
                else
                {
                    Select-ProfileSystem -Systems $OrgProfile.Systems -Operation Edit
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            #Get/Select the Endpoint
            $endPoint = $(
                if ($PSBoundParameters.ContainsKey('Identity'))
                {
                    if ($Identity -in $system.endpoints.Identity)
                    {$system.Endpoints | Where-Object -FilterScript {$_.Identity -eq $Identity}}
                    else
                    {throw("Invalid EndPoint Identity $Identity was provided.  No such endpoint exists for System $($system.identity).")}
                }
                else
                {
                    Select-OrgProfileSystemEndpoint -Endpoints $System.EndPoints -Operation Edit
                }
            )
            if ($null -eq $endPoint) {throw("No valid endpoint was selected.")}
            #Set the new endpoint object attributes
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'AddressType','Address','ServicePort','UseTLS','ProxyEnabled','CommandPrefix','AuthenticationRequired','AuthMethod','EndPointGroup','EndPointType','ServiceType','Precedence')
                {$endpoint.$($vp.name) = $($vp.value)}
            }
            #Add any servicetype specific attributes that were specified
            switch ($endpoint.ServiceType)
            {
                'ExchangeOnPremises'
                {
                    if ($null -ne $preferredDomainControllers)
                    {
                        $Endpoint.ServiceTypeAttributes.PreferredDomainControllers = $preferredDomainControllers
                    }
                }
            } #end switch
            $System = update-ExistingObjectFromMultivaluedAttribute -ParentObject $System -ChildObject $endPoint -MultiValuedAttributeName Endpoints -IdentityAttributeName Identity
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OrgProfile -Path $Path -profile $OrgProfile -ErrorAction Stop
        }#end End
    }
#end function Set-OrgProfileSystemEndpoint
function Get-OrgProfileSystemEndpoint
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$Identity
            ,
            [switch]$All
            ,
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$SystemIdentity
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = "$env:ALLUSERSPROFILE\OneShell\"
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = "$env:ALLUSERSPROFILE\OneShell"}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $Dictionary
            #Get/Select the Org Profile
            if ($null -eq $ProfileIdentity)
            {
                $OrgProfile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
            }
            else
            {
                $GetOrgProfileParams = @{
                    ErrorAction = 'Stop'
                    Identity = $ProfileIdentity
                    Path = $Path
                }                
                $OrgProfile = $(Get-OrgProfile @GetOrgProfileParams)
            }
            $System = $(
                if ($PSBoundParameters.ContainsKey('SystemIdentity'))
                {
                    if ($SystemIdentity -in $OrgProfile.systems.Identity)
                    {$OrgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $SystemIdentity}}
                    else
                    {throw("Invalid SystemIdentity $SystemIdentity was provided.  No such system exists in OrgProfile $ProfileIdentity.")}
                }
                else
                {
                    Select-ProfileSystem -Systems $OrgProfile.Systems -Operation Get
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            $EndPoints = @(
                switch ($null -eq $Identity -or [string]::IsNullOrWhiteSpace($Identity))
                {
                    $true
                    {
                        $system.endpoints
                    }
                    $false
                    {
                        if ($Identity -in $System.endpoints.identity)
                        {$System.endpoints | Where-Object  -FilterScript {$_.Identity -eq $identity -or $_.Address -eq $Identity}}
                        else
                        {throw("Invalid Endpoint Identity $Identity was provided.  No such endpoint exists for System $($system.identity).")}
                        
                    }
                }
            )
            Write-Output -InputObject $EndPoints
        }
    }
#end function Get-OrgProfileSystemEndpoint
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
            $dictionary = New-DynamicParameter -Name 'OrgProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 2
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $AdminProfileIdentities -ParameterSetName Identity -DPDictionary $dictionary -Mandatory $true -Position 1
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
    }
#end function Get-AdminUserProfile
function New-AdminUserProfile
    {
        [cmdletbinding()]
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
            [string]$Name #Overrides the default name of Org-Machine-User
            ,
            [Parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
        )
        DynamicParam
        {
            if ($null -eq $OrgProfilePath -or [string]::IsNullOrEmpty($OrgProfilePath)) {$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"}
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
                Path = $OrgProfilePath
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
            $AdminUserProfile = NewGenericAdminsUserProfileObject -TargetOrgProfile $targetOrgProfile
            $Systems = @(GetOrgProfileSystemForAdminProfile -OrgProfile $TargetOrgProfile)
            $AdminUserProfile.Systems = $Systems
            foreach ($p in $PSBoundParameters.GetEnumerator())
            {
                if ($p.key -in 'ProfileFolder','Name','MailFromSMTPAddress','Credentials','Systems')
                {$AdminUserProfile.$($p.key) = $p.value}
            }#end foreach
            Export-AdminUserProfile -profile $AdminUserProfile -path $path -errorAction 'Stop'
        }#end End
    }
#end function New-AdminUserProfile
Function Export-AdminUserProfile
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory=$true)]
            $profile
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
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
            Depth = 6
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
#end function Export-AdminUserProfile
Function Use-AdminUserProfile
    {
        [cmdletbinding(DefaultParameterSetName = 'Identity')]
        param
        (
            [parameter(ParameterSetName = 'Object',ValueFromPipeline=$true,Position = 1)]
            $AdminUserProfile
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell\"
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -ParameterSetName 'Identity' -Position 1
            Write-Output -InputObject $dictionary
        }
        begin
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            switch ($PSCmdlet.ParameterSetName)
            {
                'Object'
                {}
                'Identity'
                {
                    if ($null -eq $Identity)
                    {
                        $AdminUserProfile = Select-Profile -Profiles $paProfiles -Operation Use
                    }
                    else
                    {
                        $GetAdminUserProfileParams = @{
                            Identity = $Identity
                            ErrorAction = 'Stop'
                            Path = $path
                        }
                        $AdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
                    }
                }
            }
            #Check Admin User Profile Version
            $RequiredVersion = 1.1
            if (! $AdminUserProfile.ProfileTypeVersion -ge $RequiredVersion)
            {
                throw("The selected Admin User Profile $($AdminUserProfile.Name) is an older version. Please Run Set-AdminUserProfile -Identity $($AdminUserProfile.Identity) or Update-AdminUserProfileTypeVersion -Identity $($AdminUserProfile.Identity) to update it to version $RequiredVersion.")
            }
            #Get and use the related Org Profile
            $UseOrgProfileParams = @{
                ErrorAction = 'Stop'
                Path = $OrgProfilePath
                Identity = $AdminUserProfile.Organization.Identity
            }
            $OrgProfile = Get-OrgProfile @UseOrgProfileParams
            Use-OrgProfile -profile $OrgProfile
            #need to add some clean-up functionality for sessions when there is a change, or make it always optional to reset all sessions with this function
            $script:CurrentAdminUserProfile = $AdminUserProfile
            Write-Verbose -Message "Admin User Profile has been set to $($script:CurrentAdminUserProfile.Identity), $($script:CurrentAdminUserProfile.name)."
            #Build the 'live' systems for use by connect-* functions
            #Retrieve the systems from the current org profile
            $OrgSystems = $OrgProfile.systems
            $AdminSystems = $AdminUserProfile.systems
            $JoinedSystems = join-object -Left $OrgSystems -Right $AdminSystems -LeftJoinProperty Identity -RightJoinProperty Identity
            $Script:CurrentSystems = 
            @(
                foreach ($js in $JoinedSystems)
                {
                    $PreCredential = @($AdminUserProfile.credentials | Where-Object -FilterScript {$_.Identity -eq $js.Credential})
                    switch ($PreCredential.count)
                    {
                        1
                        {
                            $SSPassword = $PreCredential[0].password | ConvertTo-SecureString
                            $Credential = New-Object System.Management.Automation.PSCredential($PreCredential[0].Username,$SSPassword)
                        }
                        0
                        {
                            $Credential = $null
                        }
                    }
                    $js.Credential = $Credential
                    Write-Output -InputObject $js
                }
            )
            #set folder paths
            $script:OneShellAdminUserProfileFolder = $script:CurrentAdminUserProfile.ProfileFolder
            #Log Folder and Log Paths
            if ([string]::IsNullOrEmpty($script:CurrentAdminUserProfile.LogFolder))
            {
                $Script:LogFolderPath = "$script:OneShellAdminUserProfileFolder\Logs"
            }
            else
            {
                $Script:LogFolderPath = $script:CurrentAdminUserProfile.LogFolder
            }
            $Script:LogPath = "$Script:LogFolderPath\$Script:Stamp" + '-AdminOperations.log'
            $Script:ErrorLogPath = "$Script:LogFolderPath\$Script:Stamp" +  '-AdminOperations-Errors.log'
            #Input Files Path
            if ([string]::IsNullOrEmpty($script:CurrentAdminUserProfile.InputFilesFolder))
            {
                $Script:InputFilesPath = "$script:OneShellAdminUserProfileFolder\InputFiles\"
            }
            else
            {
                $Script:InputFilesPath = $script:CurrentAdminUserProfile.InputFilesFolder + '\'
            }
            #Export Data Path
            if ([string]::IsNullOrEmpty($script:CurrentAdminUserProfile.ExportDataFolder))
            {
                $Script:ExportDataPath = "$script:OneShellAdminUserProfileFolder\Export\"
            }
            else
            {
                    $Script:ExportDataPath = $script:CurrentAdminUserProfile.ExportDataFolder + '\'
            }
        }#begin
    }
#end function Use-AdminUserProfile
function Set-AdminUserProfile
    {
        [cmdletbinding(DefaultParameterSetName="Identity")]
        param
        (
            [Parameter(ParameterSetName = 'Object',ValueFromPipeline,Mandatory)]
            [ValidateScript({$_.ProfileType -eq 'OneShellAdminUserProfile'})]
            [psobject]$ProfileObject 
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string]$ProfileFolder
            ,
            [parameter()]
            [string]$Name
            ,
            [parameter()]
            [ValidateScript({Test-EmailAddress -EmailAddress $_})]
            $MailFromSMTPAddress
            ,
            [parameter()]
            [switch]$UpdateSystemsFromOrgProfile
            ,
            [parameter(ParameterSetName = 'Identity')]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell\"
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $AdminProfileIdentities -ParameterSetName 'Identity' -Mandatory $false
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            switch ($PSCmdlet.ParameterSetName)
            {
                'Object'
                {}
                'Identity'
                {
                    if ($null -eq $Identity)
                    {
                        $AdminUserProfile = Select-Profile -Profiles $paProfiles -Operation Edit
                    }
                    else
                    {
                        $GetAdminUserProfileParams = @{
                            Identity = $Identity
                            ErrorAction = 'Stop'
                            Path = $path
                        }
                        $AdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
                    }
                }
            }
            $GetOrgProfileParams = @{
                ErrorAction = 'Stop'
                Path = $orgProfilePath
                Identity = $AdminUserProfile.organization.identity
            }
            $targetOrgProfile = @(Get-OrgProfile @GetOrgProfileParams)
            #Check the Org Identity for validity (exists, not ambiguous)
            switch ($targetOrgProfile.Count)
            {
                1
                {}
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
            #Update the Admin User Profile Version if necessary
            $AdminUserProfile = UpdateAdminUserProfileObjectVersion -AdminUserProfile $AdminUserProfile
            #Update the profile itself
            if ($PSBoundParameters.ContainsKey('UpdateSystemsFromOrgProfile') -and $UpdateSystemsFromOrgProfile -eq $true)
            {
                $UpdateAdminUserProfileSystemParams = @{
                    ErrorAction = 'Stop'
                    ProfileObject = $AdminUserProfile
                    OrgProfilePath = $OrgProfilePath
                }
                Update-AdminUserProfileSystem @UpdateAdminUserProfileSystemParams
            }
            foreach ($p in $PSBoundParameters.GetEnumerator())
            {
                if ($p.key -in 'ProfileFolder','Name','MailFromSMTPAddress','Credentials','Systems')
                {$AdminUserProfile.$($p.key) = $p.value}
            }#end foreach
            Export-AdminUserProfile -profile $AdminUserProfile -ErrorAction 'Stop'
        }#End End
    }
#end function Set-AdminUserProfile
Function Get-AdminUserProfileSystem
    {
        [cmdletbinding(DefaultParameterSetName='All')]
        param
        (
            [parameter(ParameterSetName = 'Identity',Position = 1)]
            [string[]]$Identity
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"
            ,
            [parameter(ParameterSetName = 'GetCurrent')]
            [switch]$GetCurrent
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 2
            $dictionary = New-DynamicParameter -Name 'ServiceType' -Type $([string[]]) -ValidateSet $(GetOrgProfileSystemServiceTypes) -DPDictionary $dictionary -Mandatory $false -Position 3
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
                    }#end GetCurrent
                    Default
                    {
                        $GetAdminUserProfileParams = @{
                            ErrorAction = 'Stop'
                            Path = $Path
                        }
                        if ($null -ne $ProfileIdentity)
                        {
                            $GetAdminUserProfileParams.Identity = $ProfileIdentity
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
            #filter based on Identity and Service Type
            if ($null -ne $ServiceType)
            {
                $outputSystems = $outputSystems | Where-Object -FilterScript {$_.ServiceType -in $ServiceType}
            }
            if ($null -ne $Identity)
            {
                $outputSystems = $outputSystems | Where-Object -FilterScript {$_.Identity -in $Identity -or $_.Name -in $Identity}
            }
            Write-Output -InputObject $outputSystems
        }#end End
    }
#end function Get-AdminUserProfileSystem
Function Set-AdminUserProfileSystem
    {
        [cmdletbinding()]
        param
        (
            [parameter(Position = 1)]
            [string[]]$Identity
            ,
            [parameter()]
            [bool]$AutoConnect
            ,
            [parameter()]
            [String]$Credential
            ,
            [parameter()]
            [ValidateScript({($_.length -ge 2 -and $_.length -le 5) -or [string]::isnullorempty($_)})]
            [string]$PreferredPrefix
            ,
            [parameter()]
            [allowNull()]
            [string]$PreferredEndpoint
            ,        
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 2
            Write-Output -inputobject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            if ($null -eq $ProfileIdentity)
            {
                Select-Profile -Profiles $paProfiles -Operation Edit
            }
            else
            {
                $GetAdminUserProfileParams = @{
                    ErrorAction = 'Stop'
                    Path = $Path
                    Identity = $ProfileIdentity
                }
                $AdminProfile = Get-AdminUserProfile @GetAdminUserProfileParams
            }
            #Get/Select the System
            $System = $(
                if ($PSBoundParameters.ContainsKey('Identity'))
                {
                    if ($Identity -in $AdminProfile.systems.Identity)
                    {$AdminProfile.systems | Where-Object -FilterScript {$_.Identity -eq $Identity}}
                    else
                    {throw("Invalid SystemIdentity $Identity was provided. No such system exists in AdminProfile $ProfileIdentity.")}
                }
                else
                {
                    $Systems = Get-AdminUserProfileSystem -ProfileIdentity $ProfileIdentity -Path $Path -ErrorAction 'Stop'
                    Select-ProfileSystem -Systems $Systems -Operation Edit
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            #Edit the System
            switch ($PSBoundParameters.getenumerator())
            {
                {$_.key -eq 'AutoConnect'}
                {$System.AutoConnect = $AutoConnect}
                {$_.key -eq 'PreferredPrefix'}
                {$System.PreferredPrefix = $PreferredPrefix}
                {$_.key -eq 'PreferredEndpoint'}
                {
                    $Endpoints = Get-OrgProfileSystemEndpoint -Identity $PreferredEndpoint -SystemIdentity $system.Identity -ProfileIdentity $AdminProfile.Organization.Identity -Path $OrgProfilePath -ErrorAction 'Stop'
                    if ($_.value -in $Endpoints.Identity -or $null -eq $_.value)
                    {
                        $System.PreferredEndpoint = $PreferredEndpoint
                    }
                    else
                    {
                        throw("Invalid Endpoint Identity $PreferredEndpoint was provided. No such endpoint exists for system $($system.identity).")
                    }
                }
                {$_.key -eq 'Credential'}
                {
                    if ($_.value -in $AdminProfile.Credentials.Identity)
                    {
                        $system.Credential = $Credential
                    }
                    else
                    {
                        throw("Invalid Credential Identity $Credential was provided. No such credential exists for admin profile $($adminprofile.identity).")
                    }
                }
            }
            #remove any extraneous properties
            $System = $System | Select-Object -Property "Identity","AutoConnect","Credential","PreferredEndpoint","PreferredPrefix"
            #Save the system changes to the Admin Profile
            $AdminProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $AdminProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
            Export-AdminUserProfile -profile $AdminProfile -path $path -ErrorAction 'Stop'
        }#end End
    }
#end function Set-AdminUserProfileSystem
Function Set-AdminUserProfileSystemPreferredEndpoint
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [string]$SystemIdentity
            ,
            [parameter()]
            [string]$EndpointIdentity
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 2
            Write-Output -inputobject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            if ($null -eq $ProfileIdentity)
            {
                Select-Profile -Profiles $paProfiles -Operation Edit
            }
            else
            {
                $GetAdminUserProfileParams = @{
                    ErrorAction = 'Stop'
                    Path = $Path
                    Identity = $ProfileIdentity
                }
                $AdminProfile = Get-AdminUserProfile @GetAdminUserProfileParams
            }
            #Get/Select the System
            $System = $(
                if ($PSBoundParameters.ContainsKey('SystemIdentity'))
                {
                    if ($SystemIdentity -in $AdminProfile.systems.Identity)
                    {$AdminProfile.systems | Where-Object -FilterScript {$_.Identity -eq $SystemIdentity}}
                    else
                    {throw("Invalid SystemIdentity $SystemIdentity was provided. No such system exists in AdminProfile $ProfileIdentity.")}
                }
                else
                {
                    $Systems = Get-AdminUserProfileSystem -ProfileIdentity $ProfileIdentity -Path $Path -ErrorAction 'Stop'
                    Select-ProfileSystem -Systems $Systems -Operation Edit | Select-Object -Property "Identity","AutoConnect","Credential","PreferredEndpoint","PreferredPrefix"
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            #Get/Select the Endpoint
            $Endpoints = @(Get-OrgProfileSystemEndpoint -SystemIdentity $system.Identity -ProfileIdentity $AdminProfile.Organization.Identity -Path $OrgProfilePath -ErrorAction 'Stop')
            $SelectedEndpointIdentity = $(
                if ($PsBoundParameters.ContainsKey('EndpointIdentity'))
                {
                    if ($EndpointIdentity -in $Endpoints.Identity)
                    {$EndpointIdentity}
                    else
                    {
                        throw("Invalid Endpoint Identity $EndpointIdentity was provided. No such endpoint exists for system $($system.identity).")
                    }
                }
                else
                {
                    Select-OrgProfileSystemEndpoint -EndPoints $Endpoints -Operation Associate | Select-Object -ExpandProperty Identity
                }
            )
            if ($null -eq $SelectedEndpointIdentity) {throw("No valid Endpoint Identity was provided.")}
            $system.PreferredEndpoint = $SelectedEndpointIdentity
            #Save the system changes to the Admin Profile
            $AdminProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $AdminProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
            Export-AdminUserProfile -profile $AdminProfile -path $path -ErrorAction 'Stop'
        }#end End
    }
#end function Set-AdminUserProfileSystemPreferredEndpoint
Function Set-AdminUserProfileSystemCredential
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [string]$SystemIdentity
            ,
            [parameter()]
            [string]$CredentialIdentity
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell"
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 2
            Write-Output -inputobject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            if ($null -eq $ProfileIdentity)
            {
                Select-Profile -Profiles $paProfiles -Operation Edit
            }
            else
            {
                $GetAdminUserProfileParams = @{
                    ErrorAction = 'Stop'
                    Path = $Path
                    Identity = $ProfileIdentity
                }
                $AdminProfile = Get-AdminUserProfile @GetAdminUserProfileParams
            }
            #Get/Select the System
            $System = $(
                if ($PSBoundParameters.ContainsKey('SystemIdentity'))
                {
                    if ($SystemIdentity -in $AdminProfile.systems.Identity)
                    {$AdminProfile.systems | Where-Object -FilterScript {$_.Identity -eq $SystemIdentity}}
                    else
                    {throw("Invalid System Identity $SystemIdentity was provided. No such system exists in AdminProfile $ProfileIdentity.")}
                }
                else
                {
                    $Systems = Get-AdminUserProfileSystem -ProfileIdentity $ProfileIdentity -Path $Path -ErrorAction 'Stop'
                    Select-ProfileSystem -Systems $Systems -Operation Edit | Select-Object -Property "Identity","AutoConnect","Credential","PreferredEndpoint","PreferredPrefix"
                }
            )
            if ($null -eq $System) {throw("No valid SystemIdentity was provided.")}
            #Get/Select the Credential
            $Credentials = @(Get-AdminUserProfileCredential -ProfileIdentity $ProfileIdentity -ErrorAction 'Stop' -Path $path)
            $SelectedCredentialIdentity = $(
                if ($PsBoundParameters.ContainsKey('CredentialIdentity'))
                {
                    if ($CredentialIdentity -in $Credentials.Identity)
                    {$CredentialIdentity}
                    else
                    {
                        throw("Invalid Credential Identity $CredentialIdentity was provided. No such Credential exists for admin profiel $ProfileIdentity.")
                    }
                }
                else
                {
                    Select-AdminUserProfileCredential -Credentials $Credentials -Operation Associate | Select-Object -ExpandProperty Identity
                }
            )
            if ($null -eq $SelectedCredentialIdentity) {throw("No valid Credential Identity was provided.")}
            $system.Credential = $SelectedCredentialIdentity
            #Save the system changes to the Admin Profile
            $AdminProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $AdminProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
            Export-AdminUserProfile -profile $AdminProfile -path $path -ErrorAction 'Stop'
        }#end End
    }
#end function Set-AdminUserProfileSystemCredential
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

function Update-AdminUserProfileSystem
    {
        [cmdletbinding()]
        param
        (
            [Parameter(ParameterSetName = 'Object',ValueFromPipeline,Mandatory)]
            [ValidateScript({$_.ProfileType -eq 'OneShellAdminUserProfile'})]
            [psobject]$ProfileObject 
            ,
            [parameter(ParameterSetName = 'Identity')]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = "$env:ALLUSERSPROFILE\OneShell\"
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
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
                        Path = $Path
                    }
                    $AdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
                }
            }#end switch ParameterSetName
            $GetOrgProfileParams = @{
                ErrorAction = 'Stop'
                Path = $orgProfilePath
                Identity = $AdminUserProfile.organization.identity
            }
            $targetOrgProfile = @(Get-OrgProfile @GetOrgProfileParams)
            #Check the Org Identity for validity (exists, not ambiguous)
            switch ($targetOrgProfile.Count)
            {
                1
                {}
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
            $OrgProfileSystems = @(GetOrgProfileSystemForAdminProfile -OrgProfile $TargetOrgProfile)
            $AdminUserProfileSystems = @($AdminUserProfile.Systems)
            #Remove those that are no longer in the Org Profile
            $AdminUserProfileSystems = $AdminUserProfileSystems | Where-Object {$_.Identity -in $OrgProfileSystems.Identity}
            #Add those that are new to the Org Profile
            $NewOrgProfileSystems = $OrgProfileSystems | Where-Object {$_.Identity -notin $AdminUserProfileSystems.Identity}
            $NewAdminUserProfileSystems = $AdminUserProfileSystems + $NewOrgProfileSystems
            $AdminUserProfile.Systems = $NewAdminUserProfileSystems
            Export-AdminUserProfile -profile $AdminUserProfile -ErrorAction 'Stop'
        }#End End
    }
function New-AdminUserProfileCredential
    {
        [cmdletbinding()]
        param
        (
            [Parameter(Position = 2)]
            [ValidateNotNullOrEmpty()]
            [string]$Username
            ,
            [parameter(Position = 3)]
            [ValidateNotNullOrEmpty()]
            [securestring]$Password
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -DPDictionary $dictionary -Mandatory $false -Position 1 
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            if ($null -eq $ProfileIdentity)
            {
                Select-Profile -Profiles $paProfiles -Operation Edit
            }
            else
            {
                $GetAdminUserProfileParams = @{
                    ErrorAction = 'Stop'
                    Path = $Path
                    Identity = $ProfileIdentity
                }
                $AdminProfile = Get-AdminUserProfile @GetAdminUserProfileParams
            }
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
#end function New-AdminUserProfileCredential
function Remove-AdminUserProfileCredential
    {
        [cmdletbinding(DefaultParameterSetName = 'Select')]
        param
        (
            [parameter(ParameterSetName = 'Identity', Position = 2)]
            [string]$Identity
            ,
            [parameter(ParameterSetName = 'UserName', Position = 2)]
            [string]$Username
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -DPDictionary $dictionary -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            if ($null -eq $ProfileIdentity)
            {
                Select-Profile -Profiles $paProfiles -Operation Edit
            }
            else
            {
                $GetAdminUserProfileParams = @{
                    ErrorAction = 'Stop'
                    Path = $Path
                    Identity = $ProfileIdentity
                }
                $AdminProfile = Get-AdminUserProfile @GetAdminUserProfileParams
            }
            if ($AdminProfile.Credentials.Count -eq 0) {throw('There are no credentials to remove')}
            $SelectedCredential = @(
                switch ($PSCmdlet.ParameterSetName)
                {
                    'Select'
                    {
                        Select-AdminUserProfileCredential -Credentials $AdminProfile.Credentials -Operation Remove
                    }
                    'UserName'
                    {
                        $AdminProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $UserName}
                    }
                    'Identity'
                    {
                        $AdminProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                    }
                }
            )
            switch ($SelectedCredential.Count)
            {
                0 {throw("Matching credential not found")}
                1 {}
                default {throw("Multiple credentials found.")}
            }
            $adminProfile.Credentials = @($AdminProfile.Credentials | Where-Object -FilterScript {$_ -ne $SelectedCredential[0]})
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
        [cmdletbinding(DefaultParameterSetName = 'Select')]
        param
        (
            [parameter(ParameterSetName = 'Identity',Position = 2)]
            [ValidateNotNullOrEmpty()]
            [string]$Identity
            ,
            [parameter(ParameterSetName = 'UserName',Position = 2)]
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
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -DPDictionary $dictionary -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            if ($null -eq $ProfileIdentity)
            {
                Select-Profile -Profiles $paProfiles -Operation Edit
            }
            else
            {
                $GetAdminUserProfileParams = @{
                    ErrorAction = 'Stop'
                    Path = $Path
                    Identity = $ProfileIdentity
                }
                $AdminProfile = Get-AdminUserProfile @GetAdminUserProfileParams
            }
            if ($AdminProfile.Credentials.Count -eq 0) {throw('There are no credentials to set')}
            $SelectedCredential = @(
                switch ($PSCmdlet.ParameterSetName)
                {
                    'Select'
                    {
                        Select-AdminUserProfileCredential -Credentials $AdminProfile.Credentials -Operation Edit
                    }
                    'Identity'
                    {
                        $AdminProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                    }
                    'Username'
                    {
                        $AdminProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $UserName} 
                    }
                }
            )
            switch ($SelectedCredential.Count)
            {
                0 {throw("Matching credential not found")}
                1 {}
                default {throw("Multiple credentials found.")}
            }
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
        [cmdletbinding()]
        param
        (
            [parameter(Position = 2)]
            [string]$Identity #Credential Identity or UserName
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = "$env:UserProfile\OneShell\"
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = "$env:UserProfile\OneShell\"}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -DPDictionary $dictionary -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            $getAdminUserProfileParams = @{
                ErrorAction = 'Stop'
                Path = $Path
            }
            if (-not [string]::IsNullOrEmpty($ProfileIdentity))
            {$getAdminUserProfileParams.Identity = $ProfileIdentity}
            $AdminProfile = @(Get-AdminUserProfile @getAdminUserProfileParams)
            $OutputCredentials = @(
                foreach ($ap in $AdminProfile)
                {
                    $ProfileName = $ap.Name
                    $ProfileIdentity = $ap.Identity
                    $ap.Credentials | Select-Object -Property *,@{n='AdminProfileName';e={$ProfileName}},@{n='AdminProfileIdentity';e={$ProfileIdentity}}
                }    
            )
            if (-not [string]::IsNullOrEmpty($Identity))
            {$OutputCredentials = $OutputCredentials | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Username -eq $Identity}}
            Write-Output -InputObject $OutputCredentials
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

#################################################
# Interactive
#################################################
function Select-ProfileSystem
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            $Systems
            ,
            [parameter(Mandatory)]
            [ValidateSet('Remove','Edit','Get')]
            [string]$Operation
        )
        $message = "Select system to $Operation"
        $CredChoices = @(foreach ($s in $Systems){"$($s.servicetype):$($s.name):$($s.Identity)"})
        $whichone = 
            switch ($host.Name -notlike 'Console*')
            {
                $true
                {Read-Choice -Message $message -Choices $CredChoices -DefaultChoice 0 -Title $message -Numbered}
                $false
                {Read-PromptForChoice -Message $message -Choices $CredChoices -DefaultChoice 0 -Title $message -Numbered}
            }
        Write-Output -InputObject $systems[$whichone]
    }
#end function Select-ProfileSystem
function Select-OrgProfileSystemEndpoint
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            $EndPoints
            ,
            [parameter(Mandatory)]
            [ValidateSet('Remove','Edit','Associate')]
            [string]$Operation
        )
        $message = "Select endpoint to $Operation"
        $Choices = @(foreach ($i in $EndPoints){"$($i.ServiceType):$($i.address):$($i.Identity)"})
        $whichone = $(
            switch ($host.Name -notlike 'Console*')
            {
                $true
                {Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
                $false
                {Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
            }
        )
        Write-Output -InputObject $EndPoints[$whichone]
    }
#end function Select-OrgProfileSystemEndpoint
function Select-AdminUserProfileCredential
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            $Credentials
            ,
            [parameter(Mandatory)]
            [ValidateSet('Remove','Edit','Associate')]
            [string]$Operation
        )
        $message = "Select credential to $Operation"
        $Choices = @(foreach ($i in $Credentials){"$($i.username):$($i.Identity)"})
        $whichone = $(
            switch ($host.Name -notlike 'Console*')
            {
                $true
                {Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
                $false
                {Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
            }
        )
        Write-Output -InputObject $Credentials[$whichone]
    }
#end function Select-AdminUserProfileCredential
function Select-Profile
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $Profiles
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove','Edit','Associate','Get','Use')]
        [string]$Operation
    )
    $message = "Select profile to $Operation"
    $Choices = @(foreach ($i in $Profiles){"$($i.name):$($i.Identity)"})
    $whichone = $(
        switch ($host.Name -notlike 'Console*')
        {
            $true
            {Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
            $false
            {Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
        }
    )
    Write-Output -InputObject $Profiles[$whichone]
}
#end function Select-Profile
#################################################
# Need to update
#################################################

#################################################
# Need to add
#################################################
#? Remove functions for OrgProfile, AdminProfile
