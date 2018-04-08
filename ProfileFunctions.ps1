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
            [parameter()]
            [AllowNull()]
            [string[]]$path
        )
        if ($null -eq $path)
        {
            throw('You must specify the Path parameter or run Set-OneShellOrgProfilePath')
        }
        $JSONProfiles = @(
            foreach ($p in $Path)
            {
                Write-Verbose -Message "Getting JSON Files From $p"
                (Get-ChildItem -Path "$p\*" -Include '*.json' -Exclude 'OneShellSystemSettings.json')
            }
        )
        Write-Verbose -Message "Found $($jsonProfiles.count) json Files"
        $PotentialOrgProfiles = @(
            foreach ($file in $JSONProfiles)
            {Get-Content -Path $file.fullname -Raw | ConvertFrom-Json | Add-Member -MemberType NoteProperty -Name DirectoryPath -Value $File.DirectoryName -PassThru}
        )
        Write-Verbose -Message "Found $($PotentialOrgProfiles.count) Potential Org Profiles"
        if ($PotentialOrgProfiles.Count -lt 1)
        {
            throw('You must specify a folder path which contains OneShell Org Profiles with the Path parameter and/or you must create at least one Org Profile using New-OrgProfile.')
        }
        else
        {
            $PotentialOrgProfiles
        }
    }
#end funciton GetPotentialOrgProfiles
function GetPotentialAdminUserProfiles
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [AllowNull()]
            [string[]]$path
        )
        if ($null -eq $path)
        {
            throw('You must specify the Path parameter or run Set-OneShellAdminUserProfilePath')
        }
        $JSONProfiles =@(
            foreach ($p in $Path)
            {
                Get-ChildItem -Path "$p\*" -Include '*.json' -Exclude 'OneShellUserSettings.json'
            }
        )
        $PotentialAdminUserProfiles = @(
            foreach ($file in $JSONProfiles)
            {
                Get-Content -Path $file.fullname -Raw | ConvertFrom-Json
            }
        )
        if ($PotentialAdminUserProfiles.Count -lt 1)
        {
            throw('You must specify a folder path which contains OneShell Admin User Profiles with the Path parameter and/or you must create at least one Admin User Profile using New-AdminUserProfile.')
        }
        else
        {
            $PotentialAdminUserProfiles
        }
    }
#End function GetPotentialAdminUserProfiles
function GetOneShellServiceTypeNames
    {
        $script:ServiceTypes.Name
    }
#end function GetOneShellServiceTypeNames

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
                UsePSRemoting = $true
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
        #Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        if ($null -ne $dictionary)
        {
            Set-DynamicParameterVariable -dictionary $dictionary
        }
        $ServiceTypeDefinition = Get-ServiceTypeDefinition -ServiceType $ServiceType
        Write-Verbose -Message "Using ServiceTypeDefinition $($ServiceTypeDefinition.name)"
        if ($null -ne $serviceTypeDefinition.OrgSystemServiceTypeAttributes -and $serviceTypeDefinition.OrgSystemServiceTypeAttributes.count -ge 1)
        {
            foreach ($a in $ServiceTypeDefinition.OrgSystemServiceTypeAttributes.name)
            {
                $Value = $(Get-Variable -Name $a -Scope Local).Value
                Write-Verbose -Message "Value for $a is $($value -join ',')"
                $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name $a -Value $Value
            }
        }
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
                AutoImport = $null
                Credentials = [PSCustomObject]@{
                    PSSession = $null
                    Service = $null
                }
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
            $DesiredProfileTypeVersion = 1.2
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
                        if (-not (Test-Member -InputObject $se -Name Credentials))
                        {
                            $se | Add-Member -MemberType NoteProperty -Name Credentials -Value $null
                        }
                        foreach ($credential in $AdminUserProfile.Credentials)
                        {
                            if (Test-Member -InputObject $credential -Name Systems)
                            {
                                if ($se.Identity -in $credential.systems)
                                {$se.credentials = @($credential.Identity)}
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
                {$_ -eq 1.1}
                {
                    #SystemEntries Update to user possibly separate credentials for PSSession and Service
                    foreach ($se in $AdminUserProfile.Systems)
                    {
                        if (-not (Test-Member -InputObject $se -Name Credentials))
                        {
                            $se | Add-Member -MemberType NoteProperty -Name Credentials -Value $([pscustomobject]@{PSSession = $se.Credential;Service = $se.Credential})
                            $Se | Remove-Member -Member Credential
                        }
                    }
                    $AdminUserProfile.ProfileTypeVersion = 1.2
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
function GetAdminUserProfileSystemPropertySet
    {
        "Identity","AutoConnect","AutoImport","Credentials","PreferredEndpoint","PreferredPrefix"
    }
#end function GetAdminUserProfileSystemPropertySet
function GetSelectProfile
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            [ValidateSet('Org','Admin')]
            $ProfileType
            ,
            [parameter(Mandatory)]
            $Path
            ,
            [parameter(Mandatory)]
            [psobject[]]$PotentialProfiles
            ,
            [parameter()]
            [AllowNull()]
            $Identity
            ,
            [parameter(Mandatory)]
            [ValidateSet('Remove','Edit','Associate','Get','Use')]
            $Operation
        )
        if ($null -eq $Identity -or (Test-IsNullOrWhiteSpace -String $identity))
        {
            Select-Profile -Profiles $PotentialProfiles -Operation $Operation
        }
        else
        {
            $Profile = $(
                switch ($ProfileType)
                {
                    'Org'
                    {
                        $GetOrgProfileParams = @{
                            ErrorAction = 'Stop'
                            Identity = $Identity
                            Path = $Path
                        }
                        Get-OrgProfile @GetOrgProfileParams
                    }
                    'Admin'
                    {
                        $GetAdminUserProfileParams = @{
                            ErrorAction = 'Stop'
                            Path = $Path
                            Identity = $Identity
                        }
                        Get-AdminUserProfile @GetAdminUserProfileParams
                    }
                }
            )
            if ($null -eq $Profile -or $Profile.count -ge 2 -or $profile.count -eq 0)
            {
                throw("No valid $ProfileType Profile Identity was provided.")
            }
            else
            {
                Write-output -inputobject $Profile
            }
        }
    }
#end function GetSelectProfile
function GetSelectProfileSystem
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            [psobject[]]$PotentialSystems
            ,
            [parameter()]
            [AllowNull()]
            $Identity
            ,
            [parameter(Mandatory)]
            [ValidateSet('Remove','Edit','Associate','Get','Use')]
            $Operation
        )
        $System = $(
            if ($null -eq $Identity -or (Test-IsNullOrWhiteSpace -String $identity))
            {
                Select-ProfileSystem -Systems $PotentialSystems -Operation $Operation
            }
            else
            {
                if ($Identity -in $PotentialSystems.Identity -or $Identity -in $PotentialSystems.Name)
                {$PotentialSystems | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Name -eq $Identity}}
            }
        )
        if ($null -eq $system -or $system.count -ge 2 -or $system.count -eq 0)
        {throw("Invalid SystemIdentity $Identity was provided.  No such system exists or ambiguous system exists.")}
        else
        {Write-Output -inputObject $system}
    }
#end function GetSelectProfile
#################################################
# Public Functions
#################################################
function Get-ServiceTypeDefinition
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [string]$ServiceType
    )
    $Script:ServiceTypes | where-object -FilterScript {$_.Name -eq $ServiceType}
}
#end function Get-ServiceTypeDefinition
Function Get-OrgProfile
    {
        [cmdletbinding(DefaultParameterSetName = 'All')]
        param(
            [parameter(ParameterSetName = 'All')]
            [parameter(ParameterSetName = 'Identity')]
            [parameter(ParameterSetName = 'GetDefault')]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = $Script:OneShellOrgProfilePath
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
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
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
            [parameter()]
            [string[]]$OrganizationSpecificModules
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string]$Path = $script:OneShellOrgProfilePath
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
            [parameter(ParameterSetName = 'Object',ValueFromPipeline)]
            [ValidateScript({$_.ProfileType -eq 'OneShellOrgProfile'})]
            [psobject[]]$OrgProfile
            ,
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [string]$Name
            ,
            [parameter()]
            [ValidateNotNullOrEmpty()]
            [psobject[]]$Systems #Enables copying systems from one org profile to another.  No validation is implemented, however. Replaces all existing Systems when used so use or build an array of systems to use.
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1 -ParameterSetName 'Identity'
            Write-Output -InputObject $dictionary
        }
        Begin
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
                    #nothing to do here at this point
                }
            }#end Switch
        }
        Process
        {
            foreach ($op in $OrgProfile)
            {
                Write-Verbose -Message "Selected Org Profile is $($op.Name)"
                foreach ($p in $PSBoundParameters.GetEnumerator())
                {
                    if ($p.key -in @('Name','Systems'))
                    {
                        $op.$($p.key) = $p.value
                    }
                }
                Export-OrgProfile -profile $op -Path $op.DirectoryPath -ErrorAction 'Stop'
            }
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
        $profile | Remove-Member -Member DirectoryPath
        $JSONparams=@{
            InputObject = $profile
            ErrorAction = 'Stop'
            Depth = 10
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
            [string[]]$Path = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
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
            [parameter(Mandatory,ValueFromPipelineByPropertyName)]
            [string]$Name
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [string]$Description
            ,
            [parameter(Mandatory,ValueFromPipelineByPropertyName)]
            [string]$ServiceType
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [validateset($true,$false)]
            [bool]$ProxyEnabled
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [validateset($true,$false)]
            [bool]$AuthenticationRequired
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [validateset($true,$false)]
            [bool]$UseTLS
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateSet('Basic','Kerberos','Integrated')]
            $AuthMethod
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [AllowEmptyString()]
            [AllowNull()]
            [string]$CommandPrefix
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = $Script:OneShellOrgProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles.Name;$PotentialOrgProfiles.Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            #build any service type specific parameters that may be needed
            $ServiceTypeDefinition = Get-ServiceTypeDefinition -ServiceType $ServiceType
            if ($null -ne $serviceTypeDefinition.OrgSystemServiceTypeAttributes -and $serviceTypeDefinition.OrgSystemServiceTypeAttributes.count -ge 1)
            {
                foreach ($a in $ServiceTypeDefinition.OrgSystemServiceTypeAttributes)
                {
                    $dictionary = New-DynamicParameter -Name $a.name -Type $($a.type -as [type]) -Mandatory $a.mandatory -DPDictionary $dictionary
                }
            }
            Write-Output -InputObject $dictionary
        }#End DynamicParam
        Begin
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the OrgProfile
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
        }
        Process
        {
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
            $global:TestOrgProfile = $OrgProfile
            Export-OrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath
        }
    }
#end function New-OrgSystemObject
function Set-OrgProfileSystem
    {
        [cmdletbinding()]
        param
        (
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
            [string[]]$Identity #System Identity or Name
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [string]$ServiceType
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [string]$Name
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [string]$Description
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [validateset($true,$false)]
            [bool]$ProxyEnabled
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [validateset($true,$false)]
            [bool]$AuthenticationRequired
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [validateset($true,$false)]
            [bool]$UseTLS
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateSet('Basic','Kerberos','Integrated')]
            $AuthMethod
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [AllowEmptyString()]
            [AllowNull()]
            [string]$CommandPrefix
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = $Script:OneShellOrgProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1 -ValueFromPipelineByPropertyName $true
            Write-Output -InputObject $dictionary
        }#End DynamicParam
        Begin
        {
        }
        Process
        {
            foreach ($i in $Identity)
            {
                Set-DynamicParameterVariable -dictionary $dictionary
                #Get/Select the Org Profile
                $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
                #Get/Select the System
                $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $i -Operation Edit
                if ($ServiceType -ne $System.ServiceType) {throw("ServiceType specified does not match the system.")}
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
                #update the system entry in the org profile
                $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
                Export-OrgProfile -profile $OrgProfile -Path $OrgProfile.FilePath
            }
        }
    }
#end function Set-OrgSystemObject
function Set-OrgProfileSystemServiceTypeAttributes
    {
        [cmdletbinding()]
        param
        (
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
            [string[]]$Identity #System Identity or Name
            ,
            [parameter(Mandatory)]
            [string]$ServiceType
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1 -ValueFromPipelineByPropertyName $true
            #build service type specific parameters that may be needed
            $ServiceTypeDefinition = Get-ServiceTypeDefinition -ServiceType $ServiceType
            if ($null -ne $serviceTypeDefinition.OrgSystemServiceTypeAttributes -and $serviceTypeDefinition.OrgSystemServiceTypeAttributes.count -ge 1)
            {
                foreach ($a in $ServiceTypeDefinition.OrgSystemServiceTypeAttributes)
                {
                    $dictionary = New-DynamicParameter -Name $a.name -Type $($a.type -as [type]) -Mandatory $false -DPDictionary $dictionary -ValueFromPipelineByPropertyName $true
                }
            }
            Write-Output -InputObject $dictionary
        }#End DynamicParam
        Process
        {
            foreach ($i in $Identity)
            {
                Set-DynamicParameterVariable -dictionary $dictionary
                #Get/Select the Org Profile
                $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
                #Get/Select the System
                $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $i -Operation Edit
                if ($ServiceType -ne $System.ServiceType) {throw("ServiceType specified does not match the system.")}
                #Edit the selected System
                $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
                #Set the ServiceType Specific System Attributes
                $ServiceTypeDefinition = Get-ServiceTypeDefinition -ServiceType $ServiceType
                if ($null -ne $serviceTypeDefinition.OrgSystemServiceTypeAttributes -and $serviceTypeDefinition.OrgSystemServiceTypeAttributes.count -ge 1)
                {
                    $ServiceTypeAttributeNames = @($ServiceTypeDefinition.OrgSystemServiceTypeAttributes.Name)
                }
                foreach ($vp in $AllValuedParameters)
                {
                    if ($vp.name -in $ServiceTypeAttributeNames)
                    {$System.ServiceTypeAttributes.$($vp.name) = $($vp.value)}
                }
                #update the system entry in the org profile
                $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
                Export-OrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath
            }
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
            [string[]]$Path = $Script:OneShellOrgProfilePath
            ,
            [parameter(ParameterSetName = 'GetCurrent')]
            [switch]$GetCurrent
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $true -Position 1 -ParameterSetName 'ProfileIdentity'
            $dictionary = New-DynamicParameter -Name 'ServiceType' -Type $([string[]]) -ValidateSet @(GetOneShellServiceTypeNames) -HelpMessage 'Specify one or more system types to include' -Mandatory $false -DPDictionary $dictionary -Position 2
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
                    $p.systems | Select-Object -Property *,@{n='OrgName';e={$p.Name}},@{n='OrgIdentity';e={$p.Identity}},@{n='ProfileIdentity';e={$p.Identity}}
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
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateNotNullOrEmpty()]
            [string[]]$Identity #System Identity or Name
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -path $_})]
            [string[]]$Path = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1 -ParameterSetName 'ProfileIdentity'
            Write-Output -InputObject $dictionary
        }
        Begin
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Org Profile
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
        }
        Process
        {
            Foreach ($i in $Identity)
            {
                #Get/Select the System
                $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $i -Operation Remove
                #Remove the system from the Org Profile
                $OrgProfile = Remove-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
                Export-OrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath -ErrorAction Stop
            }
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
            [string]$Path = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            #build any service type specific parameters that may be needed and warn for Exchange* variants that don't need endpoints added
            switch -wildcard ($ServiceType)
            {
                '*'
                {
                    $ServiceTypeDefinition = Get-ServiceTypeDefinition -ServiceType $ServiceType
                    if ($null -ne $serviceTypeDefinition.EndpointServiceTypeAttributes -and $serviceTypeDefinition.EndpointServiceTypeAttributes.count -ge 1)
                    {
                        foreach ($a in $ServiceTypeDefinition.EndpointServiceTypeAttributes)
                        {
                            $dictionary = New-DynamicParameter -Name $a.name -Type $($a.type -as [type]) -Mandatory $a.Mandatory -DPDictionary $dictionary
                        }
                    }
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
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
            #Get/Select the System
            $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $SystemIdentity -Operation Edit
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
            ###########################################################
            $ServiceTypeDefinition = Get-ServiceTypeDefinition -ServiceType $ServiceType
            if ($null -ne $serviceTypeDefinition.EndpointServiceTypeAttributes -and $serviceTypeDefinition.EndpointServiceTypeAttributes.count -ge 1)
            {
                $ServiceTypeAttributeNames = @($ServiceTypeDefinition.EndpointServiceTypeAttributes.Name)
                foreach ($n in $ServiceTypeAttributeNames)
                {
                    $GenericEndpointObject.ServiceTypeAttributes | Add-Member -Name $n -Value $null -MemberType NoteProperty
                }
            }
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in $ServiceTypeAttributeNames)
                {
                    $GenericEndpointObject.ServiceTypeAttributes.$($vp.name) = $($vp.value)
                }
            }
            ###########################################################
            #Add the endpoint object to the system
            $system.endpoints += $GenericEndpointObject
            #update the system on the profile object
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName 'Systems' -IdentityAttributeName 'Identity'
            Export-OrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath -ErrorAction Stop
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
            [string]$Path = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $Dictionary
            #Get/Select the Org Profile
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
            #Get/Select the System
            $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $SystemIdentity -Operation Edit
            if ($System.Endpoints.Count -eq 0) {throw('There are no endpoints to remove')}
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
            Export-OrgProfile -Path $OrgProfile.DirectoryPath -profile $OrgProfile -ErrorAction Stop
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
            [string]$Path = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
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
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
            #Get/Select the System
            $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $SystemIdentity -Operation Edit
            if ($System.Endpoints.Count -eq 0) {throw('There are no endpoints to set')}
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
            #Set any servicetype specific attributes that were specified
            $ServiceTypeDefinition = Get-ServiceTypeDefinition -ServiceType $ServiceType
            if ($null -ne $serviceTypeDefinition.EndpointServiceTypeAttributes -and $serviceTypeDefinition.EndpointServiceTypeAttributes.count -ge 1)
            {
                $ServiceTypeAttributeNames = @($ServiceTypeDefinition.EndpointServiceTypeAttributes.Name)
            }
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in $ServiceTypeAttributeNames)
                {
                    $GenericEndpointObject.ServiceTypeAttributes.$($vp.name) = $($vp.value)
                }
            }
            $System = update-ExistingObjectFromMultivaluedAttribute -ParentObject $System -ChildObject $endPoint -MultiValuedAttributeName Endpoints -IdentityAttributeName Identity
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OrgProfile -Path $OrgProfile.DirectoryPath -profile $OrgProfile -ErrorAction Stop
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
            [string[]]$Path = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$Path = $Script:OneShellOrgProfilePath}
            $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
            $OrgProfileIdentities = @($PotentialOrgProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $PotentialOrgProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $OrgProfileIdentities -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $Dictionary
            #Get/Select the Org Profile
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Get
            #Get/Select the System
            $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $SystemIdentity -Operation Get
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
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
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            if ($null -eq $OrgProfilePath -or [string]::IsNullOrEmpty($OrgProfilePath)) {$OrgProfilePath = $Script:OneShellOrgProfilePath}
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
            [string]$OrgProfilePath = $Script:OneShellOrgProfilePath
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string]$Path = $Script:OneShellAdminUserProfilePath
        )
        DynamicParam
        {
            if ($null -eq $OrgProfilePath -or [string]::IsNullOrEmpty($OrgProfilePath)) {$OrgProfilePath = $Script:OneShellOrgProfilePath}
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
            ,
            [switch]$NoAutoConnect
            ,
            [switch]$NoAutoImport
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
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
            #Write-Verbose -Message $("Members of Joined Systems: " + $($JoinedSystems | get-member -MemberType Properties | Select-Object -ExpandProperty Name) -join ',')
            #Write-Verbose -Message $("Members of Joined Systems Credentials: " + $($JoinedSystems.credentials | get-member -MemberType Properties | Select-Object -ExpandProperty Name) -join ',')
            $Script:CurrentSystems =
            @(
                foreach ($js in $JoinedSystems)
                {
                    foreach ($p in @('PSSession','Service'))
                    {
                        $PreCredential = @($AdminUserProfile.credentials | Where-Object -FilterScript {$_.Identity -eq $js.Credentials.$p})
                        switch ($PreCredential.count)
                        {
                            1
                            {
                                $SSPassword = $PreCredential[0].password | ConvertTo-SecureString
                                $Credential = New-Object System.Management.Automation.PSCredential($PreCredential[0].Username,$SSPassword)
                                #Write-Verbose -Message "Service Credential Found for $($js.name)"
                            }
                            0
                            {
                                $Credential = $null
                                #Write-Verbose -Message "Service Credential Not Found for $($js.name)"
                            }
                        }
                        $js.Credentials.$p = $Credential
                    }
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
        end
        {
            if ($NoAutoConnect -ne $true)
            {
                $AutoConnectSystems = Get-OneShellAvailableSystem | Where-Object -FilterScript {$_.AutoConnect -eq $true}

                if ($NoAutoImport -eq $true)
                {
                    $ConnectOneShellSystemParams = @{
                        NoAutoImport = $true
                    }
                }
                else
                {
                    $ConnectOneShellSystemParams = @{}
                }
                $AutoConnectSystems | foreach-object {Connect-OneShellSystem -identity $_.Identity @ConnectOneShellSystemParams}
            }
        }
    }
#end function Use-AdminUserProfile
function Set-AdminUserProfile
    {
        [cmdletbinding(DefaultParameterSetName="Identity")]
        param
        (
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string]$ProfileFolder
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [string]$Name
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateScript({Test-EmailAddress -EmailAddress $_})]
            $MailFromSMTPAddress
            ,
            [parameter()]
            [switch]$UpdateSystemsFromOrgProfile
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String[]]) -ValidateSet $AdminProfileIdentities -Mandatory $true -ValueFromPipelineByPropertyName $true
            Write-Output -InputObject $dictionary
        }
        Process
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            foreach ($i in $Identity)
            {
                $AdminUserProfile = GetSelectProfile -ProfileType Admin -Path $path -PotentialProfiles $paProfiles -Identity $i -Operation Edit
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
                        $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $AdminUserProfile.organization.identity -Message "No matching Organization Profile was found for identity $OrganizationIdentity"
                        $PSCmdlet.ThrowTerminatingError($errorRecord)
                    }
                    Default
                    {
                        $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $AdminUserProfile.organization.identity -Message "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"
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
                    if ($p.key -in 'ProfileFolder','Name','MailFromSMTPAddress') #,'Credentials','Systems')
                    {$AdminUserProfile.$($p.key) = $p.value}
                }#end foreach
                Export-AdminUserProfile -profile $AdminUserProfile -ErrorAction 'Stop'
            }#end foreach
        }#End Process
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
            ,
            [parameter(ParameterSetName = 'GetCurrent')]
            [switch]$GetCurrent
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 2
            $dictionary = New-DynamicParameter -Name 'ServiceType' -Type $([string[]]) -ValidateSet $(GetOneShellServiceTypeNames) -DPDictionary $dictionary -Mandatory $false -Position 3
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
            [parameter(Position = 1,ValueFromPipelineByPropertyName,ValueFromPipeline)]
            [string]$Identity
            ,
            [parameter()]
            [bool]$AutoConnect
            ,
            [parameter()]
            [bool]$AutoImport
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 2
            Write-Output -inputobject $dictionary
        }
        Begin
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            $AdminProfile = GetSelectProfile -ProfileType Admin -Path $path -PotentialProfiles $paProfiles -Identity $ProfileIdentity -Operation Edit
            Write-Verbose -Message "Loaded Admin User Profile $($adminProfile.name) with Identity $($adminProfile.Identity)"
            #Get/Select the System
            $Systems = Get-AdminUserProfileSystem -ProfileIdentity $AdminProfile.Identity -Path $Path -ErrorAction 'Stop'
        }
        Process
        {
            foreach ($i in $Identity)
            {
                $System = GetSelectProfileSystem -PotentialSystems $Systems -Identity $i -Operation Edit
                #Edit the System
                switch ($PSBoundParameters.getenumerator())
                {
                    {$_.key -eq 'AutoConnect'}
                    {$System.AutoConnect = $AutoConnect}
                    {$_.key -eq 'AutoImport'}
                    {$System.AutoImport = $AutoImport}
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
                }
                #remove any extraneous properties
                $System = $System | Select-Object -Property $(GetAdminUserProfileSystemPropertySet)
                #Save the system changes to the Admin Profile
                $AdminProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $AdminProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
                Export-AdminUserProfile -profile $AdminProfile -path $path -ErrorAction 'Stop'
            }
        }#end Process
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 2
            Write-Output -inputobject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            $AdminProfile = GetSelectProfile -ProfileType Admin -Path $path -PotentialProfiles $paProfiles -Identity $ProfileIdentity -Operation Edit
            #Get/Select the System
            $Systems = Get-AdminUserProfileSystem -ProfileIdentity $AdminProfile.Identity -Path $Path -ErrorAction 'Stop'
            $System = GetSelectProfileSystem -PotentialSystems $Systems -Identity $SystemIdentity -Operation Edit
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
            $System = $System | Select-Object -Property $(GetAdminUserProfileSystemPropertySet)
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
            [parameter(ValueFromPipelineByPropertyName,ValueFromPipeline)]
            [string[]]$SystemIdentity
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [string]$CredentialIdentity
            ,
            [parameter(ValueFromPipelineByPropertyName)]
            [ValidateSet('All','PSSession','Service')]
            $Purpose = 'All'
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 2
            Write-Output -inputobject $dictionary
        }
        Begin
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            $AdminProfile = GetSelectProfile -ProfileType Admin -Path $path -PotentialProfiles $paProfiles -Identity $ProfileIdentity -Operation Edit
            #Get/Select the System
            $Systems = Get-AdminUserProfileSystem -ProfileIdentity $AdminProfile.Identity -Path $Path -ErrorAction 'Stop'
        }
        Process
        {
            if ($SystemIdentity.count -eq 0)
            {
                $SystemIdentity = @(
                    $(GetSelectProfileSystem -PotentialSystems $Systems -Operation Edit).Identity
                )
            }
            foreach ($i in $SystemIdentity)
            {
                $System = GetSelectProfileSystem -PotentialSystems $Systems -Identity $i -Operation Edit
                #Get/Select the Credential
                $Credentials = @(Get-AdminUserProfileCredential -ProfileIdentity $AdminProfile.Identity -ErrorAction 'Stop' -Path $path)
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
                #If this is the first time a credential has been added we may need to add Properties/Attributes
                if ($null -eq $system.Credentials)
                {
                    $system.Credentials = [PSCustomObject]@{PSSession = $null;Service = $null}
                }
                #Remove any existing credential with the same purpose (only one of each purpose is allowed at one time)
                if ($Purpose -eq 'All')
                {
                    $system.Credentials.PSSession = $SelectedCredentialIdentity
                    $system.Credentials.Service = $SelectedCredentialIdentity
                }
                else
                {
                    $system.Credentials.$purpose = $SelectedCredentialIdentity
                }
                $system = $system | Select-Object -Property $(GetAdminUserProfileSystemPropertySet)
                #Save the system changes to the Admin Profile
                $AdminProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $AdminProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
                Export-AdminUserProfile -profile $AdminProfile -path $path -ErrorAction 'Stop'
            }
        }#end End
    }
#end function Set-AdminUserProfileSystemCredential
function Update-AdminUserProfileTypeVersion
    {
        [cmdletbinding()]
        param
        (
            $Path
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'Identity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $true -Position 1
            Write-Output -inputobject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
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
    }
#end function Update-AdminUserProfileTypeVersion
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
            ,
            [parameter()]
            [ValidateScript({Test-DirectoryPath -Path $_})]
            [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
        )
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
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
            $AdminUserProfileSystems = @($AdminUserProfileSystems | Where-Object {$_.Identity -in $OrgProfileSystems.Identity})
            #Add those that are new to the Org Profile
            $NewOrgProfileSystems = @($OrgProfileSystems | Where-Object {$_.Identity -notin $AdminUserProfileSystems.Identity})
            $NewAdminUserProfileSystems = @($AdminUserProfileSystems;$NewOrgProfileSystems)
            $AdminUserProfile.Systems = $NewAdminUserProfileSystems
            Export-AdminUserProfile -profile $AdminUserProfile -ErrorAction 'Stop'
        }#End End
    }
#end function Update-AdminUserProfileSystem
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $paProfiles = GetPotentialAdminUserProfiles -path $Path
            $AdminProfileIdentities = @($paProfiles.name; $paProfiles.Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -DPDictionary $dictionary -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            $AdminProfile = GetSelectProfile -ProfileType Admin -Path $path -PotentialProfiles $paProfiles -Identity $ProfileIdentity -Operation Edit
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -DPDictionary $dictionary -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            $AdminProfile = GetSelectProfile -ProfileType Admin -Path $path -PotentialProfiles $paProfiles -Identity $ProfileIdentity -Operation Edit
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
            #NeededCode:  Remove references to the removed credential from Admin Systems?
        }
    }
#end function Remove-AdminUserProfileCredential
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 1
            Write-Output -InputObject $dictionary
        }
        End
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            #Get/Select the Profile
            $AdminProfile = GetSelectProfile -ProfileType Admin -Path $path -PotentialProfiles $paProfiles -Identity $ProfileIdentity -Operation Edit
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
#end function Set-AdminUserProfileCredential
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
            [string[]]$Path = $Script:OneShellAdminUserProfilePath
        )#end param
        DynamicParam
        {
            if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellAdminUserProfilePath}
            $AdminProfileIdentities = @($paProfiles = GetPotentialAdminUserProfiles -path $Path; $paProfiles | Select-object -ExpandProperty Name -ErrorAction SilentlyContinue; $paProfiles | Select-Object -ExpandProperty Identity)
            $dictionary = New-DynamicParameter -Name 'ProfileIdentity' -Type $([String]) -ValidateSet $AdminProfileIdentities -Mandatory $false -Position 1
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
#end function Get-AdminUserProfileCredential
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
#end function Convert-CredentialToAdminProfileCredential
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
        $whichone = Read-Choice -Message $message -Choices $CredChoices -DefaultChoice 0 -Title $message -Numbered -Vertical
            #switch ($host.Name -like 'Console*')
            #{
            #    $false
            #    {Read-Choice -Message $message -Choices $CredChoices -DefaultChoice 0 -Title $message -Numbered}
            #    $true
            #    {Read-PromptForChoice -Message $message -Choices $CredChoices -DefaultChoice 0 -Numbered} #-Title $message
            #}
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
        $whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
        #$(
        #    switch ($host.Name -like 'Console*')
        #    {
        #        $false
        #        {Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
        #        $true
        #        {Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered}
        #    }
        #)
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
        $whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
        #$(
        #    switch ($host.Name -like 'Console*')
        #    {
        #        $false
        #        {Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
        #        $true
        #        {Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered}
        #    }
        #)
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
        $whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
        #$(
        #    switch ($host.Name -like 'Console*')
        #    {
        #        $false
        #        {Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered}
        #        $true
        #        {Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered}
        #    }
        #)
        Write-Output -InputObject $Profiles[$whichone]
    }
#end function Select-Profile
#################################################
# Need to update
#################################################
function Set-OneShellOrgProfileDirectory
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [string]$Path #If not specified the Path will default to the DefaultPath of $env:ALLUSERSPROFILE\OneShell for OrgProfileDirectoryScope System and to $env:LocalAppData\OneShell for OrgProfileDirectoryScope User
            ,
            [parameter(Mandatory)]
            [validateSet('System','User')]
            [string]$OrgProfileDirectoryScope
            ,
            [parameter()]
            [switch]$DoNotPersist #By Default, this function tries to persist the OrgProfileDirectory to the DefaultPath by writing a JSON file with the setting to that location.  This switch overrides that behavior.
        )
        switch ($OrgProfileDirectoryScope)
        {
            'System'
            {
                $DefaultPath = $("$env:ALLUSERSPROFILE\OneShell")
                if ($Path -ne $DefaultPath)
                {
                    $message = "The recommended/default location for System wide OneShell Org Profile storage is $DefaultPath."
                    Write-Verbose -Message $message -Verbose
                }
                if (-not $PSBoundParameters.ContainsKey('Path'))
                {
                    $Path = $DefaultPath
                }
            }
            'User'
            {
                $DefaultPath = $("$env:LocalAppData\OneShell")
                if ($Path -ne $DefaultPath)
                {
                    $message = "The recommended/default location for User specific OneShell Org Profile storage is $DefaultPath."
                    Write-Verbose -Message $message -Verbose
                }
                if (-not $PSBoundParameters.ContainsKey('Path'))
                {
                    $Path = $DefaultPath
                }
            }
        }
        if (-not (Test-Path -Path $Path -PathType Container))
        {
            Write-Verbose -Message "Creating Directory $Path" -Verbose
            try
            {
                New-Item -Path $Path -ItemType Directory -ErrorAction Stop | Out-Null
            }
            catch
            {
                throw($_)
            }
        }
        if (-not (Test-IsWriteableDirectory -path $path))
        {
            $message = "The specified path exists but does not appear to be writeable. Without elevating or using a different credential this user may be able to use existing OneShell Org Profiles in this location but may not be able to edit them."
            Write-Warning -Message $message
        }
        $Script:OneShellOrgProfilePath = @($Path)

        if (-not $PSBoundParameters.ContainsKey('DoNotPersist'))
        {
            $PersistObject = [PSCustomObject]@{
                OrgProfilePath = $Path
            }
            $PersistFileName = 'OneShellSystemSettings.json'
            $PersistFilePath = Join-Path -Path $DefaultPath -ChildPath $PersistFileName
            if ((Test-IsWriteableDirectory -path $DefaultPath))
            {

                $PersistObject | ConvertTo-Json | Out-File -Encoding utf8 -FilePath $PersistFilePath
            }
            else
            {
                $message = "Unable to write file $PersistFilePath. You may have to use Set-OneShellOrgProfileDirectory with subsequent uses of the OneShell module."
                Write-Warning -Message $message
            }
        }
    }
#end function Set-OneShellOrgProfileDirectory
function GetOneShellOrgProfileDirectory
    {
        [CmdletBinding()]
        param
        ()
        $UserDirectory = $("$env:LocalAppData\OneShell")
        $SystemDirectory = $("$env:ALLUSERSPROFILE\OneShell")
        $PersistFileName = 'OneShellSystemSettings.json'
        $UserFilePath = Join-Path -Path $UserDirectory -ChildPath $PersistFileName
        $SystemFilePath = Join-Path -Path $SystemDirectory -ChildPath $PersistFileName
        if (Test-Path -Path $UserFilePath -PathType Leaf)
        {
            $Script:OneShellOrgProfilePath = $(Import-JSON -Path $UserFilePath).OrgProfilePath
        }
        else
        {
            if (Test-Path -Path $SystemFilePath -PathType Leaf)
            {
                $Script:OneShellOrgProfilePath = $(Import-JSON -Path $SystemFilePath).OrgProfilePath
            }
        }
        if ([string]::IsNullOrWhiteSpace($Script:OneShellOrgProfilePath))
        {
            $message = 'You must run Set-OneShellOrgProfileDirectory. No persisted OneShell Org Profile directories found.'
            Write-Warning -Message $message
        }
    }
#end function GetOneShellOrgProfileDirectory
function Set-OneShellAdminUserProfileDirectory
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [string]$Path #If not specified the Path will default to the DefaultPath of $env:LocalAppData\OneShell
            ,
            [parameter()]
            [switch]$DoNotPersist #By Default, this function tries to persist the AdminUserProfileDirectory to the DefaultPath by writing a JSON file with the setting to that location.  This switch overrides that behavior.
        )
            $DefaultPath = $("$env:LocalAppData\OneShell")
            if ($Path -ne $DefaultPath)
            {
                $message = "The recommended/default location for User specific OneShell Admin User Profile storage is $DefaultPath."
                Write-Verbose -Message $message -Verbose
            }
            if (-not $PSBoundParameters.ContainsKey('Path'))
            {
                $Path = $DefaultPath
            }

        if (-not (Test-Path -Path $Path -PathType Container))
        {
            Write-Verbose -Message "Creating Directory $Path" -Verbose
            try
            {
                New-Item -Path $Path -ItemType Directory -ErrorAction Stop | Out-Null
            }
            catch
            {
                throw($_)
            }
        }
        if (-not (Test-IsWriteableDirectory -path $path))
        {
            $message = "The specified path exists but does not appear to be writeable. Without elevating or using a different credential this user may be able to use existing OneShell Admin User Profiles in this location but may not be able to edit them."
            Write-Warning -Message $message
        }
        $Script:OneShellAdminUserProfilePath = $Path

        if (-not $PSBoundParameters.ContainsKey('DoNotPersist'))
        {
            $PersistObject = [PSCustomObject]@{
                AdminUserProfilePath = $Path
            }
            $PersistFileName = 'OneShellUserSettings.json'
            $PersistFilePath = Join-Path -Path $DefaultPath -ChildPath $PersistFileName
            if ((Test-IsWriteableDirectory -path $DefaultPath))
            {

                $PersistObject | ConvertTo-Json | Out-File -Encoding utf8 -FilePath $PersistFilePath
            }
            else
            {
                $message = "Unable to write file $PersistFilePath. You may have to use Set-OneShellAdminUserProfileDirectory with subsequent uses of the OneShell module."
                Write-Warning -Message $message
            }
        }
    }
#end function Set-OneShellAdminUserProfileDirectory
function GetOneShellAdminUserProfileDirectory
{
    [CmdletBinding()]
    param
    ()
    $UserDirectory = $("$env:LocalAppData\OneShell")
    $PersistFileName = 'OneShellUserSettings.json'
    $UserFilePath = Join-Path -Path $UserDirectory -ChildPath $PersistFileName
    if (Test-Path -Path $UserFilePath -PathType Leaf)
    {
        $Script:OneShellAdminUserProfilePath = $(Import-JSON -Path $UserFilePath).AdminUserProfilePath
    }
    if ([string]::IsNullOrWhiteSpace($Script:OneShellAdminUserProfilePath))
    {
        $message = 'You must run Set-OneShellAdminUserProfileDirectory. No persisted OneShell Admin User Profile directories found.'
        Write-Warning -Message $message
    }
}
#end function GetOneShellOrgProfileDirectory
#################################################
# Need to add
#################################################
Register-ArgumentCompleter -CommandName 'New-OrgProfileSystem', 'Get-ServiceTypeDefinition', 'Set-OrgProfileSystem', 'Set-OrgProfileSystemServiceTypeAttributes', 'New-OrgProfileSystemEndpoint' -ParameterName 'ServiceType' -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)
    GetOneShellServiceTypeNames | Where-Object -FilterScript {$_ -like "$wordToComplete*"} | Sort-Object |
    ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
#? Remove functions for OrgProfile, AdminProfile
#update admin user profile functions with new Path
