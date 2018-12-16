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
            Write-Verbose -Message "Getting json Files From $p"
            (Get-ChildItem -Path "$p\*" -Include '*.json' -Exclude 'OneShellSystemSettings.json')
        }
    )
    Write-Verbose -Message "Found $($jsonProfiles.count) json Files"
    $PotentialOrgProfiles = @(
        foreach ($file in $JSONProfiles)
        {
            Import-Json -Path $file.fullname |
            Where-Object -FilterScript {$_.ProfileType -eq 'OneShellOrgProfile'} |
            Add-Member -MemberType NoteProperty -Name DirectoryPath -Value $File.DirectoryName -PassThru
        }
    )
    Write-Verbose -Message "Found $($PotentialOrgProfiles.count) Potential Org Profiles"
    if ($PotentialOrgProfiles.Count -lt 1)
    {
        throw('You must specify a folder path which contains OneShell Org Profiles with the Path parameter and/or you must create at least one Org Profile using New-OneShellOrgProfile.')
    }
    else
    {
        $PotentialOrgProfiles
    }
}
#end funciton GetPotentialOrgProfiles
function GetPotentialUserProfiles
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
        throw('You must specify the Path parameter or run Set-OneShellUserProfilePath')
    }
    $JSONProfiles = @(
        foreach ($p in $Path)
        {
            Get-ChildItem -Path "$p\*" -Include '*.json' -Exclude 'OneShellUserSettings.json'
        }
    )
    $PotentialUserProfiles = @(
        foreach ($file in $JSONProfiles)
        {
            Import-JSON -Path $file.fullname |
            Where-Object -FilterScript {$_.Profiletype -eq 'OneShellUserProfile'} |
            Add-Member -MemberType NoteProperty -Name DirectoryPath -Value $File.DirectoryName -PassThru
        }
    )
    if ($PotentialUserProfiles.Count -lt 1)
    {
        throw('You must specify a folder path which contains OneShell User Profiles with the Path parameter and/or you must create at least one User Profile using New-OneShellUserProfile.')
    }
    else
    {
        $PotentialUserProfiles
    }
}
#End function GetPotentialUserProfiles
function Get-OneShellServiceTypeName
{
    $script:ServiceTypes.Name
}
#end function Get-OneShellServiceTypeName
function NewGenericOrgProfileObject
{
    [cmdletbinding()]
    param()
    [pscustomobject]@{
        Identity                    = [guid]::NewGuid()
        Name                        = ''
        ProfileType                 = 'OneShellOrgProfile'
        ProfileTypeVersion          = 1.2
        Version                     = .01
        OrganizationSpecificModules = @()
        Systems                     = @()
    }
}
#end function GetGenericNewOrgProfileObject
function NewGenericOrgSystemObject
{
    [cmdletbinding()]
    param()
    [pscustomobject]@{
        Identity              = [guid]::NewGuid()
        Name                  = ''
        Description           = ''
        ServiceType           = ''
        SystemObjectVersion   = .01
        Version               = .01
        Defaults              = [PSCustomObject]@{
            ProxyEnabled           = $null
            AuthenticationRequired = $true
            UseTLS                 = $null
            AuthMethod             = $null
            CommandPrefix          = $null
            UsePSRemoting          = $true
        }
        Endpoints             = @()
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
    $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
    Write-Verbose -Message "Using ServiceTypeDefinition $($ServiceTypeDefinition.name)"
    if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.System -and $ServiceTypeDefinition.ServiceTypeAttributes.System.count -ge 1)
    {
        foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.System.name)
        {
            $Value = $(Get-Variable -Name $a -Scope Local).Value
            Write-Verbose -Message "Value for $a is $($value -join ',')"
            $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name $a -Value $Value
        }
    }
    $OrgSystemObject
}
#end function AddServiceTypeAttributesToGenericOrgSystemObject
function NewGenericSystemEndpointObject
{
    [cmdletbinding()]
    param()
    [PSCustomObject]@{
        Identity               = [guid]::NewGuid()
        AddressType            = $null
        Address                = $null
        ServicePort            = $null
        UseTLS                 = $null
        ProxyEnabled           = $null
        CommandPrefix          = $null
        AuthenticationRequired = $null
        AuthMethod             = $null
        EndpointGroup          = $null
        Precedence             = $null
        EndpointType           = $null
        ServiceTypeAttributes  = [PSCustomObject]@{}
        ServiceType            = $null
        PSRemoting             = $null
    }
}
#end function NewGenericSystemEndpointObject
function NewGenericUserProfileObject
{
    [cmdletbinding()]
    param
    (
        $TargetOrgProfile
    )
    [pscustomobject]@{
        Identity            = [guid]::NewGuid()
        ProfileType         = 'OneShellUserProfile'
        ProfileTypeVersion  = 1.4
        Name                = $targetOrgProfile.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME
        Host                = $env:COMPUTERNAME
        User                = $env:USERNAME
        Organization        = [pscustomobject]@{
            Name     = $targetOrgProfile.Name
            Identity = $targetOrgProfile.identity
        }
        ProfileFolder       = ''
        LogFolder           = ''
        ExportDataFolder    = ''
        InputFilesFolder    = ''
        MailFromSMTPAddress = ''
        Systems             = @()
        Credentials         = @()
    }
}#end function NewGenericUserProfileObject
function GetOrgProfileSystemForUserProfile
{
    [cmdletbinding()]
    param($OrgProfile)
    foreach ($s in $OrgProfile.Systems)
    {
        [PSCustomObject]@{
            Identity          = $s.Identity
            AutoConnect       = $null
            AutoImport        = $null
            Credentials       = [PSCustomObject]@{
                PSSession = $null
                Service   = $null
            }
            PreferredEndpoint = $null
            PreferredPrefix   = $null
            UsePSRemoting     = $null
            ProxyEnabled      = $null
            AuthenticationRequired = $null
            UseTLS = $null
            AuthMethod = $null
        }
    }
}
#end function GetOrgProfileSystemForUserProfile
function UpdateUserProfileObjectVersion
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $UserProfile
        ,
        $DesiredProfileTypeVersion = $Script:UserProfileTypeLatestVersion
    )
    do
    {
        switch ($UserProfile.ProfileTypeVersion)
        {
            {$_ -lt 1}
            {
                #Upgrade ProfileVersion to 1
                #MailFrom
                if (-not (Test-Member -InputObject $UserProfile.General -Name MailFrom))
                {
                    $UserProfile.General | Add-Member -MemberType NoteProperty -Name MailFrom -Value $null
                }
                #UserName
                if (-not (Test-Member -InputObject $UserProfile.General -Name User))
                {
                    $UserProfile.General | Add-Member -MemberType NoteProperty -Name User -Value $env:USERNAME
                }
                #MailRelayEndpointToUse
                if (-not (Test-Member -InputObject $UserProfile.General -Name MailRelayEndpointToUse))
                {
                    $UserProfile.General | Add-Member -MemberType NoteProperty -Name MailRelayEndpointToUse -Value $null
                }
                #ProfileTypeVersion
                if (-not (Test-Member -InputObject $UserProfile -Name ProfileTypeVersion))
                {
                    $UserProfile | Add-Member -MemberType NoteProperty -Name ProfileTypeVersion -Value 1.0
                }
                #Credentials add Identity
                foreach ($Credential in $UserProfile.Credentials)
                {
                    if (-not (Test-Member -InputObject $Credential -Name Identity))
                    {
                        $Credential | Add-Member -MemberType NoteProperty -Name Identity -Value $(New-OneShellGuid).guid
                    }
                }
                #SystemEntries
                foreach ($se in $UserProfile.Systems)
                {
                    if (-not (Test-Member -InputObject $se -Name Credentials))
                    {
                        $se | Add-Member -MemberType NoteProperty -Name Credentials -Value $null
                    }
                    foreach ($credential in $UserProfile.Credentials)
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
                    foreach ($Credential in $UserProfile.Credentials)
                    {
                        if (Test-Member -InputObject $Credential -Name Systems)
                        {
                            $UpdatedCredential = $Credential | Select-Object -Property Identity, Username, Password
                            $UpdatedCredential
                        }
                        else
                        {
                            $Credential
                        }
                    }
                )
                $UserProfile.Credentials = $UpdatedCredentialObjects
            }#end $_ -lt 1
            {$_ -eq 1}
            {
                $NewMembers = ('ProfileFolder', 'Name', 'MailFromSMTPAddress')
                foreach ($nm in $NewMembers)
                {
                    if (-not (Test-Member -InputObject $UserProfile -Name $nm))
                    {
                        $UserProfile | Add-Member -MemberType NoteProperty -Name $nm -Value $null
                    }
                    switch ($nm)
                    {
                        'MailFromSMTPAddress'
                        {$UserProfile.$nm = $UserProfile.General.MailFrom}
                        Default
                        {$UserProfile.$nm = $UserProfile.General.$nm}
                    }
                }
                $UserProfile | Add-Member -MemberType NoteProperty -Value $([pscustomobject]@{Identity = $null; Name = $null}) -name Organization
                $UserProfile.Organization.Identity = $UserProfile.General.OrganizationIdentity
                $UserProfile | Remove-member -member General
                $UserProfile.ProfileTypeVersion = 1.1
            }
            {$_ -eq 1.1}
            {
                #SystemEntries Update to user possibly separate credentials for PSSession and Service
                foreach ($se in $UserProfile.Systems)
                {
                    if (-not (Test-Member -InputObject $se -Name Credentials))
                    {
                        $se | Add-Member -MemberType NoteProperty -Name Credentials -Value $([pscustomobject]@{PSSession = $se.Credential; Service = $se.Credential})
                        $Se | Remove-Member -Member Credential
                    }
                }
                $UserProfile.ProfileTypeVersion = 1.2
            }
            {$_ -eq 1.2}
            {
                #Add attributes for discrete LogFolder, ExportDataFolder, and InputFilesFolder
                $NewMembers = ('LogFolder', 'ExportDataFolder', 'InputFilesFolder')
                foreach ($nm in $NewMembers)
                {
                    if (-not (Test-Member -InputObject $UserProfile -name $nm))
                    {
                        $UserProfile | Add-Member -MemberType NoteProperty -Name $nm -Value $null
                    }
                }
                $UserProfile.ProfileTypeVersion = 1.3
            }
            {$_ -eq 1.3}
            {
                $NewMembers = GetUserProfileSystemPropertySet
                foreach ($s in $UserProfile.systems)
                {
                    Add-RequiredMember -RequiredMember $NewMembers -InputObject $s
                }
                $UserProfile.ProfileTypeVersion = 1.4
            }
        }#end switch
    }
    Until ($UserProfile.ProfileTypeVersion -eq $DesiredProfileTypeVersion)
    $UserProfile
}
#end function UpdateUserProfileObjectVersion
function AddUserProfileFolder
{
    [cmdletbinding()]
    param
    (
        $UserProfile
    )
    $profileFolder = $UserProfile.ProfileFolder
    if ($null -eq $profileFolder -or [string]::IsNullOrEmpty($profileFolder))
    {throw("User Profile $($UserProfile.Identity) Profile Folder is invalid.")}
    if (-not (Test-Path -Path $profileFolder))
    {
        [void](New-Item -Path $profileFolder -ItemType Directory -ErrorAction Stop)
    }
    $profileSubfolders = $(join-path $profilefolder 'Logs'), $(join-path $profilefolder 'Export'), $(join-path $profileFolder 'InputFiles')
    foreach ($folder in $profileSubfolders)
    {
        if (-not (Test-Path -Path $folder))
        {
            [void](New-Item -Path $folder -ItemType Directory -ErrorAction Stop)
        }
    }
}
#end function AddUserProfileFolder
function GetUserProfileSystemPropertySet
{
    "Identity", "AutoConnect", "AutoImport", "Credentials", "PreferredEndpoint", "PreferredPrefix","UsePSRemoting","ProxyEnabled","AuthenticationRequired","UseTLS","AuthMethod"
}
#end function GetUserProfileSystemPropertySet
function GetSelectProfile
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [ValidateSet('Org', 'User')]
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
        [ValidateSet('Remove', 'Edit', 'Associate', 'Get', 'Use')]
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
                        Identity    = $Identity
                        Path        = $Path
                    }
                    Get-OneShellOrgProfile @GetOrgProfileParams
                }
                'User'
                {
                    $GetUserProfileParams = @{
                        ErrorAction = 'Stop'
                        Path        = $Path
                        Identity    = $Identity
                    }
                    Get-OneShellUserProfile @GetUserProfileParams
                }
            }
        )
        if ($null -eq $Profile -or $Profile.count -ge 2 -or $profile.count -eq 0)
        {
            throw("No valid $ProfileType Profile Identity was provided.")
        }
        else
        {
            $Profile
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
        [ValidateSet('Remove', 'Edit', 'Associate', 'Get', 'Use')]
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
    {$system}
}
#end function GetSelectProfile
#################################################
# Public Functions
#################################################
function Get-OneShellServiceTypeDefinition
{
    [cmdletbinding()]
    param
    (
        [parameter()]
        [string]$ServiceType
    )
    $Script:ServiceTypes | where-object -FilterScript {$_.Name -eq $ServiceType -or (Test-IsNullOrWhiteSpace -String $ServiceType)}
}
#end function Get-OneShellServiceTypeDefinition
Function Get-OneShellOrgProfile
{
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param
    (
        [parameter(ParameterSetName = 'Identity', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        $OrgProfileType = 'OneShellOrgProfile'
        ,
        [parameter(ParameterSetName = 'GetCurrent')]
        [switch]$GetCurrent
    )
    Process
    {
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
                            foreach ($i in $Identity)
                            {
                                Write-Verbose -Message "Identity is set to $"
                                @($FoundOrgProfiles | Where-Object -FilterScript {$_.Identity -eq $i -or $_.Name -eq $i})
                            }
                        }#Identity
                        'All'
                        {
                            @($FoundOrgProfiles)
                        }#All
                    }#switch
                }#if
            }#Default
        }#switch
    }#end Process
}
#end Function Get-OneShellOrgProfile
function New-OneShellOrgProfile
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
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$Path = $script:OneShellOrgProfilePath
    )
    $GenericOrgProfileObject = NewGenericOrgProfileObject
    $GenericOrgProfileObject.Name = $Name
    $GenericOrgProfileObject.OrganizationSpecificModules = $OrganizationSpecificModules
    Export-OneShellOrgProfile -profile $GenericOrgProfileObject -path $path -erroraction Stop
}
#end function New-OneShellOrgProfile
function Set-OneShellOrgProfile
{
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(ParameterSetName = 'Identity', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Identity
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [psobject[]]$Systems #Enables copying systems from one org profile to another.  No validation is implemented, however. Replaces all existing Systems when used so use or build an array of systems to use. Use with caution for existing profiles.
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )
    Process
    {
        foreach ($i in $Identity)
        {
            #Get the Org Profile
            $GetOrgProfileParams = @{
                ErrorAction = 'Stop'
                Identity    = $Identity
                Path        = $Path
            }
            $OrgProfile = $(Get-OneShellOrgProfile @GetOrgProfileParams)
            Write-Verbose -Message "Selected Org Profile is $($OrgProfile.Name)"
            foreach ($p in $PSBoundParameters.GetEnumerator())
            {
                if ($p.key -in @('Name', 'Systems'))
                {
                    $OrgProfile.$($p.key) = $p.value
                }
            }
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath -ErrorAction 'Stop'
        }
    }
}
#end function Set-OneShellOrgProfile
Function Export-OneShellOrgProfile
{
    [cmdletbinding(SupportsShouldProcess)]
    param
    (
        [parameter(Mandatory)]
        [psobject]$profile
        ,
        [parameter(Mandatory)]
        [AllowNull()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
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
    $JSONparams = @{
        InputObject = $profile
        ErrorAction = 'Stop'
        Depth       = 10
    }
    $OutParams = @{
        ErrorAction = 'Stop'
        FilePath    = $FilePath
        Encoding    = 'ascii'
    }
    if ($whatifPreference -eq $false)
    {$OutParams.Force = $true}
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
#end Function Export-OneShellOrgProfile
Function Use-OneShellOrgProfile
{
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'Object')]
        $profile
        ,
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )
    end
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'Object'
            {}
            'Identity'
            {
                $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
                if ($null -eq $Identity)
                {
                    $Profile = Select-Profile -Profiles $PotentialOrgProfiles -Operation Edit
                }
                else
                {
                    #Get the Org Profile
                    $GetOrgProfileParams = @{
                        ErrorAction = 'Stop'
                        Identity    = $Identity
                        Path        = $Path
                    }
                    $Profile = $(Get-OneShellOrgProfile @GetOrgProfileParams)
                }
            }
        }# end switch
        if ($null -ne $script:CurrentOrgProfile -and $profile.Identity -ne $script:CurrentOrgProfile.Identity)
        {
            $script:CurrentOrgProfile = $profile
            Write-OneShellLog -message "Org Profile has been changed to $($script:CurrentOrgProfile.Identity), $($script:CurrentOrgProfile.name).  Remove PSSessions and select an user Profile to load." -EntryType Notification -Verbose
        }
        else
        {
            $script:CurrentOrgProfile = $profile
            Write-OneShellLog -Message "Org Profile has been set to $($script:CurrentOrgProfile.Identity), $($script:CurrentOrgProfile.name)." -EntryType Notification -Verbose
        }
    }
}
#end function Use-OneShellOrgProfile
function New-OneShellOrgProfileSystem
{
    [cmdletbinding(SupportsShouldProcess)]
    param
    (
        [parameter(ParameterSetName = 'Identity', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$Description
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ServiceType
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$ProxyEnabled
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$AuthenticationRequired
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$UseTLS
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$UsePSRemoting
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Basic', 'Kerberos', 'Integrated')]
        $AuthMethod
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$CommandPrefix
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )#end param
    DynamicParam
    {
        #build any service type specific parameters that may be needed
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.System -and $ServiceTypeDefinition.ServiceTypeAttributes.System.count -ge 1)
        {
            foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.System)
            {
                $newDynamicParameterParams = @{
                    Name = $a.name
                    Type = $($a.type -as [type])
                    Mandatory = $a.mandatory
                    DPDictionary = $dictionary
                }
                if ($true -eq $a.Value) {$newDynamicParameterParams.ValidateSet = $a.Value}
                $dictionary = New-DynamicParameter @newDynamicParameterParams
            }
        }
        $dictionary
    }#End DynamicParam
    Begin
    {
        $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
        if ($null -ne $dictionary)
        {
            Set-DynamicParameterVariable -dictionary $dictionary
        }
        #Get/Select the OrgProfile
        $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
        #Build the System Object
        $GenericSystemObject = NewGenericOrgSystemObject
        $GenericSystemObject.ServiceType = $ServiceType
        #Edit the selected System
        $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
        #Set the common System Attributes
        foreach ($vp in $AllValuedParameters)
        {
            if ($vp.name -in 'Name', 'Description')
            {$GenericSystemObject.$($vp.name) = $($vp.value)}
        }
        #set the default System Attributes
        foreach ($vp in $AllValuedParameters)
        {
            if ($vp.name -in 'UseTLS', 'ProxyEnabled', 'CommandPrefix', 'AuthenticationRequired', 'AuthMethod','UsePSRemoting')
            {$GenericSystemObject.defaults.$($vp.name) = $($vp.value)}
        }
        $addServiceTypeAttributesParams = @{
            OrgSystemObject = $GenericSystemObject
            ServiceType     = $ServiceType
        }
        if ($null -ne $Dictionary)
        {$addServiceTypeAttributesParams.Dictionary = $Dictionary}
        $GenericSystemObject = AddServiceTypeAttributesToGenericOrgSystemObject @addServiceTypeAttributesParams
        $OrgProfile.Systems += $GenericSystemObject
        Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath
    }
}
#end function New-OrgSystemObject
function Set-OneShellOrgProfileSystem
{
    [cmdletbinding()]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Identity')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity #System Identity or Name
        #,switching service types of a system is not currently supported because of ServiceTypeAttributes for systems and endpoints
        #[parameter(ValueFromPipelineByPropertyName)]
        #[string]$ServiceType
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$Name
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$Description
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ServiceType
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$ProxyEnabled
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$AuthenticationRequired
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$UseTLS
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [validateset($true, $false)]
        [bool]$UsePSRemoting
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Basic', 'Kerberos', 'Integrated')]
        $AuthMethod
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$CommandPrefix
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )#end param
    DynamicParam
    {
        #build any service type specific parameters that may be needed
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.System -and $ServiceTypeDefinition.ServiceTypeAttributes.System.count -ge 1)
        {
            foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.System)
            {
                $newDynamicParameterParams = @{
                    Name = $a.name
                    Type = $($a.type -as [type])
                    Mandatory = $false #$a.mandatory
                    DPDictionary = $dictionary
                }
                if ($true -eq $a.Value) {$newDynamicParameterParams.ValidateSet = $a.Value}
                $dictionary = New-DynamicParameter @newDynamicParameterParams
            }
        }
        $dictionary
    }#End DynamicParam
    Begin
    {
        $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
        if ($null -ne $dictionary)
        {
            Set-DynamicParameterVariable -dictionary $dictionary
        }
    }
    Process
    {
        foreach ($i in $Identity)
        {
            #Get/Select the Org Profile
            $OrgProfile = GetSelectProfile -ProfileType Org -Path $path -PotentialProfiles $PotentialOrgProfiles -Identity $ProfileIdentity -Operation Edit
            #Get/Select the System
            $System = GetSelectProfileSystem -PotentialSystems $OrgProfile.Systems -Identity $i -Operation Edit
            #Edit the selected System
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            #Set the common System Attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'Name', 'Description', 'ServiceType')
                {$System.$($vp.name) = $($vp.value)}
            }
            #set the default System Attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'UseTLS', 'ProxyEnabled', 'CommandPrefix', 'AuthenticationRequired', 'AuthMethod','UsePSRemoting')
                {$System.defaults.$($vp.name) = $($vp.value)}
            }
            #set the ServiceType Attributes
            #make sure they exist on the object
            $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $System.ServiceType
            Add-RequiredMember -RequiredMember $ServiceTypeDefinition.ServiceTypeAttributes.System.Name -InputObject $System.ServiceTypeAttributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in $ServiceTypeDefinition.ServiceTypeAttributes.System.Name)
                {$System.ServiceTypeAttributes.$($vp.name) = $($vp.value)}
            }
            #update the system entry in the org profile
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath
        }
    }
}
#end function Set-OrgSystemObject
function Set-OneShellOrgProfileSystemServiceTypeAttribute
{
    [cmdletbinding()]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipelineByPropertyName, Mandatory)]
        [string]$ProfileIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity #System Identity or Name
        ,
        [parameter(Mandatory)]
        [string]$ServiceType
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )#end param
    DynamicParam
    {
        #build any service type specific parameters that may be needed
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.System -and $ServiceTypeDefinition.ServiceTypeAttributes.System.count -ge 1)
        {
            foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.System)
            {
                $newDynamicParameterParams = @{
                    Name = $a.name
                    Type = $($a.type -as [type])
                    Mandatory = $a.mandatory
                    DPDictionary = $dictionary
                }
                if ($true -eq $a.Value) {$newDynamicParameterParams.ValidateSet = $a.Value}
                $dictionary = New-DynamicParameter @newDynamicParameterParams
            }
        }
        $dictionary
    }#End DynamicParam
    Begin
    {
        $PotentialOrgProfiles = GetPotentialOrgProfiles -path $Path
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
            #Set the ServiceType Specific System Attributes
            $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
            if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.System -and $ServiceTypeDefinition.ServiceTypeAttributes.System.count -ge 1)
            {
                $ServiceTypeAttributeNames = @($ServiceTypeDefinition.ServiceTypeAttributes.System.Name)
            }
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in $ServiceTypeAttributeNames)
                {$System.ServiceTypeAttributes.$($vp.name) = $($vp.value)}
            }
            #update the system entry in the org profile
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath
        }
    }
}
#end function Set-OrgSystemObject
Function Get-OneShellOrgProfileSystem
{
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity #System Identity or Name
        ,
        [parameter(ParameterSetName = 'Identity')]
        [parameter(ParameterSetName = 'All')]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
        ,
        [parameter(ParameterSetName = 'GetCurrent')]
        [switch]$GetCurrent
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [string[]]$ServiceType
        ,
        [parameter(ParameterSetName = 'Identity')]
        [string[]]$ProfileIdentity
    )
    Begin
    {
        $profiles = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'GetCurrent'
                {
                    Get-OneShellOrgProfile -GetCurrent -ErrorAction Stop -Path $Path
                }
                'Identity'
                {
                    if ($PsBoundParameters.ContainsKey('ProfileIdentity'))
                    {
                        Get-OneShellOrgProfile -Identity $ProfileIdentity -ErrorAction Stop -Path $Path
                    }
                    else
                    {
                        Get-OneShellOrgProfile -Path $Path -ErrorAction Stop
                    }
                }
                'All'
                {
                    Get-OneShellOrgProfile -ErrorAction Stop -Path $Path
                }
            }
        )
        $OutputSystems = @(
            foreach ($p in $profiles)
            {
                $p.systems #| Select-Object -Property *, @{n = 'OrgName'; e = {$p.Name}}, @{n = 'OrgIdentity'; e = {$p.Identity}}, @{n = 'ProfileIdentity'; e = {$p.Identity}}
            }
        )
        #Filter outputSystems if required by specified parameters
        $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.ServiceType -in $ServiceType -or (Test-IsNullOrWhiteSpace -string $ServiceType)})
        $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.Identity -in $Identity -or $_.Name -in $Identity -or (Test-IsNullorWhiteSpace -string $Identity)})
        $OutputSystems
    }
}
#end function Get-OneShellOrgProfileSystem
Function Remove-OneShellOrgProfileSystem
{
    [cmdletbinding(SupportsShouldProcess)]
    param
    (
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity #System Identity or Name
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
    )
    Process
    {
        Foreach ($i in $Identity)
        {
            #Get the System and then the profile from the system
            $System = Get-OneShellOrgProfileSystem -Identity $Identity -Path $Path -ErrorAction Stop -ProfileIdentity $ProfileIdentity
            $OrgProfile = Get-OneShellOrgProfile -Identity $ProfileIdentity
            #Remove the system from the Org Profile
            $OrgProfile = Remove-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath -ErrorAction Stop
        }
    }
}
#end function Remove-OneShellOrgProfileSystem
function New-OneShellOrgProfileSystemEndpoint
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$SystemIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ServiceType
        ,
        [Parameter(Mandatory)]
        [ValidateSet('URL', 'IPAddress', 'FQDN')]
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
        [ValidateSet($true, $false, $null)]
        $UseTLS
        ,
        [parameter()]
        [AllowNull()]
        [validateSet($true, $false, $null)]
        $ProxyEnabled = $false
        ,
        [parameter()]
        [ValidateLength(2, 5)]
        $CommandPrefix
        ,
        [parameter()]
        [AllowNull()]
        [validateSet($true, $false, $null)]
        $AuthenticationRequired
        ,
        [parameter()]
        [ValidateSet('Basic', 'Kerberos', 'Integrated')]
        $AuthMethod
        ,
        [parameter()]
        [string]$EndpointGroup
        ,
        [parameter()]
        [int16]$Precedence
        ,
        [parameter()]
        [ValidateSet('Admin', 'MRSProxyServer')]
        [string]$EndpointType = 'Admin'
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$Path = $Script:OneShellOrgProfilePath
    )
    DynamicParam
    {
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint -and $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.count -ge 1)
        {
            foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint)
            {
                $Dictionary = New-DynamicParameter -Name $a.name -Type $($a.type -as [type]) -Mandatory $a.Mandatory -DPDictionary $Dictionary
            }
        }
        #if (Test-IsNotNullOrWhiteSpace -string $ServiceTypeDefinition.WellKnownEndpointURI)
        #{Write-Warning -Message "$($serviceType) systems in OneShell use a well-known endpoint $($ServiceTypeDefinition.WellKnownEndpointURI). If you create an endpoint for this system type it will be ignored when connecting to this system."}
        $Dictionary
    }#End DynamicParam
    Process
    {
        Foreach ($i in $SystemIdentity)
        {
            if ($null -ne $Dictionary)
            {
                Set-DynamicParameterVariable -dictionary $Dictionary
            }
            #Get the System and then the profile from the system
            $System = Get-OneShellOrgProfileSystem -Identity $i -Path $Path -ErrorAction Stop -ProfileIdentity $ProfileIdentity
            $OrgProfile = Get-OneShellOrgProfile -Identity $ProfileIdentity
            if ($ServiceType -ne $system.ServiceType)
            {throw("Invalid ServiceType $serviceType specified (does not match system ServiceType $($system.servicetype))")}
            #Get the new endpoint object
            $GenericEndpointObject = NewGenericSystemEndpointObject
            #Set the new endpoint object attributes
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'AddressType', 'Address', 'ServicePort', 'UseTLS', 'ProxyEnabled', 'CommandPrefix', 'AuthenticationRequired', 'AuthMethod', 'EndpointGroup', 'EndpointType', 'ServiceType', 'Precedence')
                {$GenericEndpointObject.$($vp.name) = $($vp.value)}
            }
            #Add any servicetype specific attributes that were specified
            ###########################################################
            $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
            if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint -and $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.count -ge 1)
            {
                $ServiceTypeAttributeNames = @($ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.Name)
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
            #Strip 'extra' Org Attributes that were added
            $system = $system | Select-Object -Property * -excludeProperty OrgName, OrgIdentity, ProfileIdentity
            #update the system on the profile object
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName 'Systems' -IdentityAttributeName 'Identity'
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath -ErrorAction Stop
        }
    }
}
#end function New-OneShellOrgProfileSystemEndpoint
function Remove-OneShellOrgProfileSystemEndpoint
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$SystemIdentity
        ,
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$Path = $Script:OneShellOrgProfilePath
    )
    Process
    {
        #Get Org Profile
        $OrgProfile = Get-OneShellOrgProfile -Identity $ProfileIdentity -Path $Path -ErrorAction Stop
        #Get the System
        $System = Get-OneShellOrgProfileSystem -Identity $SystemIdentity -Path $Path -ErrorAction Stop
        if ($System.Endpoints.Count -eq 0) {throw('There are no endpoints to remove')}
        #Get the Endpoint
        foreach ($i in $Identity)
        {
            $endPoint = @($System.Endpoints | Where-Object -FilterScript {
                    $_.Identity -eq $i -or $_.Address -eq $i
                })
            if ($endPoint.Count -ne 1) {throw ("Invalid or Ambiguous Endpoint Identity $Identity Provided")}
            else {$Endpoint = $Endpoint[0]}
            $System = Remove-ExistingObjectFromMultivaluedAttribute -ParentObject $System -ChildObject $endPoint -MultiValuedAttributeName Endpoints -IdentityAttributeName Identity
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OneShellOrgProfile -Path $OrgProfile.DirectoryPath -profile $OrgProfile -ErrorAction Stop
        }
    }
}
#end function Remove-OneShellOrgProfileSystemEndpoint
function Set-OneShellOrgProfileSystemEndpoint
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$SystemIdentity
        ,
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ServiceType
        ,
        [Parameter()]
        [ValidateSet('URL', 'IPAddress', 'FQDN')]
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
        [ValidateSet($true, $false, $null)]
        $UseTLS
        ,
        [parameter()]
        [AllowNull()]
        [validateSet($true, $false, $null)]
        $ProxyEnabled = $false
        ,
        [parameter()]
        [ValidateLength(2, 5)]
        $CommandPrefix
        ,
        [parameter()]
        [AllowNull()]
        [validateSet($true, $false, $null)]
        $AuthenticationRequired
        ,
        [parameter()]
        [ValidateSet('Basic', 'Kerberos', 'Integrated')]
        $AuthMethod
        ,
        [parameter()]
        $EndpointGroup
        ,
        [parameter()]
        [int16]$Precedence
        ,
        [parameter()]
        [ValidateSet('Admin', 'MRSProxyServer')]
        [string]$EndpointType = 'Admin'
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$Path = $Script:OneShellOrgProfilePath
    )
    DynamicParam
    {
        $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint -and $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.count -ge 1)
        {
            foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint)
            {
                $Dictionary = New-DynamicParameter -Name $a.name -Type $($a.type -as [type]) -Mandatory $a.Mandatory -DPDictionary $Dictionary
            }
        }
        #if (Test-IsNotNullOrWhiteSpace -string $ServiceTypeDefinition.WellKnownEndpointURI)
        #{Write-Warning -Message "$($serviceType) systems in OneShell use a well-known endpoint $($ServiceTypeDefinition.WellKnownEndpointURI). If you create an endpoint for this system type it will be ignored when connecting to this system."}
        $Dictionary
    }#End DynamicParam
    Process
    {
        if ($null -ne $Dictionary)
        {
            Set-DynamicParameterVariable -dictionary $Dictionary
        }
        #Get Org Profile
        $OrgProfile = Get-OneShellOrgProfile -Identity $ProfileIdentity -Path $Path -ErrorAction Stop
        #Get the System
        $System = Get-OneShellOrgProfileSystem -Identity $SystemIdentity -Path $Path -ErrorAction Stop
        if ($System.Endpoints.Count -eq 0) {throw('There are no endpoints to set')}
        #Get the Endpoint
        foreach ($i in $Identity)
        {
            $endPoint = @($System.Endpoints | Where-Object -FilterScript {
                    $_.Identity -eq $i -or $_.Address -eq $i
                })
            if ($endPoint.Count -ne 1) {throw ("Invalid or Ambiguous Endpoint Identity $Identity Provided")}
            else {$Endpoint = $Endpoint[0]}
            $AllValuedParameters = Get-AllParametersWithAValue -BoundParameters $PSBoundParameters -AllParameters $MyInvocation.MyCommand.Parameters
            #Set the new endpoint object attributes
            foreach ($vp in $AllValuedParameters)
            {
                if ($vp.name -in 'AddressType', 'Address', 'ServicePort', 'UseTLS', 'ProxyEnabled', 'CommandPrefix', 'AuthenticationRequired', 'AuthMethod', 'EndpointGroup', 'EndpointType', 'ServiceType', 'Precedence')
                {$endpoint.$($vp.name) = $($vp.value)}
            }
        }
        #Set any servicetype specific attributes that were specified
        if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint -and $ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.count -ge 1)
        {
            $ServiceTypeAttributeNames = @($ServiceTypeDefinition.ServiceTypeAttributes.Endpoint.Name)
        }
        foreach ($vp in $AllValuedParameters)
        {
            if ($vp.name -in $ServiceTypeAttributeNames)
            {
                $Endpoint.ServiceTypeAttributes.$($vp.name) = $($vp.value)
            }
        }
        $System = update-ExistingObjectFromMultivaluedAttribute -ParentObject $System -ChildObject $Endpoint -MultiValuedAttributeName Endpoints -IdentityAttributeName Identity
        $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity
        Export-OneShellOrgProfile -Path $OrgProfile.DirectoryPath -profile $OrgProfile -ErrorAction Stop
    }#end End
}
#end function Set-OneShellOrgProfileSystemEndpoint
function Get-OneShellOrgProfileSystemEndpoint
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        $ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$SystemIdentity
        ,
        [parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )
    Process
    {
        #Get the System
        $System = Get-OneShellOrgProfileSystem -Identity $SystemIdentity -Path $Path -ErrorAction Stop -ProfileIdentity $ProfileIdentity
        $Endpoints = @(
            $System.endpoints | Where-Object  -FilterScript {$_.Identity -in $identity -or $_.Address -in $Identity -or (Test-IsNullOrWhiteSpace -String $identity)}
        )
        $Endpoints
    }
}
#end function Get-OneShellOrgProfileSystemEndpoint
Function Get-OneShellUserProfile
{
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter(ParameterSetName = 'OrgProfileIdentity')]
        [string]$OrgProfileIdentity
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        $ProfileType = 'OneShellUserProfile'
        ,
        [parameter(ParameterSetName = 'All')]
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath
        ,
        [parameter(ParameterSetName = 'GetCurrent')]
        [switch]$GetCurrent
    )#end param
    Begin
    {
    }
    Process
    {
        $outputprofiles = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'GetCurrent'
                {
                    $script:CurrentUserProfile
                }
                Default
                {
                    $PotentialUserProfiles = GetPotentialUserProfiles -path $Path
                    $FoundUserProfiles = @($PotentialUserProfiles | Where-Object {$_.ProfileType -eq $ProfileType})
                    if ($FoundUserProfiles.Count -ge 1)
                    {
                        switch ($PSCmdlet.ParameterSetName)
                        {
                            'All'
                            {
                                $FoundUserProfiles
                            }
                            'Identity'
                            {
                                foreach ($i in $Identity)
                                {
                                    $FoundUserProfiles | Where-Object -FilterScript {$_.Identity -eq $i -or $_.Name -eq $i}
                                }
                            }
                            'OrgProfileIdentity'
                            {
                                $FoundUserProfiles | Where-Object -FilterScript {$_.organization.identity -eq $OrgProfileIdentity -or $_.organization.Name -eq $OrgProfileIdentity}
                            }
                        }#end Switch
                    }#end if
                }#end Default
            }#end Switch
        )#end outputprofiles
        #output the found profiles
        $outputprofiles
        foreach ($opp in $outputprofiles)
        {
            if ($opp.ProfileTypeVersion -lt $script:UserProfileTypeLatestVersion)
            {
                Write-Warning -Message "The Schema of User Profile $($opp.Name) is out of date. Run Update-OneShellUserProfileTypeVersion -Identity $($opp.Name) to update."
            }
        }
    }#end End
}
#end function Get-OneShellUserProfile
function New-OneShellUserProfile
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [string]$OrgProfileIdentity
        ,
        [Parameter(Mandatory)]
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
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$OrgProfilePath = $Script:OneShellOrgProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$Path = $Script:OneShellUserProfilePath
    )
    End
    {
        $GetOrgProfileParams = @{
            ErrorAction = 'Stop'
            Identity    = $OrgProfileIdentity
            Path        = $OrgProfilePath
        }
        $targetOrgProfile = @(Get-OneShellOrgProfile @GetOrgProfileParams)
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
        $UserProfile = NewGenericUserProfileObject -TargetOrgProfile $targetOrgProfile
        $Systems = @(GetOrgProfileSystemForUserProfile -OrgProfile $TargetOrgProfile)
        $UserProfile.Systems = $Systems
        foreach ($p in $PSBoundParameters.GetEnumerator())
        {
            if ($p.key -in 'ProfileFolder', 'Name', 'MailFromSMTPAddress', 'Credentials', 'Systems')
            {
                if ($p.key -eq 'ProfileFolder')
                {
                    if ($p.value -like '*\' -or $p.value -like '*/')
                    {$ProfileFolder = join-path (split-path -path $p.value -Parent) (split-path -Path $p.value -Leaf)}
                    if (-not (Test-Path -PathType Container -Path $ProfileFolder))
                    {
                        Write-Warning -Message "The specified Profile Folder $ProfileFolder does not exist.  Attempting to Create it."
                        [void](New-Item -Path $ProfileFolder -ItemType Directory)
                    }
                }
                $UserProfile.$($p.key) = $p.value
            }
        }#end foreach
        Export-OneShellUserProfile -profile $UserProfile -path $path -errorAction 'Stop'
    }#end End
}
#end function New-OneShellUserProfile
Function Export-OneShellUserProfile
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        $profile
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        $path = $script:OneShellUserProfilePath
    )
    if ($profile.Identity -is 'GUID')
    {$name = $($profile.Identity.Guid) + '.json'}
    else
    {$name = $($profile.Identity) + '.json'}
    $fullpath = Join-Path -Path $path -ChildPath $name
    $ConvertToJsonParams = @{
        InputObject = $profile
        ErrorAction = 'Stop'
        Depth       = 6
    }
    try
    {
        ConvertTo-Json @ConvertToJsonParams | Out-File -FilePath $fullpath -Encoding ascii -ErrorAction Stop -Force
    }#try
    catch
    {
        $_
        throw "FAILED: Could not write User Profile data to $path"
    }#catch
}
#end function Export-OneShellUserProfile
Function Use-OneShellUserProfile
{
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 1, Mandatory)]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'Object', ValueFromPipeline = $true, Position = 1, Mandatory)]
        $UserProfile
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
        ,
        [switch]$NoAutoConnect
        ,
        [switch]$NoAutoImport
    )
    begin
    {
        $PotentialUserProfiles = GetPotentialUserProfiles -path $Path
    }
    process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'Object'
            {
                #validate that this is a user profile object . . .
            }
            'Identity'
            {
                if ($null -eq $Identity)
                {
                    $UserProfile = Select-Profile -Profiles $PotentialUserProfiles -Operation Use
                }
                else
                {
                    $GetUserProfileParams = @{
                        Identity    = $Identity
                        ErrorAction = 'Stop'
                        Path        = $path
                    }
                    $UserProfile = $(Get-OneShellUserProfile @GetUserProfileParams)
                }
            }
        }
        #Check User Profile Version
        #$RequiredVersion = 1.3
        #if (! $UserProfile.ProfileTypeVersion -ge $RequiredVersion)
        #{
        #    throw("The selected User Profile $($UserProfile.Name) is an older version. Please Run Set-OneShellUserProfile -Identity $($UserProfile.Identity) or Update-OneShellUserProfileTypeVersion -Identity $($UserProfile.Identity) to update it to version $RequiredVersion.")
        #}
        #Get and use the related Org Profile
        $UseOrgProfileParams = @{
            ErrorAction = 'Stop'
            Path        = $OrgProfilePath
            Identity    = $UserProfile.Organization.Identity
        }
        $OrgProfile = Get-OneShellOrgProfile @UseOrgProfileParams
        Use-OneShellOrgProfile -profile $OrgProfile
        #need to add some clean-up functionality for sessions when there is a change, or make it always optional to reset all sessions with this function
        $script:CurrentUserProfile = $UserProfile
        Write-Verbose -Message "User Profile has been set to $($script:CurrentUserProfile.Identity), $($script:CurrentUserProfile.name)."
        #Build the 'live' systems for use by connect-* functions
        #Retrieve the systems from the current org profile
        $OrgSystems = $OrgProfile.systems
        $UserSystems = $UserProfile.systems
        $JoinedSystems = join-object -Left $OrgSystems -Right $UserSystems -LeftJoinProperty Identity -RightJoinProperty Identity
        #Write-Verbose -Message $("Members of Joined Systems: " + $($JoinedSystems | get-member -MemberType Properties | Select-Object -ExpandProperty Name) -join ',')
        #Write-Verbose -Message $("Members of Joined Systems Credentials: " + $($JoinedSystems.credentials | get-member -MemberType Properties | Select-Object -ExpandProperty Name) -join ',')
        $Script:CurrentSystems =
        @(
            foreach ($js in $JoinedSystems)
            {
                foreach ($p in @('PSSession', 'Service'))
                {
                    $PreCredential = @($UserProfile.credentials | Where-Object -FilterScript {$_.Identity -eq $js.Credentials.$p})
                    switch ($PreCredential.count)
                    {
                        1
                        {
                            $SSPassword = $PreCredential[0].password | ConvertTo-SecureString
                            $Credential = New-Object System.Management.Automation.PSCredential($PreCredential[0].Username, $SSPassword)
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
                $js
            }
        )
        #set folder paths
        $script:OneShellUserProfileFolder = $script:CurrentUserProfile.ProfileFolder
        #Log Folder and Log Paths
        if ([string]::IsNullOrEmpty($script:CurrentUserProfile.LogFolder))
        {
            $Script:LogFolderPath = "$script:OneShellUserProfileFolder\Logs"
        }
        else
        {
            $Script:LogFolderPath = $script:CurrentUserProfile.LogFolder
        }
        if (-not (Test-path -PathType Container -Path $Script:LogFolderPath))
        {
            [void](New-Item -Path $Script:LogFolderPath -ItemType Directory -ErrorAction Stop)
        }
        $Script:LogPath = "$Script:LogFolderPath\$Script:Stamp" + '-Operations.log'
        $Script:ErrorLogPath = "$Script:LogFolderPath\$Script:Stamp" + '-Operations-Errors.log'
        #Input Files Path
        if ([string]::IsNullOrEmpty($script:CurrentUserProfile.InputFilesFolder))
        {
            $Script:InputFilesPath = "$script:OneShellUserProfileFolder\InputFiles\"
        }
        else
        {
            $Script:InputFilesPath = $script:CurrentUserProfile.InputFilesFolder + '\'
        }
        if (-not (Test-path -PathType Container -Path $Script:InputFilesPath))
        {
            [void](New-Item -Path $Script:InputFilesPath -ItemType Directory -ErrorAction Stop)
        }
        #Export Data Path
        if ([string]::IsNullOrEmpty($script:CurrentUserProfile.ExportDataFolder))
        {
            $Script:ExportDataPath = "$script:OneShellUserProfileFolder\Export\"
        }
        else
        {
            $Script:ExportDataPath = $script:CurrentUserProfile.ExportDataFolder + '\'
        }
        if (-not (Test-path -PathType Container -Path $Script:ExportDataPath))
        {
            [void](New-Item -Path $Script:ExportDataPath -ItemType Directory -ErrorAction Stop)
        }
    }#process
    end
    {
        if ($NoAutoConnect -ne $true)
        {
            $AutoConnectSystems = Get-OneShellSystem | Where-Object -FilterScript {$_.AutoConnect -eq $true}

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
#end function Use-OneShellUserProfile
function Set-OneShellUserProfile
{
    [cmdletbinding(DefaultParameterSetName = "Identity")]
    param
    (
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string[]]$Identity
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$ProfileFolder
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$LogFolder
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$ExportDataFolder
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$InputFilesFolder
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$Name
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-EmailAddress -EmailAddress $_})]
        $MailFromSMTPAddress
        ,
        [parameter()]
        [switch]$UpdateSystemsFromOrgProfile
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )
    Begin
    {
        $PotentialUserProfiles = GetPotentialUserProfiles -path $Path
    }
    Process
    {
        foreach ($i in $Identity)
        {
            $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $PotentialUserProfiles -Identity $i -Operation Edit
            $GetOrgProfileParams = @{
                ErrorAction = 'Stop'
                Path        = $orgProfilePath
                Identity    = $UserProfile.organization.identity
            }
            $targetOrgProfile = @(Get-OneShellOrgProfile @GetOrgProfileParams)
            #Check the Org Identity for validity (exists, not ambiguous)
            switch ($targetOrgProfile.Count)
            {
                1
                {}
                0
                {
                    $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $UserProfile.organization.identity -Message "No matching Organization Profile was found for identity $OrganizationIdentity"
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
                Default
                {
                    $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $UserProfile.organization.identity -Message "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            }
            #Update the User Profile Version if necessary
            $UserProfile = UpdateUserProfileObjectVersion -UserProfile $UserProfile
            #Update the profile itself
            if ($PSBoundParameters.ContainsKey('UpdateSystemsFromOrgProfile') -and $UpdateSystemsFromOrgProfile -eq $true)
            {
                $UpdateUserProfileSystemParams = @{
                    ErrorAction    = 'Stop'
                    ProfileObject  = $UserProfile
                    OrgProfilePath = $OrgProfilePath
                }
                Update-OneShellUserProfileSystem @UpdateUserProfileSystemParams
            }
            foreach ($p in $PSBoundParameters.GetEnumerator())
            {
                if ($p.key -in 'ProfileFolder', 'Name', 'MailFromSMTPAddress', 'LogFolder', 'ExportDataFolder', 'InputFilesFolder')
                {
                    if ($p.key -in 'ProfileFolder', 'LogFolder', 'ExportDataFolder', 'InputFilesFolder')
                    {
                        if ($p.value -like '*\' -or $p.value -like '*/')
                        {$ProfileFolder = join-path (split-path -path $p.value -Parent) (split-path -Path $p.value -Leaf)}
                        if (-not (Test-Path -PathType Container -Path $ProfileFolder))
                        {
                            Write-Warning -Message "The specified ProfileFolder $ProfileFolder does not exist.  Attempting to Create it."
                            [void](New-Item -Path $ProfileFolder -ItemType Directory)
                        }
                    }
                    $UserProfile.$($p.key) = $p.value
                }
            }#end foreach
            Export-OneShellUserProfile -profile $UserProfile -ErrorAction 'Stop'
        }#end foreach
    }#End Process
}
#end function Set-OneShellUserProfile
function Remove-OneShellUserProfile
{
    [cmdletbinding(DefaultParameterSetName = "Identity", SupportsShouldProcess)]
    param
    (
        [parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
    )
    Begin
    {
        $paProfiles = GetPotentialUserProfiles -path $Path
    }
    Process
    {
        foreach ($i in $Identity)
        {
            $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $paProfiles -Identity $i -Operation Edit
            $ProfilePath = Join-Path -Path $Path -ChildPath $($UserProfile.Identity + '.json')
            Remove-Item -Path $ProfilePath
        }#end foreach
    }#End Process
}
#end function Remove-OneShellUserProfile
Function Get-OneShellUserProfileSystem
{
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param
    (
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$ServiceType
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )#end param
    Process
    {
        $UserProfiles = @(
            $GetUserProfileParams = @{
                ErrorAction = 'Stop'
                Path        = $Path
            }
            if (Test-IsNotNullOrWhiteSpace -String $ProfileIdentity)
            {
                $GetUserProfileParams.Identity = $ProfileIdentity
            }
            Get-OneShellUserProfile @GetUserProfileParams
        )#end UserProfiles
        Write-Verbose -Message "Got $($UserProfiles.count) User Profiles"
        $OutputSystems = @(
            foreach ($up in $UserProfiles)
            {
                $orgProfile = Get-OneShellOrgProfile -Identity $up.organization.Identity -ErrorAction Stop -Path $OrgProfilePath
                foreach ($us in $up.systems)
                {
                    $os = $orgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $us.identity}
                    $us | Select-Object -Property *, @{n = 'ServiceType'; e = {$os.ServiceType}}, @{n = 'Name'; e = {$os.name}}, @{n = 'ProfileName'; e = {$up.Name}}, @{n = 'ProfileIdentity'; e = {$up.Identity}}, @{n = 'OrgName'; e = {$orgProfile.Name}}, @{n = 'OrgIdentity'; e = {$orgProfile.Identity}}
                }
            }
        )
        #filter based on Identity and Service Type
        $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.ServiceType -in $ServiceType -or (Test-IsNullorWhiteSpace -String $ServiceType)})
        $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.Identity -in $Identity -or $_.Name -in $Identity -or (Test-IsNullorWhiteSpace -String $Identity)})
        $OutputSystems
    }#end Process
}
#end function Get-OneShellUserProfileSystem
Function Set-OneShellUserProfileSystem
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline, Mandatory)]
        [string[]]$Identity
        ,
        [parameter()]
        [validateset($true, $false)]
        [bool]$AutoConnect
        ,
        [parameter()]
        [validateset($true, $false)]
        [bool]$AutoImport
        ,
        [parameter()]
        [validateset($true, $false)]
        [bool]$UsePSRemoting
        ,
        [parameter()]
        [ValidateScript( {($_.length -ge 2 -and $_.length -le 5) -or [string]::isnullorempty($_)})]
        [string]$PreferredPrefix
        ,
        [parameter()]
        [allowNull()]
        [string]$PreferredEndpoint
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )#end param
    Process
    {
        $UserProfile = @(Get-OneShellUserProfile -Identity $ProfileIdentity -Path $Path -OrgProfilePath $OrgProfilePath -ErrorAction Stop)
        if ($UserProfile.Count -ne 1)
        {throw("Ambiguous or not found User ProfileIdentity $ProfileIdentity was specified")}
        else
        {$UserProfile = $UserProfile[0]}
        foreach ($i in $Identity)
        {
            $System = @(Get-OneShellUserProfileSystem -ProfileIdentity $ProfileIdentity -Identity $i -Path $Path -OrgProfilePath $OrgProfilePath -ErrorAction Stop)
            if ($System.Count -ne 1)
            {throw("Ambiguous or not found System Identity $i was specified")}
            else
            {$System = $System[0]}
            #Edit the System
            switch ($PSBoundParameters.getenumerator())
            {
                {$_.key -eq 'AutoConnect'}
                {$System.AutoConnect = $AutoConnect}
                {$_.key -eq 'AutoImport'}
                {
                    if ($true -eq $AutoImport -and ($false -eq $system.UsePSRemoting -or $false -eq $UsePSRemoting))
                    {
                        Write-Warning -Message 'When UsePSRemoting is set to $false, AutoImport $true will be effective when connecting to a System.'
                    }
                    $System.AutoImport = $AutoImport
                }
                {$_.key -eq 'UsePSRemoting'}
                {
                    $System.UsePSRemoting = $UsePSRemoting
                    if ($false -eq $UsePSRemoting)
                    {
                        if ($true -eq $System.AutoImport)
                        {
                            Write-Warning -Message 'When UsePSRemoting is set to $False, AutoImport is also set to $False'
                            $AutoImport = $false
                            $System.AutoImport = $AutoImport
                        }
                    }
                }
                {$_.key -eq 'PreferredPrefix'}
                {$System.PreferredPrefix = $PreferredPrefix}
                {$_.key -eq 'PreferredEndpoint'}
                {
                    $Endpoints = Get-OneShellOrgProfileSystemEndpoint -Identity $PreferredEndpoint -SystemIdentity $system.Identity -ProfileIdentity $UserProfile.Organization.Identity -Path $OrgProfilePath -ErrorAction 'Stop'
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
            $System = $System | Select-Object -Property $(GetUserProfileSystemPropertySet)
            #Save the system changes to the User Profile
            $UserProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $UserProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
            Export-OneShellUserProfile -profile $UserProfile -path $path -ErrorAction 'Stop'
        }
    }#end Process
}
#end function Set-OneShellUserProfileSystem
Function Set-OneShellUserProfileSystemCredential
{
    [cmdletbinding()]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline, Position = 2)]
        [string[]]$SystemIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, Position = 3)]
        [string]$Identity
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('All', 'PSSession', 'Service')]
        $Purpose = 'All'
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )#end param
    Begin
    {
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellUserProfilePath}
        $puProfiles = GetPotentialUserProfiles -path $Path;
        #Get/Select the Profile
        $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $puProfiles -Identity $ProfileIdentity -Operation Edit
        #Get/Select the System
        $Systems = Get-OneShellUserProfileSystem -ProfileIdentity $UserProfile.Identity -Path $Path -ErrorAction 'Stop'
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
            $Credentials = @(Get-OneShellUserProfileCredential -ProfileIdentity $UserProfile.Identity -ErrorAction 'Stop' -Path $path)
            $SelectedCredential = @(
                $Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                $Credentials | Where-Object -FilterScript {$_.Username -eq $Identity}
            )
            switch ($SelectedCredential.Count)
            {
                0 {throw("Matching credential for value $($Identity;$UserName) not found")}
                1 {}
                default {throw("Multiple credentials with value $($Identity;$UserName) found.")}
            }
            #If this is the first time a credential has been added we may need to add Properties/Attributes
            if ($null -eq $system.Credentials)
            {
                $system.Credentials = [PSCustomObject]@{PSSession = $null; Service = $null}
            }
            #Remove any existing credential with the same purpose (only one of each purpose is allowed at one time)
            if ($Purpose -eq 'All')
            {
                $system.Credentials.PSSession = $SelectedCredential.Identity
                $system.Credentials.Service = $SelectedCredential.Identity
            }
            else
            {
                $system.Credentials.$purpose = $SelectedCredential.Identity
            }
            $system = $system | Select-Object -Property $(GetUserProfileSystemPropertySet)
            #Save the system changes to the User Profile
            $UserProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $UserProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
            Export-OneShellUserProfile -profile $UserProfile -path $path -ErrorAction 'Stop'
        }
    }#end End
}
#end function Set-OneShellUserProfileSystemCredential
function Update-OneShellUserProfileTypeVersion
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $Identity
        ,
        $Path = $Script:OneShellUserProfilePath
    )
    End
    {
        $GetUserProfileParams = @{
            Identity    = $Identity
            errorAction = 'Stop'
        }
        if ($PSBoundParameters.ContainsKey('Path'))
        {
            $GetUserProfileParams.Path = $Path
        }
        $UserProfile = Get-OneShellUserProfile @GetUserProfileParams
        $UpdatedUserProfile = UpdateUserProfileObjectVersion -UserProfile $UserProfile
        Export-OneShellUserProfile -profile $UpdatedUserProfile -path $Path
    }
}
#end function Update-OneShellUserProfileTypeVersion
function Update-OneShellUserProfileSystem
{
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [Parameter(Mandatory,ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [Parameter(ParameterSetName = 'Object', ValueFromPipeline, Mandatory)]
        [ValidateScript( {$_.ProfileType -eq 'OneShellUserProfile'})]
        [psobject[]]$ProfileObject
        ,
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )
    Process
    {
        $IncomingObjects = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'Object'
                {
                    $ProfileObject
                }
                'Identity'
                {
                    $Identity
                }
            }
        )
        foreach ($io in $IncomingObjects)
        {
            switch ($PSCmdlet.ParameterSetName)
            {
                'Object'
                {
                    #validate the object
                    $UserProfile = $io
                }
                'Identity'
                {
                    $GetUserProfileParams = @{
                        ErrorAction = 'Stop'
                        Identity    = $io
                        Path        = $Path
                    }
                    $UserProfile = $(Get-OneShellUserProfile @GetUserProfileParams)
                }
            }#end switch ParameterSetName
            $GetOrgProfileParams = @{
                ErrorAction = 'Stop'
                Path        = $orgProfilePath
                Identity    = $UserProfile.organization.identity
            }
            $targetOrgProfile = @(Get-OneShellOrgProfile @GetOrgProfileParams)
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
            $OrgProfileSystems = @(GetOrgProfileSystemForUserProfile -OrgProfile $TargetOrgProfile)
            $UserProfileSystems = @($UserProfile.Systems)
            #Remove those that are no longer in the Org Profile
            $UserProfileSystems = @($UserProfileSystems | Where-Object {$_.Identity -in $OrgProfileSystems.Identity})
            #Add those that are new to the Org Profile
            $NewOrgProfileSystems = @($OrgProfileSystems | Where-Object {$_.Identity -notin $UserProfileSystems.Identity})
            $NewUserProfileSystems = @($UserProfileSystems; $NewOrgProfileSystems)
            $UserProfile.Systems = $NewUserProfileSystems
            Export-OneShellUserProfile -profile $UserProfile -ErrorAction 'Stop'
        }#Foreach
    }#Process
}
#end function Update-OneShellUserProfileSystem
function New-OneShellUserProfileCredential
{
    [cmdletbinding()]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Username
        ,
        [parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [securestring]$Password
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
    )#end param
    End
    {
        #Get/Select the Profile
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellUserProfilePath}
        $puProfiles = GetPotentialUserProfiles -path $Path
        $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $puProfiles -Identity $ProfileIdentity -Operation Edit
        $NewCredential = $(
            switch ($PSBoundParameters.ContainsKey('Username'))
            {
                $true
                {
                    switch ($PSBoundParameters.ContainsKey('Password'))
                    {
                        $true
                        {
                            New-Object System.Management.Automation.PSCredential ($Username, $Password)
                        }
                        $false
                        {
                            $host.ui.PromptForCredential('New Credential', 'Specify the Password for the credential', $Username, '')
                        }
                    }
                }
                $false
                {
                    $host.ui.PromptForCredential('New Credential', 'Specify the Username and Password for the credential', '', '')
                }
            }
        )
        if ($NewCredential -is [PSCredential])
        {
            $UserProfileCredential = Convert-CredentialToUserProfileCredential -credential $NewCredential
            $UserProfile.Credentials += $UserProfileCredential
            $exportUserProfileParams = @{
                profile     = $UserProfile
                path        = $Path
                ErrorAction = 'Stop'
            }
            Export-OneShellUserProfile @exportUserProfileParams
        }
    }
}
#end function New-OneShellUserProfileCredential
function Remove-OneShellUserProfileCredential
{
    [cmdletbinding(DefaultParameterSetName = 'Select')]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ParameterSetName = 'Identity', Position = 2)]
        [string]$Identity
        ,
        [parameter(Mandatory, ParameterSetName = 'UserName', Position = 2)]
        [string]$Username
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
    )#end param
    End
    {
        #Get/Select the Profile
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellUserProfilePath}
        $puProfiles = GetPotentialUserProfiles -path $Path
        $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $puProfiles -Identity $ProfileIdentity -Operation Edit
        if ($UserProfile.Credentials.Count -eq 0) {throw('There are no credentials to remove')}
        $SelectedCredential = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'Select'
                {
                    Select-OneShellUserProfileCredential -Credential $UserProfile.Credentials -Operation Remove
                }
                'UserName'
                {
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $UserName}
                }
                'Identity'
                {
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $Identity}
                }
            }
        )
        switch ($SelectedCredential.Count)
        {
            0 {throw("Matching credential for value $($Identity;$UserName) not found")}
            1 {}
            default {throw("Multiple credentials with value $($Identity;$UserName) found.")}
        }
        $UserProfile.Credentials = @($UserProfile.Credentials | Where-Object -FilterScript {$_ -ne $SelectedCredential[0]})
        $exportUserProfileParams = @{
            profile     = $UserProfile
            path        = $Path
            ErrorAction = 'Stop'
        }
        Export-OneShellUserProfile @exportUserProfileParams
        #NeededCode:  Remove references to the removed credential from user profile Systems
    }
}
#end function Remove-OneShellUserProfileCredential
function Set-OneShellUserProfileCredential
{
    [cmdletbinding(DefaultParameterSetName = 'Select')]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [parameter(ParameterSetName = 'Identity', Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'UserName', Position = 2)]
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
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
    )#end param
    End
    {
        #Get/Select the Profile
        if ($null -eq $Path -or [string]::IsNullOrEmpty($Path)) {$path = $Script:OneShellUserProfilePath}
        $puProfiles = GetPotentialUserProfiles -path $Path
        $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $puProfiles -Identity $ProfileIdentity -Operation Edit
        if ($UserProfile.Credentials.Count -eq 0) {throw('There are no credentials to set')}
        $SelectedCredential = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'Select'
                {
                    Select-OneShellUserProfileCredential -Credential $UserProfile.Credentials -Operation Edit
                }
                'Identity'
                {
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Identity -eq $Identity}
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $Identity}
                }
                'Username'
                {
                    $UserProfile.Credentials | Where-Object -FilterScript {$_.Username -eq $UserName}
                }
            }
        )
        switch ($SelectedCredential.Count)
        {
            0 {throw("Matching credential for value $($Identity;$UserName) not found")}
            1 {}
            default {throw("Multiple credentials with value $($Identity;$UserName) found.")}
        }
        $EditedCredential = $(
            switch ($SelectedCredential)
            {
                #Both Username and Password Specified - Update Both
                {$PSBoundParameters.ContainsKey('NewUsername') -and $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($NewUsername, $NewPassword)
                }
                #Only Username Specified - Update Username, Preserve Password
                {$PSBoundParameters.ContainsKey('NewUsername') -and -not $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($NewUsername, $($SelectedCredential.Password | ConvertTo-SecureString))
                }
                #Only Password Specified - Update Password, Preserve Username
                {-not $PSBoundParameters.ContainsKey('NewUsername') -and $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    New-Object System.Management.Automation.PSCredential ($SelectedCredential.Username, $NewPassword)
                }
                #nothing Specified except Identity - suggest preserving username, prompt to update password
                {-not $PSBoundParameters.ContainsKey('NewUsername') -and -not $PSBoundParameters.ContainsKey('NewPassword')}
                {
                    $host.ui.PromptForCredential('Set Credential', 'Specify the Password for the credential', $SelectedCredential.Username, '')
                }
            }
        )
        if ($null -ne $EditedCredential)
        {
            $UserProfileCredential = Convert-CredentialToUserProfileCredential -credential $EditedCredential -Identity $SelectedCredential.Identity
            $Index = Get-ArrayIndexForValue -array $UserProfile.Credentials -value $SelectedCredential.Identity -property Identity -ErrorAction Stop
            $UserProfile.Credentials[$Index] = $UserProfileCredential
            $exportUserProfileParams = @{
                profile     = $UserProfile
                path        = $Path
                ErrorAction = 'Stop'
            }
            Export-OneShellUserProfile @exportUserProfileParams
        }
    }
}
#end function Set-OneShellUserProfileCredential
function Get-OneShellUserProfileCredential
{
    [cmdletbinding()]
    param
    (
        [parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileIdentity
        ,
        [parameter(Position = 2)]
        [string]$Identity #Credential Identity or UserName
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath

    )#end param
    End
    {
        $getUserProfileParams = @{
            ErrorAction = 'Stop'
            Path        = $Path
        }
        if (-not [string]::IsNullOrEmpty($ProfileIdentity))
        {$getUserProfileParams.Identity = $ProfileIdentity}
        $UserProfile = @(Get-OneShellUserProfile @getUserProfileParams)
        $OutputCredentials = @(
            foreach ($ap in $UserProfile)
            {
                $ProfileName = $ap.Name
                $ProfileIdentity = $ap.Identity
                $ap.Credentials | Select-Object -Property *, @{n = 'UserProfileName'; e = {$ProfileName}}, @{n = 'UserProfileIdentity'; e = {$ProfileIdentity}}
            }
        )
        if (-not [string]::IsNullOrEmpty($Identity))
        {$OutputCredentials = $OutputCredentials | Where-Object -FilterScript {$_.Identity -eq $Identity -or $_.Username -eq $Identity}}
        $OutputCredentials
    }
}
#end function Get-OneShellUserProfileCredential
function Convert-CredentialToUserProfileCredential
{
    [cmdletbinding()]
    param
    (
        [pscredential]$credential
        ,
        [string]$Identity
    )
    if ($null -eq $Identity -or [string]::IsNullOrWhiteSpace($Identity))
    {$Identity = $(New-OneShellGuid).guid}
    $credential | Add-Member -MemberType NoteProperty -Name 'Identity' -Value $Identity
    $credential | Select-Object -Property @{n = 'Identity'; e = {$_.Identity}}, @{n = 'UserName'; e = {$_.UserName}}, @{n = 'Password'; e = {$_.Password | ConvertFrom-SecureString}}
}
#end function Convert-CredentialToUserProfileCredential
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
        [ValidateSet('Remove', 'Edit', 'Get')]
        [string]$Operation
    )
    $message = "Select system to $Operation"
    $CredChoices = @(foreach ($s in $Systems) {"$($s.servicetype):$($s.name):$($s.Identity)"})
    #$whichone = Read-Choice -Message $message -Choices $CredChoices -DefaultChoice 0 -Title $message -Numbered -Vertical
    $whichone = Read-PromptForChoice -Message $message -Choices $CredChoices -DefaultChoice 0 -Numbered
    $systems[$whichone]
}
#end function Select-ProfileSystem
function Select-OneShellOrgProfileSystemEndpoint
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $Endpoints
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Associate')]
        [string]$Operation
    )
    $message = "Select endpoint to $Operation"
    $Choices = @(foreach ($i in $Endpoints) {"$($i.ServiceType):$($i.address):$($i.Identity)"})
    #$whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
    $whichone = Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered
    $Endpoints[$whichone]
}
#end function Select-OneShellOrgProfileSystemEndpoint
function Select-OneShellUserProfileCredential
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [psobject[]]$Credential
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Associate')]
        [string]$Operation
    )
    $message = "Select credential to $Operation"
    $Choices = @(foreach ($i in $Credential) {"$($i.username):$($i.Identity)"})
    #$whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
    $whichone = Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered
    $Credential[$whichone]
}
#end function Select-OneShellUserProfileCredential
function Select-Profile
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [pscustomobject[]]$Profiles
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Associate', 'Get', 'Use')]
        [string]$Operation
    )
    $message = "Select profile to $Operation"
    $Choices = @(foreach ($i in $Profiles) {"$($i.name):$($i.Identity)"})
    #$whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
    $whichone = Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered
    $Profiles[$whichone]
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
        [validateSet('AllUsers', 'CurrentUser')]
        [string]$OrgProfileDirectoryScope
        ,
        [parameter()]
        [switch]$DoNotPersist #By Default, this function tries to persist the OrgProfileDirectory to the DefaultPath by writing a JSON file with the setting to that location.  This switch overrides that behavior.
    )
    switch ($OrgProfileDirectoryScope)
    {
        'AllUsers'
        {
            $DefaultPath = $("$env:ALLUSERSPROFILE\OneShell")
            if ($Path -ne $DefaultPath)
            {
                $message = "The recommended/default location for AllUsers OneShell Org Profile storage is $DefaultPath."
                Write-Verbose -Message $message -Verbose
            }
            if (-not $PSBoundParameters.ContainsKey('Path'))
            {
                $Path = $DefaultPath
            }
        }
        'CurrentUser'
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
            [void](New-Item -Path $Path -ItemType Directory -ErrorAction Stop)
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
    $Script:OneShellOrgProfilePath = $Path

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
        $Script:OneShellOrgProfilePath = $(Import-Json -Path $UserFilePath).OrgProfilePath
    }
    else
    {
        if (Test-Path -Path $SystemFilePath -PathType Leaf)
        {
            $Script:OneShellOrgProfilePath = $(Import-Json -Path $SystemFilePath).OrgProfilePath
        }
    }
    if ([string]::IsNullOrWhiteSpace($Script:OneShellOrgProfilePath))
    {
        $message = 'You must run Set-OneShellOrgProfileDirectory. No persisted OneShell Org Profile directories found.'
        Write-Warning -Message $message
    }
}
#end function GetOneShellOrgProfileDirectory
function Set-OneShellUserProfileDirectory
{
    [cmdletbinding()]
    param
    (
        [parameter()]
        [string]$Path #If not specified the Path will default to the DefaultPath of $env:LocalAppData\OneShell
        ,
        [parameter()]
        [switch]$DoNotPersist #By Default, this function tries to persist the UserProfileDirectory to the DefaultPath by writing a JSON file with the setting to that location.  This switch overrides that behavior.
    )
    $DefaultPath = $("$env:LocalAppData\OneShell")
    if ($Path -ne $DefaultPath)
    {
        $message = "The recommended/default location for User specific OneShell User Profile storage is $DefaultPath."
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
            [void](New-Item -Path $Path -ItemType Directory -ErrorAction Stop)
        }
        catch
        {
            throw($_)
        }
    }
    if (-not (Test-IsWriteableDirectory -path $path))
    {
        $message = "The specified path exists but does not appear to be writeable. Without elevating or using a different credential this user may be able to use existing OneShell User Profiles in this location but may not be able to edit them."
        Write-Warning -Message $message
    }
    $Script:OneShellUserProfilePath = $Path

    if (-not $PSBoundParameters.ContainsKey('DoNotPersist'))
    {
        if (-not (Test-Path -Path $DefaultPath -PathType Container))
        {
            Write-Verbose -Message "Creating Directory $DefaultPath" -Verbose
            try
            {
                [void](New-Item -Path $DefaultPath -ItemType Directory -ErrorAction Stop)
            }
            catch
            {
                throw($_)
            }
        }
        $PersistObject = [PSCustomObject]@{
            UserProfilePath = $Path
        }
        $PersistFileName = 'OneShellUserSettings.json'
        $PersistFilePath = Join-Path -Path $DefaultPath -ChildPath $PersistFileName
        if ((Test-IsWriteableDirectory -path $DefaultPath))
        {
            $PersistObject | ConvertTo-Json | Out-File -Encoding utf8 -FilePath $PersistFilePath
        }
        else
        {
            $message = "Unable to write file $PersistFilePath. You may have to use Set-OneShellUserProfileDirectory with subsequent uses of the OneShell module."
            Write-Warning -Message $message
        }
    }
}
#end function Set-OneShellUserProfileDirectory
function GetOneShellUserProfileDirectory
{
    [CmdletBinding()]
    param
    ()
    $UserDirectory = $("$env:LocalAppData\OneShell")
    $PersistFileName = 'OneShellUserSettings.json'
    $UserFilePath = Join-Path -Path $UserDirectory -ChildPath $PersistFileName
    if (Test-Path -Path $UserFilePath -PathType Leaf)
    {
        $Script:OneShellUserProfilePath = $(Import-Json -Path $UserFilePath).UserProfilePath
    }
    if ([string]::IsNullOrWhiteSpace($Script:OneShellUserProfilePath))
    {
        $message = 'You must run Set-OneShellUserProfileDirectory. No persisted OneShell User Profile directories found.'
        Write-Warning -Message $message
    }
}
#end function GetOneShellOrgProfileDirectory
#################################################
# Need to add
#################################################
