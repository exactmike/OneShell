##########################################################################################################
#Remote System Connection Functions
##########################################################################################################
function Find-EndPointToUse
    {
        [cmdletbinding()]
        param
        (
            [parameter()]
            [AllowNull()]
            $EndPointIdentity
            ,
            $ServiceObject
        )
        if ($null -eq $EndPointIdentity)
        {
            if ($null -eq $ServiceObject.PreferredEndpoint)
            {
                $ServiceObject.EndPoints | Where-Object -FilterScript {$_.isDefault -eq $true} | Select-Object -First 1
            }
            else
            {
                $ServiceObject.EndPoints | Where-Object -FilterScript {$_.Identity -eq $ServiceObject.PreferredEndpoint}
            }
        }
        else
        {
            if ($EndPointIdentity -notin $ServiceObject.EndPoints.Identity)
            {throw("Invalid EndPoint Identity $EndPointIdentity was specified. System $($ServiceObject.Identity) has no such endpoint.")}
            else
            {
                $ServiceObject.EndPoints | Where-Object -FilterScript {$_.Identity -eq $EndPointIdentity}
            }
        }
    }
#end function Find-EndPointToUse
function Find-ExchangeOnlineEndpointToUse
    {
        [cmdletbinding()]
        param
        (
            $ServiceObject
        )
        [PSCustomObject]@{
            Identity = (New-Guid).guid
            AddressType = 'URL'
            Address = 'https://outlook.office365.com/powershell-liveid/'
            ServicePort = $null
            IsDefault = $true
            UseTLS = $false
            ProxyEnabled = $ServiceObject.Defaults.ProxyEnabled
            CommandPrefix = $ServiceObject.Defaults.CommandPrefix
            AuthenticationRequired = $true
            AuthMethod = 'Basic'
            EndPointGroup = $null
            EndPointType = 'Admin'
            ServiceTypeAttributes = $null
            ServiceType = 'ExchangeOrganization'
            AllowRedirection = $true
        }
    }
#end function Find-ExchangeOnlineEndpointToUse
function Find-ComplianceCenterEndpointToUse
    {
        [cmdletbinding()]
        param
        (
            $ServiceObject
        )
        [PSCustomObject]@{
            Identity = (New-Guid).guid
            AddressType = 'URL'
            Address = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
            ServicePort = $null
            IsDefault = $true
            UseTLS = $false
            ProxyEnabled = $ServiceObject.Defaults.ProxyEnabled
            CommandPrefix = $ServiceObject.Defaults.CommandPrefix
            AuthenticationRequired = $true
            AuthMethod = 'Basic'
            EndPointGroup = $null
            EndPointType = 'Admin'
            ServiceTypeAttributes = $null
            ServiceType = 'ExchangeOrganization'
            AllowRedirection = $true
        }
    }
#end function Find-ComplianceCenterEndpointToUse
function Get-OneShellAvailableSystem
    {
        [cmdletbinding()]
        param
        (
        )
        DynamicParam
        {
            $dictionary = New-DynamicParameter -name ServiceType -ValidateSet $(getorgservicetypes) -Type $([string[]]) -Mandatory $false
            Write-Output -InputObject $dictionary
        }
        end
        {
            Set-DynamicParameterVariable -dictionary $dictionary
            if ($null -eq $script:CurrentOrgProfile)
            {throw('No OneShell Organization profile is active.  Use function Use-OrgProfile to load an organization profile.')}
            if ($null -eq $script:CurrentAdminUserProfile)
            {throw('No OneShell Admin user profile is active.  Use function Use-AdminUserProfile to load an admin user profile.')}
            Write-Verbose -Message "ServiceType is set to $($serviceType -join ',')"
            (Get-OneShellVariableValue -Name CurrentSystems -ErrorAction Stop).GetEnumerator() |
            Where-object -FilterScript {$null -eq $ServiceType -or $_.ServiceType -in $ServiceType}
        }
    }
#end function Get-OneShellAvailableSystem
function New-ExchangeOrganizationDynamicParameter
    {
        [cmdletbinding()]
        param
        (
            [switch]$Mandatory
            ,
            [int]$Position
            ,
            [string]$ParameterSetName
            ,
            [switch]$Multivalued
        )
        $NewDynamicParameterParams=@{
            Name = 'ExchangeOrganization'
            ValidateSet = @(Get-OneShellAvailableSystem -ServiceType ExchangeOrganization | Select-Object -ExpandProperty Name)
            Alias = @('Org','ExchangeOrg')
        }
        if ($PSBoundParameters.ContainsKey('Mandatory'))
        {
            $NewDynamicParameterParams.Mandatory = $true
        }
        if ($PSBoundParameters.ContainsKey('Multivalued'))
        {
            $NewDynamicParameterParams.Type = [string[]]
        }
        if ($PSBoundParameters.ContainsKey('Position'))
        {
            $NewDynamicParameterParams.Position = $Position
        }
        if ($PSBoundParameters.ContainsKey('ParameterSetName'))
        {
            $NewDynamicParameterParams.ParameterSetName = $ParameterSetName
        }
        New-DynamicParameter @NewDynamicParameterParams
    }
#end function New-ExchangeOrganizationDynamicParameter
Function Connect-Exchange
{
    [cmdletbinding()]
    Param
    (
        [parameter()]
        [ValidateNotNullOrEmpty()]
        $EndPointIdentity #An endpoint identity from existing endpoints configure for this system. Overrides the otherwise specified endpoint.
        ,
        [parameter()]
        [ValidateScript({($_.length -ge 2 -and $_.length -le 5) -or [string]::isnullorempty($_)})]
        [string]$CommandPrefix #Overrides the otherwise specified command prefix.
    )
    DynamicParam
    {
        $Dictionary = New-ExchangeOrganizationDynamicParameter -Mandatory $true
        Write-Output -InputObject $dictionary
    }#DynamicParam
    end
    {
        Set-DynamicParameterVariable -dictionary $Dictionary
        $ServiceObject = Get-OneShellAvailableSystem -ServiceType ExchangeOrganization | Where-Object -FilterScript {$_.name -eq $ExchangeOrganization}
        Write-Verbose -Message "Selecting an Endpoint"
        $EndPoint = $(
            switch ($ServiceObject.ServiceTypeAttributes.ExchangeOrgType)
            {
                'OnPremises'
                {
                    Find-EndPointToUse -EndPointIdentity $EndPointIdentity -ServiceObject $ServiceObject -ErrorAction Stop
                }
                'Online'
                {
                    Find-ExchangeOnlineEndpointToUse -ServiceObject $ServiceObject -ErrorAction Stop
                }
                'ComplianceCenter'
                {
                    Find-ComplianceCenterEndpointToUse -ServiceObject $ServiceObject -ErrorAction Stop
                }
            }
        )
        #Test for an existing connection
            #if the connection is opened, test for functionality
            #if not remove
            #if functional leave as is
            #if not remove
        #
        
    }#end End
}#function Connect-Exchange
Function Import-RequiredModule
{
  [cmdletbinding()]
  param
  (
    [parameter(Mandatory=$true)]
    [ValidateSet('ActiveDirectory','AzureAD','MSOnline','AADRM','LyncOnlineConnector','POSH_ADO_SQLServer','MigrationPowershell','BitTitanPowerShell')]
    [string]$ModuleName
  )
  #Do any custom environment preparation per specific module
  switch ($ModuleName)
  {
    'ActiveDirectory'
    {
        #Suppress Creation of the Default AD Drive with current credentials
        $Env:ADPS_LoadDefaultDrive = 0
    }
    Default 
    {
    }
  }
  #Test if the module required is already loaded:
  $ModuleLoaded = @(Get-Module | Where-Object Name -eq $ModuleName)
  if ($ModuleLoaded.count -eq 0) 
  {
    try 
    {
        $message = "Import the $ModuleName Module"
        Write-Log -message $message -EntryType Attempting
        Import-Module -Name $ModuleName -Global -ErrorAction Stop
        Write-Log -message $message -EntryType Succeeded
        Write-Output -InputObject $true
    }#try
    catch 
    {
        $myerror = $_
        Write-Log -message $message -Verbose -ErrorLog -EntryType Failed 
        Write-Log -message $myerror.tostring() -ErrorLog
        Write-Output -InputObject $false
        $PSCmdlet.ThrowTerminatingError($myerror)
    }#catch
  } else 
  {
    Write-Log -EntryType Notification -Message "$ModuleName Module is already loaded."
    Write-Output -InputObject $true
  }
}# Function Import-RequiredModule

Function Connect-Skype {
    [cmdletbinding(DefaultParameterSetName = 'Organization')]
    Param(
        [parameter(ParameterSetName='OnPremises')]
        [string]$Server
        ,
        [parameter(ParameterSetName='OnPremises')]
        [ValidateSet('Basic','Kerberos','Negotiate','Default','CredSSP','Digest','NegotiateWithImplicitCredential')]
        [string]$AuthMethod
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        $Credential
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [string]$CommandPrefix
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [string]$SessionNamePrefix
        ,
        [parameter(ParameterSetName='Online')]
        [switch]$online
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [bool]$ProxyEnabled = $False
        ,
        [parameter(ParameterSetName='OnPremises')]
        [string[]]$PreferredDomainControllers
        <#    ,
            [parameter(ParameterSetName='Organization')]
        [switch]$Profile#>
    )
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'SkypeOrganization'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SkypeOrganizations' | Select-Object -ExpandProperty Name)
            Alias = @('Org','SkypeOrg')
            Position = 2
            ParameterSetName = 'Organization'
        }
        New-DynamicParameter @NewDynamicParameterParams
    }#DynamicParam
    Begin {
        switch ($PSCmdlet.ParameterSetName) {
            'Organization' {
                $Org = $PSBoundParameters['SkypeOrganization']
                $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'SkypeOrganizations' | Where-Object {$_.name -eq $org}
                $orgtype = $orgobj.orgtype
                $credential = $orgobj.credential
                $orgName = $orgobj.Name
                $CommandPrefix = $orgobj.CommandPrefix
                $Server =  $orgobj.Server
                $AuthMethod = $orgobj.authmethod
                $ProxyEnabled = $orgobj.ProxyEnabled
                $SessionName = $orgobj.Identity
                $PreferredDomainControllers = if (-not [string]::IsNullOrWhiteSpace($orgobj.PreferredDomainControllers)) {@($orgobj.PreferredDomainControllers)} else {$null}
            }
            'Online'{
                $orgtype = $PSCmdlet.ParameterSetName
                $SessionName = "$SessionNamePrefix-Skype"
                $orgName = $SessionNamePrefix
            }
            'OnPremises'{
                $orgtype = $PSCmdlet.ParameterSetName
                $SessionName = "$SessionNamePrefix-Skype"
                $orgName = $SessionNamePrefix
            }
        }
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
    }
    Process {
        try
        {
            $existingsession = Get-PSSession -Name $SessionName -ErrorAction Stop
            Write-Log -Message "Existing session for $SessionName exists"
            Write-Log -Message "Checking $SessionName State" 
            if ($existingsession.State -ne 'Opened')
            {
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'"
                Remove-PSSession -Name $SessionName 
                $UseExistingSession = $False
            }#if
            else
            {
                #Write-Log -Message "$SessionName State is 'Opened'. Using existing Session." 
                switch ($orgtype)
                {
                    'OnPremises'
                    {
                        try
                        {
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-SkypeCommand -cmdlet 'Get-CsTenantFederationConfiguration' -SkypeOrganization $orgName -string '-erroraction Stop' -WarningAction SilentlyContinue
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch
                        {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#OnPremises
                    'Online'
                    {
                        try
                        {
                            try
                            {Import-RequiredModule -ModuleName LyncOnlineConnector -ErrorAction Stop}
                            catch
                            {
                                Write-Log -Message 'Unable to load LyncOnlineConnector Module' -EntryType Failed -ErrorLog -Verbose
                                Write-Log -Message $_.tostring() -ErrorLog 
                                Write-Output -InputObject $false
                            }
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-SkypeCommand -cmdlet 'Get-CsTenantFederationConfiguration' -SkypeOrganization $orgName -string '-erroraction Stop'
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch
                        {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#Online
                }#switch $orgtype
            }#else
        }#try
        catch
        {
            Write-Log -Message "No existing session for $SessionName exists" 
            $UseExistingSession = $false
        }#catch
        switch ($UseExistingSession) {
            $true {Write-Output -InputObject $true}#$true
            $false {
                $sessionParams = @{
                    Credential = $Credential
                    Name = $SessionName
                }
                switch ($orgtype) {
                    'Online' {
                        <#If ($ProxyEnabled) {
                            $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                            Write-Log -message 'Using Proxy Configuration'
                        }
                        #>
                    }
                    'OnPremises' {
                        #add option for https + Basic Auth    
                        <#
                        $sessionParams.ConnectionURI = "http://" + $Server + "/PowerShell/"
                        $sessionParams.Authentication = $AuthMethod
                        if ($ProxyEnabled) {
                            $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                            Write-Log -message 'Using Proxy Configuration'
                        }
                        #>
                    }
                }
                try {
                    $message = "Creation of Remote Session $SessionName to Skype System $orgName"
                    Write-Log -Message $message -entryType Attempting
                    $sessionobj = New-cSonlineSession @sessionParams -ErrorAction Stop
                    Write-Log -Message $message -EntryType Succeeded
                    Write-Log -Message "Attempting: Import Skype Session $SessionName and Module" 
                    $ImportPSSessionParams = @{
                        AllowClobber = $true
                        DisableNameChecking = $true
                        ErrorAction = 'Stop'
                        Session = Get-PSSession -Name $SessionName
                    }
                    $ImportModuleParams = @{
                        DisableNameChecking = $true
                        ErrorAction = 'Stop'
                        Global = $true
                    }
                    if (-not [string]::IsNullOrWhiteSpace($CommandPrefix)) {
                        $ImportPSSessionParams.Prefix = $CommandPrefix
                        $ImportModuleParams.Prefix = $CommandPrefix
                    }
                    Import-Module (Import-PSSession @ImportPSSessionParams) @ImportModuleParams
                    Write-Log -Message "Succeeded: Import Skype Session $SessionName and Module" 
                    Write-Output -InputObject $true
                    Write-Log -Message "Succeeded: Connect to Skype System $orgName"
                }#try
                catch {
                    Write-Log -Message "Failed: Connect to Skype System $orgName" -Verbose -ErrorLog
                    Write-Log -Message $_.tostring() -ErrorLog
                    Write-Output -InputObject $False
                    $_
                }#catch
            }#$false
        }#switch
    }#process
}#function Connect-Skype
Function Connect-AADSync {
    [cmdletbinding(DefaultParameterSetName = 'Profile')]
    Param(
        [parameter(ParameterSetName='Manual',Mandatory=$true)]
        $Server
        ,[parameter(ParameterSetName='Manual',Mandatory=$true)]
        $Credential
        ,
        [Parameter(ParameterSetName='Manual',Mandatory)]
        [ValidateLength(1,3)]
        [string]$CommandPrefix
        ,
        [switch]$usePrefix
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'AADSyncServer'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AADSyncServers' | Select-Object -ExpandProperty Name)
            Alias = @('Org','SkypeOrg')
            Position = 2
            ParameterSetName = 'Profile'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    #Connect to Directory Synchronization
    #Server has to have been enabled for PS Remoting (enable-psremoting)
    #Credential has to be a member of ADSyncAdmins on the AADSync Server
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        switch ($PSCmdlet.ParameterSetName) {
            'Profile' {
                $SelectedProfile = $AADSyncServer
                $Profile = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'AADSyncServers' | Where-Object {$_.name -eq $selectedProfile}
                $CommandPrefix = $Profile.Name
                $SessionName = $Profile.Identity
                $Server = $Profile.Server
                $Credential = $Profile.Credential
            }#Profile
            'Manual' {
                $SessionName = "$CommandPrefix-AADync"
            }#manual
        }#switch
    }
    Process{
        try {
            $existingsession = Get-PSSession -Name $SessionName -ErrorAction Stop
            #Write-Log -Message "Existing session for $SessionName exists"
            #Write-Log -Message "Checking $SessionName State" 
            if ($existingsession.State -ne 'Opened') {
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'"
                Remove-PSSession -Name $SessionName 
                $UseExistingSession = $False
            }#if
            else {
                #Write-Log -Message "$SessionName State is 'Opened'. Using existing Session." 
                $UseExistingSession = $true
                Write-Output -InputObject $true
            }#else
        }#try
        catch {
            Write-Log -Message "No existing session for $SessionName exists" 
            $UseExistingSession = $false
        }#catch
        if ($UseExistingSession -eq $False) {
            Write-Log -Message "Connecting to Directory Synchronization Server $server as User $($credential.username)."
            Try {
                $Session = New-PsSession -ComputerName $Server -Credential $Credential -Name $SessionName -ErrorAction Stop
                Write-Log -Message "Attempting: Import AADSync Session $SessionName and Module" 
                if ($usePrefix) {
                    Invoke-Command -Session $Session -ScriptBlock {Import-Module -Name ADSync -DisableNameChecking} -ErrorAction Stop
                    Import-Module (Import-PSSession -Session $Session -Module ADSync -DisableNameChecking -ErrorAction Stop -Prefix $CommandPrefix) -Global -DisableNameChecking -ErrorAction Stop -Prefix $CommandPrefix
                }
                else {
                    Invoke-Command -Session $Session -ScriptBlock {Import-Module -Name ADSync -DisableNameChecking} -ErrorAction Stop
                    Import-Module (Import-PSSession -Session $Session -Module ADSync -DisableNameChecking -ErrorAction Stop) -Global -DisableNameChecking -ErrorAction Stop 
                }
                Write-Log -Message "Succeeded: Import AADSync Session $SessionName and Module" 
                if ((Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock {Get-Command -Module ADSync | Select-Object -ExpandProperty Name}) -contains 'Get-ADSyncScheduler') 
                {
                if ($usePrefix) {$functionstring = "Function Global:Start-$($CommandPrefix)DirectorySynchronization {"}
                else {$functionstring = 'Function Global:Start-DirectorySynchronization {'}
                $functionstring += 
                @"
    param([switch]`$full)
    Write-Warning -Message 'Start-DirectorySynchronization is deprecated. Please replace with Start-ADSyncSyncCycle.'
    if (`$full) {
        `$scriptblock = [ScriptBlock]::Create('Start-ADSyncSyncCycle -PolicyType Initial')
        Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock `$scriptblock | Write-Verbose -verbose
    }#if
    else {
        `$scriptblock = [ScriptBlock]::Create('Start-ADSyncSyncCycle -PolicyType Delta')
        Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock `$scriptblock | Write-Verbose -verbose
    }#else
}#Function Global:Start-DirectorySynchronization
"@
                }
                else 
                {
                if ($usePrefix) {$functionstring = "Function Global:Start-$($CommandPrefix)DirectorySynchronization {"}
                else {$functionstring = 'Function Global:Start-DirectorySynchronization {'}
                $functionstring += 
                @"
    param([switch]`$full)
    if (`$full) {
        `$scriptblock = [ScriptBlock]::Create('SCHTASKS /run /TN "Azure AD Sync Scheduler Full"')
        Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock `$scriptblock | Write-Verbose -verbose
    }#if
    else {
        `$scriptblock = [ScriptBlock]::Create('SCHTASKS /run /TN "Azure AD Sync Scheduler"')
        Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock `$scriptblock | Write-Verbose -verbose
    }#else
}#Function Global:Start-DirectorySynchronization
"@
                }
                $function = [scriptblock]::Create($functionstring)
                &$function
                Write-Output -InputObject $true
            }#Try
            Catch {
                Write-Log -Verbose -Message "ERROR: Connection to $server failed." -ErrorLog
                Write-Log -Verbose -Message $_.tostring() -ErrorLog
                Write-Output -InputObject $false
            }#catch
        }#if
    }#process 
}#Function Connect-AADSync
Function Connect-ADInstance {
    [cmdletbinding(DefaultParameterSetName = 'NamedInstance')]
    param(
        [parameter(Mandatory=$True,ParameterSetName='Manual')]
        [string]$Name
        ,
        [parameter(Mandatory = $true,ParameterSetName='Manual')]
        [string]$server
        ,
        [parameter(Mandatory = $true,ParameterSetName='Manual')]
        $Credential
        ,
        [parameter(Mandatory = $true,ParameterSetName='Manual')]
        [string]$description
        ,
        [parameter(Mandatory = $true,ParameterSetName='Manual')]
        [bool]$GlobalCatalog
        ,
        [parameter(Mandatory = $true,ParameterSetName='InstanceObject')]
        [psobject]$InstanceObject
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'ActiveDirectoryInstance'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Select-Object -ExpandProperty Name)
            Alias = @('AD','Instance')
            Position = 2
            ParameterSetName = 'NamedInstance'
        }
        $Dictionary  = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    Begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        #Process Reporting
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }#$ProcessStatus
        Switch ($PSCmdlet.ParameterSetName) {
            'NamedInstance'
            {
                $ADI = $ActiveDirectoryInstance
                $ADIobj = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Where-Object {$_.name -eq $ADI}
                $name = $ADIobj.Name
                $server = $ADIobj.Server
                $Credential = $ADIobj.credential
                $Description = "OneShell $($ADIobj.Identity): $($ADIobj.description)"
                $GlobalCatalog = $ADIobj.GlobalCatalog
            }#instance
            'InstanceObject'
            {
                $name = $InstanceObject.name
                $server = $InstanceObject.Server
                $Credential = $InstanceObject.credential
                $Description = "OneShell $($InstanceObject.Identity): $($InstanceObject.description)"
                $GlobalCatalog = $InstanceObject.GlobalCatalog
            }
            'Manual'
            {
            }#manual
        }#switch
    }#begin
    Process {
        try {
            $existingdrive = Get-PSDrive -Name $Name -ErrorAction Stop
            #Write-Log -Message "Existing drive  for $name exists"
            #Write-Log -Message "Checking $SessionName State" 
            if ($existingdrive) {
                Write-Log -Message "Existing Drive for $Name exists." 
                Write-Log -Message "Attempting: Validate Operational Status of Drive $name." 
                try {
                    $result = @(Get-ChildItem -Path "$name`:\" -ErrorAction Stop)
                    If ($result.Count -ge 1) {
                        Write-Log -Message "Succeeded: Validate Operational Status of Drive $name."
                        $UseExistingDrive = $True
                        Write-Output -InputObject $True
                    }
                    else {
                        Remove-PSDrive -Name $name -ErrorAction Stop
                        throw "No Results for Get-ChildItem for Path $name`:\"
                    }
                }
                Catch {
                    Write-Log -Message "Failed: Validate Operational Status of Drive $name." -ErrorLog
                    $UseExistingDrive = $False
                }
            }#if
            else {
                $UseExistingDrive = $false
            }#else
        }#try
        catch {
            Write-Log -Message "No existing PSDrive for $Name exists" 
            $UseExistingDrive = $false
        }#catch
        if ($UseExistingDrive -eq $False) {
            if ($GlobalCatalog) {$server = $server + ':3268'}
            $NewPSDriveParams = @{
                Name = $name
                Server = $server
                Root = '//RootDSE/'
                Scope = 'Global'
                PSProvider = 'ActiveDirectory'
                ErrorAction = 'Stop'
            }#newpsdriveparams
            if ($Description) {$NewPSDriveParams.Description = $Description}
            if ($credential) {$NewPSDriveParams.Credential = $Credential}
            try
            {
                Write-Log -Message "Attempting: Connect PS Drive $name`: to $Description"
                if (Import-RequiredModule -ModuleName ActiveDirectory -ErrorAction Stop)
                {
                    New-PSDrive @NewPSDriveParams  > $null
                }#if
                Write-Log -Message "Succeeded: Connect PS Drive $name`: to $Description"
                Write-Output -InputObject $true
            }#try
            catch
            {
                Write-Log -Message "FAILED: Connect PS Drive $name`: to $Description" -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                Write-Output -InputObject $false
            }#catch
        } #if
    }#process  
}#Connect-ADForest
Function Connect-MSOnlineTenant {
    [cmdletbinding(DefaultParameterSetName = 'Tenant')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'Tenant'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Select-Object -ExpandProperty Name)
            Alias = @('AD','Instance')
            Position = 2
            ParameterSetName = 'Tenant'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    #Connect to Windows Azure Active Directory
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Tenant' 
            {
                $Identity = $Tenant
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' 
            {
            }#manual
        }#switch
    }#begin
    process 
    {
            try 
            {
                $ModuleStatus = Import-RequiredModule -ModuleName MSOnline -ErrorAction Stop
                Write-Log -Message "Attempting: Connect to Windows Azure AD Administration with User $($Credential.username)."
                Connect-MsolService -Credential $Credential -ErrorAction Stop
                Write-Log -Message "Succeeded: Connect to Windows Azure AD Administration with User $($Credential.username)."
                Write-Output -InputObject $true
            }
            Catch 
            {
                Write-Log -Message "FAILED: Connect to Windows Azure AD Administration with User $($Credential.username)." -Verbose -ErrorLog
                Write-Log -Message $_.tostring()
                Write-Output -InputObject $false 
            }
    } #process
    <#Proxy for connect-msolservice
        netsh winhttp import proxy source=ie
        [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    #>
}#function Connect-MSOnlineTenant
Function Connect-AzureADTenant {
    [cmdletbinding(DefaultParameterSetName = 'Tenant')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'Tenant'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AzureADTenants' | Select-Object -ExpandProperty Name)
            Position = 2
            ParameterSetName = 'Tenant'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    #Connect to Windows Azure Active Directory
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Tenant' 
            {
                $Identity = $Tenant
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AzureADTenants' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' 
            {
            }#manual
        }#switch
    }#begin
    process 
    {
            try 
            {
                $ModuleStatus = Import-RequiredModule -ModuleName AzureAD -ErrorAction Stop
                Write-Log -Message "Attempting: Connect to Windows Azure AD Administration with User $($Credential.username)."
                $AzureADContext = Connect-AzureAD -Credential $Credential -Confirm:$false -ErrorAction Stop
                #Looks like they might set these up to support multiple tenant connections simultaneously.  May need to add them to a Script array if so.  
                Write-Log -Message "Succeeded: Connect to Windows Azure AD Administration with User $($Credential.username)."
                Write-Output -InputObject $true
            }
            Catch 
            {
                Write-Log -Message "FAILED: Connect to Windows Azure AD Administration with User $($Credential.username)." -Verbose -ErrorLog
                Write-Log -Message $_.tostring()
                Write-Output -InputObject $false 
            }
    } #process
    <#Proxy for connect-msolservice
        netsh winhttp import proxy source=ie
        [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    #>
}#function Connect-AzureAD
Function Connect-AADRM {
    [cmdletbinding(DefaultParameterSetName = 'Tenant')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'Tenant'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Select-Object -ExpandProperty Name)
            Position = 2
            ParameterSetName = 'Tenant'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    #Connect to Windows Azure Active Directory Rights Management
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary

        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Tenant' {
                $Identity = $PSBoundParameters['Tenant']
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' {
            }#manual
        }#switch
    }#begin
    process 
    {
        try 
        {
            $ModuleStatus = Import-RequiredModule -ModuleName AADRM -ErrorAction Stop
            Write-Log -Message "Attempting: Connect to Azure AD RMS Administration with User $($Credential.username)."
            Connect-AadrmService -Credential $Credential -errorAction Stop  > $null
            Write-Log -Message "Succeeded: Connect to Azure AD RMS Administration with User $($Credential.username)."
            Write-Output -InputObject $true
        }
        catch 
        {
            Write-Log -Message "FAILED: Connect to Azure AD RMS Administration with User $($Credential.username)." -Verbose -ErrorLog
            Write-Log -Message $_.tostring() -ErrorLog
            Write-Output -InputObject $false 
        }
    }#process
}#function Connect-AADRM
Function Connect-SQLDatabase {
    [cmdletbinding(DefaultParameterSetName = 'SQLDatabase')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'SQLDatabase'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Select-Object -ExpandProperty Name)
            Position = 2
            ParameterSetName = 'SQLDatabase'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    #Connect to Windows Azure Active Directory Rights Management
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'SQLDatabase' {
                $Identity = $SQLDatabase
                $SQLDatabaseObj = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Where-Object {$_.name -eq $Identity}
                $name = $SQLDatabaseObj.Name
                $SQLServer = $SQLDatabaseObj.Server
                $Instance = $SQLDatabaseObj.Instance
                $Database = $SQLDatabaseObj.Database
                $Credential = $SQLDatabaseObj.credential
                $Description = "OneShell $($SQLDatabaseObj.Identity): $($SQLDatabaseObj.description)"
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' {
            }#manual
        }#switch
    }#begin
    process 
    {
        try 
        {
            $message = 'Import required module POSH_ADO_SQLServer'
            Write-Log -Message $message -EntryType Attempting
            $ModuleStatus = Import-RequiredModule -ModuleName POSH_ADO_SQLServer -ErrorAction Stop
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $myerror = $_
            Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror)
        }
        try
        {
            $message = "Connect to $Description on $SQLServer as User $($Credential.username)."
            Write-Log -Message $message -EntryType Attempting
            Write-Warning -Message 'Connect-SQLDatabase currently uses Windows Integrated Authentication to connect to SQL Servers and ignores supplied credentials'
            $SQLConnection = New-SQLServerConnection -server $SQLServer -database $Database -ErrorAction Stop #-user $credential.username -password $($Credential.password | Convert-SecureStringToString)
            $SQLConnectionString = New-SQLServerConnectionString -server $SQLServer -database $Database -ErrorAction Stop
            Write-Log -Message $message -EntryType Succeeded
            $SQLConnection | Add-Member -Name 'Name' -Value $name -MemberType NoteProperty
            Update-SQLConnections -ConnectionName $Name -SQLConnection $SQLConnection
            Update-SQLConnectionStrings -ConnectionName $name -SQLConnectionString $SQLConnectionString
            Write-Output -InputObject $true
        }
        catch 
        {
            $myerror = $_
            Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror) 
        }
    }#process
}#function Connect-SQLDatabase
Function Connect-PowerShellSystem {
    [cmdletbinding(DefaultParameterSetName = 'Profile')]
    Param(
        [parameter(ParameterSetName='Manual',Mandatory=$true)]
        $ComputerName
        ,[parameter(ParameterSetName='Manual',Mandatory=$true)]
        $Credential
        ,
        [Parameter(ParameterSetName='Manual',Mandatory)]
        [ValidateLength(1,3)]
        [string]$CommandPrefix
        ,
        [switch]$usePrefix
        ,
        [string[]]$ManagementGroups
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'PowerShellSystem'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'PowerShellSystems' | Select-Object -ExpandProperty Name)
            Position = 3
            ParameterSetName = 'Profile'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    #Connect to Directory Synchronization
    #Server has to have been enabled for PS Remoting (enable-psremoting)
    #Credential has to be a member of ADSyncAdmins on the AADSync Server
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        switch ($PSCmdlet.ParameterSetName) {
            'Profile' {
                $SelectedProfile = $PSBoundParameters['PowerShellSystem']
                $Profile = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'PowerShellSystems' | Where-Object {$_.name -eq $selectedProfile}
                $UseX86 = $Profile.UseX86
                $SessionName = "$($Profile.Identity)"
                $System = $Profile.System
                $Credential = $Profile.Credential
                $ManagementGroups = $Profile.SessionManagementGroups
            }#Profile
            'Manual' {
                $SessionName = $ComputerName
                $System = $ComputerName
            }#manual
        }#switch
    }#begin
    Process{
        try {
            $existingsession = Get-PSSession -Name $SessionName -ErrorAction Stop
            #Write-Log -Message "Existing session for $SessionName exists"
            #Write-Log -Message "Checking $SessionName State" 
            if ($existingsession.State -ne 'Opened') {
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'" -EntryType Notification
                Remove-PSSession -Name $SessionName 
                $UseExistingSession = $False
            }#if
            else {
                #Write-Log -Message "$SessionName State is 'Opened'. Using existing Session." 
                $UseExistingSession = $true
                Write-Output -InputObject $true
            }#else
        }#try
        catch {
            Write-Log -Message "No existing session for $SessionName exists" -EntryType Notification
            $UseExistingSession = $false
        }#catch
        if ($UseExistingSession -eq $False) {
            $message = "Connecting to System $system as User $($credential.username)."
            $NewPSSessionParams = @{
                ComputerName = $System
                Credential = $Credential
                Name = $SessionName
                ErrorAction = 'Stop'
            }
            if ($UseX86 -eq $true) {$NewPSSessionParams.ConfigurationName = 'microsoft.powershell32'}
            Try {
                Write-Log -Message $message -EntryType Attempting
                $Session = New-PsSession @NewPSSessionParams
                Write-Log -Message $message -EntryType Succeeded
                Update-SessionManagementGroups -ManagementGroups $ManagementGroups -Session $SessionName -ErrorAction Stop
                Write-Output -InputObject $true
            }#Try
            Catch {
                Write-Log -Verbose -Message $message -ErrorLog -EntryType Failed
                Write-Log -Verbose -Message $_.tostring() -ErrorLog
                $false
            }#catch
        }#if
    }#process 
}#Function Connect-PowerShellSystem
Function Connect-MigrationWiz
{
    [cmdletbinding(DefaultParameterSetName = 'Account')]
    Param
    (
    [parameter(ParameterSetName='Manual')]
    $Credential
    )#param
    DynamicParam
    {
        $NewDynamicParameterParams=@{
            Name = 'Account'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'MigrationWizAccounts' | Select-Object -ExpandProperty Name)
            Position = 2
            ParameterSetName = 'Account'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary

        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Account' 
            {
                $Name = $Account
                $MigrationWizAccountObj = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'MigrationWizAccounts' | Where-Object {$_.name -eq $Name}
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'MigrationWizAccounts' | Where-Object -FilterScript {$_.Name -eq $Name} | Select-Object -ExpandProperty Credential
                $Name = $MigrationWizAccountObj.Name
                $Identity = $MigrationWizAccountObj.Identity
            }#Account
            'Manual' 
            {
            }#manual
        }#switch
    }#begin
    process 
    {
        try 
        {
            $message = "Connect to MigrationWiz with User $($Credential.username)."
            Write-Log -Message $message -EntryType Attempting                
            $ModuleStatus = Import-RequiredModule -ModuleName MigrationPowerShell -ErrorAction Stop
            #May eliminate the Script/Module variable later (dropping $Script:) in favor of the MigrationWizTickets Hashtable
            $Script:MigrationWizTicket = Get-MW_Ticket -Credentials $Credential -ErrorAction Stop -
            Update-MigrationWizTickets -AccountName $Name -MigrationWizTicket $Script:MigrationWizTicket #-Identity $Identity
            Write-Log -Message $message -EntryType Succeeded
            Write-Output -InputObject $true
        }
        Catch 
        {
            $myerror = $_
            Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
            Write-Log -Message $myerror.tostring()
            Write-Output -InputObject $false 
        }
    } 
}#function Connect-MigrationWiz
Function Connect-BitTitan
{
    [cmdletbinding(DefaultParameterSetName = 'Account')]
    Param
    (
    [parameter(ParameterSetName='Manual')]
    $Credential
    )#param
    DynamicParam
    {
        $NewDynamicParameterParams=@{
            Name = 'Account'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'BitTitanAccounts' | Select-Object -ExpandProperty Name)
            Position = 2
            ParameterSetName = 'Account'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary

        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Account' 
            {
                $Name = $Account
                $BitTitanAccountObj = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'BitTitanAccounts' | Where-Object {$_.name -eq $Name}
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'BitTitanAccounts' | Where-Object -FilterScript {$_.Name -eq $Name} | Select-Object -ExpandProperty Credential
                $Name = $BitTitanAccountObj.Name
                $Identity = $BitTitanAccountObj.Identity
            }#Account
            'Manual' 
            {
            }#manual
        }#switch
    }#begin
    process 
    {
        try 
        {
            $message = "Connect to BitTitan with User $($Credential.username)."
            Write-Log -Message $message -EntryType Attempting                
            $ModuleStatus = Import-RequiredModule -ModuleName BitTitanPowerShell -ErrorAction Stop
            #May eliminate the Script/Module variable later (dropping $Script:) in favor of the BitTitanTickets Hashtable
            $Script:BitTitanTicket = Get-BT_Ticket -Credentials $Credential -ErrorAction Stop -ServiceType BitTitan -SetDefault
            Update-BitTitanTickets -AccountName $Name -BitTitanTicket $Script:BitTitanTicket #-Identity $Identity
            Write-Log -Message $message -EntryType Succeeded
            Write-Output -InputObject $true
        }
        Catch 
        {
            $myerror = $_
            Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
            Write-Log -Message $myerror.tostring()
            Write-Output -InputObject $false 
        }
    } 
}#function Connect-BitTitan
Function Connect-LotusNotesDatabase
{
    [cmdletbinding(DefaultParameterSetName = 'LotusNotesDatabase')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'LotusNotesDatabase'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'LotusNotesDatabases' | Select-Object -ExpandProperty Name)
            Position = 2
            ParameterSetName = 'LotusNotesDatabase'
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        Write-StartFunctionStatus -CallingFunction $MyInvocation.MyCommand
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'LotusNotesDatabase' {
                $Name = $PSBoundParameters['LotusNotesDatabase']
                $LotusNotesDatabaseObj = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'LotusNotesDatabases' | Where-Object {$_.name -eq $Name}
                $NotesServer = $LotusNotesDatabaseObj.Server
                $Client = $Script:CurrentOrgAdminProfileSystems | Where-Object -FilterScript {$_.Identity -eq $LotusNotesDatabaseObj.Client}
                $ClientName = $Client.Name
                $ClientIdentity = $Client.Identity
                $Database = $LotusNotesDatabaseObj.Database
                $Credential = $LotusNotesDatabaseObj.credential
                $Description = $LotusNotesDatabaseObj.description
                $Identity = $LotusNotesDatabaseObj.Identity
            }#tenant
            'Manual' {
            }#manual
        }#switch
    }#begin
    process 
    {
        #Verify the required PSSession is available (has to a a x86 session due to Notes com object limitations, ugh)
        try 
        {
            $message = "Verify Connection to Lotus Notes Client PowerShell Session on Client $ClientName"
            Write-Log -Message $message -EntryType Attempting
            $ClientConnectionStatus = Connect-PowerShellSystem -PowerShellSystem $ClientName -ErrorAction Stop
            $ClientPSSession = Get-PSSession -Name $ClientIdentity -ErrorAction Stop
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $myerror = $_
            Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror)
        }
        #Create the required functions in the Client PSSession 
        try
        {
            $message = "Import the required Notes Module into the client PSSession $ClientIdentity"
            Write-Log -Message $message -EntryType Attempting
            Invoke-Command -Session $ClientPSSession -ScriptBlock {Import-Module -Global -Name PSLotusNotes}
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $myerror = $_
            Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror)
        }
        #and then import the session with just those functions available to bring them into the local session
        try
        {
            $message = 'Import the Client PSSession importing only the Notes functions'
            Write-Log -Message $message -EntryType Attempting
            Import-Module (Import-PSSession -Module PSLotusNotes -AllowClobber -Session $ClientPSSession -ErrorAction Stop) -Scope Global
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $myerror = $_
            Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror)
        }
        #Run the New-NotesDatabaseConnection Function in the Client PSSession
        try
        {
            $message = "Connect to $Description on $NotesServer as User $($Credential.username)."
            Write-Log -Message $message -EntryType Attempting
            $WarningMessage = "Connect-LotusNotesDatabase currently uses the client's configured Notes User and ignores the supplied username.  It does use the supplied password for the Notes credential, however."
            Write-Warning -Message $WarningMessage
            Write-Log -Message $WarningMessage -EntryType Notification -ErrorLog
            $NotesDatabaseConnection = New-NotesDatabaseConnection -NotesServerName $NotesServer -database $Database -ErrorAction Stop -Credential $Credential -Name $Name -Identity $Identity
            Write-Log -Message $message -EntryType Succeeded
            #$NotesDatabaseConnection | Add-Member -Name 'Name' -Value $name -MemberType NoteProperty
            #$NotesDatabaseConnection | Add-Member -Name 'Identity' -Value $Identity -MemberType NoteProperty
            #Update-NotesDatabaseConnections -ConnectionName $Name -NotesDatabaseConnection $NotesDatabaseConnection
            Write-Output -InputObject $true
        }
        catch 
        {
            $myerror = $_
            Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror) 
        }
    }#process
    end
    {
        Write-EndFunctionStatus -CallingFunction $MyInvocation.MyCommand
    }
}#function Connect-LotusNotesDatabase
Function Update-SessionManagementGroups {
  [cmdletbinding(DefaultParameterSetName = 'Profile')]
  Param(
    [parameter(Mandatory=$true)]
    $SessionName
    ,[parameter(Mandatory=$true)]
    [string[]]$ManagementGroups
  )#param
  foreach ($MG in $ManagementGroups)
  {
    $SessionGroup = $MG + '_Sessions'
    #Check if the Session Group already exists
    if (Test-Path -Path "variable:\$SessionGroup") 
    {
      #since the session group already exists, add the session to it if it is not already present
        $existingSessions = Get-Variable -Name $SessionGroup -Scope Global -ValueOnly
        $existingSessionNames = $existingSessions | Select-Object -ExpandProperty Name
        $existingSessionIDs = $existingSessions | Select-Object -ExpandProperty ID
        if ($SessionName -in $existingSessionNames) 
        {
            $NewSession = Get-PSSession -Name $SessionName
            $newvalue = @($existingSessions | Where-Object -FilterScript {$_.Name -ne $SessionName})
            $newvalue += $NewSession
            Set-Variable -Name $SessionGroup -Value $newvalue -Scope Global
        } else {
            $NewSession = Get-PSSession -Name $SessionName
            $newvalue = @(Get-PSSession -Name $existingSessionNames)
            $newvalue += $NewSession
            Set-Variable -Name $SessionGroup -Value $newvalue -Scope Global
        }
    } else {
      #since the session group does not exist, create it and add the session to it
        New-Variable -Name $SessionGroup -Value @($(Get-PSSession -Name $SessionName)) -Scope Global
    }#else
  }#foreach
}#function Update-SessionManagementGroups
Function Update-SQLConnections {
  [cmdletbinding()]
  Param(
    [parameter(Mandatory=$true)]
    $ConnectionName
    ,[parameter(Mandatory=$true)]
    $SQLConnection
  )#param
  #Check if the Session Group already exists
  if (Test-Path -Path 'variable:\SQLConnections')
  {
    #since the connection group already exists, add the connection to it if it is not already present or update it if it is
    $existingConnections = Get-Variable -Name 'SQLConnections' -Scope Global -ValueOnly
    $existingConnectionNames = $existingConnections | Select-Object -ExpandProperty Name
    #$existingSessionIDs = $existingSessions | Select-Object -ExpandProperty ID
    if ($ConnectionName -in $existingConnectionNames)
    {
        $newvalue = @($existingConnections | Where-Object -FilterScript {$_.Name -ne $ConnectionName})
        $newvalue += $SQLConnection
        Set-Variable -Name 'SQLConnections' -Value $newvalue -Scope Global
    } else {
        $newvalue = @($existingConnections)
        $newvalue += $SQLConnection
        Set-Variable -Name 'SQLConnections' -Value $newvalue -Scope Global
    }

  } else {
    #since the session group does not exist, create it and add the session to it
    New-Variable -Name 'SQLConnections' -Value @(,$SQLConnection) -Scope Global
  }#else
}#function Update-SQLConnections
Function Update-SQLConnectionStrings {
  [cmdletbinding()]
  Param(
    [parameter(Mandatory=$true)]
    $ConnectionName
    ,[parameter(Mandatory=$true)]
    $SQLConnectionString
  )#param
  #Check if the Session Group already exists
  if (Test-Path -Path 'variable:\SQLConnectionStrings') 
  {
    $Global:SQLConnectionStrings.$($ConnectionName)=$SQLConnectionString
  } else {
    #since the session group does not exist, create it and add the session to it
    New-Variable -Name 'SQLConnectionStrings' -Value @{$ConnectionName = $SQLConnectionString} -Scope Global
  }#else
}#function Update-SQLConnectionStrings
Function Update-MigrationWizTickets
{
  [cmdletbinding()]
  Param(
    [parameter(Mandatory=$true)]
    $AccountName
    ,[parameter(Mandatory=$true)]
    $MigrationWizTicket
  )#param
  if (Test-Path -Path 'variable:Global:MigrationWizTickets') 
  {
    $Global:MigrationWizTickets.$($AccountName)=$MigrationWizTicket
  } else
  {
    New-Variable -Name 'MigrationWizTickets' -Value @{$AccountName = $MigrationWizTicket} -Scope Global
  }#else
}#function Update-MigrationWizTickets
Function Update-BitTitanTickets
{
  [cmdletbinding()]
  Param(
    [parameter(Mandatory=$true)]
    $AccountName
    ,[parameter(Mandatory=$true)]
    $BitTitanTicket
  )#param
  if (Test-Path -Path 'variable:Global:BitTitanTickets') 
  {
    $Global:BitTitanTickets.$($AccountName)=$BitTitanTicket
  } else
  {
    New-Variable -Name 'BitTitanTickets' -Value @{$AccountName = $BitTitanTicket} -Scope Global
  }#else
}#function Update-BitTitanTickets
Function Connect-RemoteSystems
{
    [CmdletBinding()]
    param ()
    $ProcessStatus = [pscustomobject]@{
        Command = $MyInvocation.MyCommand.Name
        BoundParameters = $MyInvocation.BoundParameters
        Outcome = $null
        Connections = @()
    }
    try {
        # Connect To Exchange Systems
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to $sys-Exchange."
                Write-Log -Message $message -EntryType Attempting
                $ConnectionResult = Connect-Exchange -ExchangeOrganization $sys -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
                $ProcessStatus.Connections += [pscustomobject]@{Type='Exchange';Name=$sys;ConnectionStatus=$ConnectionResult}
            }#try
            catch {
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $_.tostring() -ErrorLog
                $ProcessStatus.Connections += [pscustomobject]@{Type='Exchange';Name=$sys;ConnectionStatus=$ConnectionResult}
            }#catch
        }
        # Connect to Azure AD Sync
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AADSyncServers' | Where-Object AutoConnect -EQ $true | Select-Object -ExpandProperty Name)) 
        {
            $ConnectAADSyncParams = @{AADSyncServer = $sys; ErrorAction = 'Stop'}
            if (($Script:AADSyncServers | Where-Object AutoConnect -EQ $true).count -gt 1) {$ConnectAADSyncParams.UsePrefix = $true}
            try {
                Write-Log -Message "Attempting: Connect to $sys-AADSync."
                $Status = Connect-AADSync @ConnectAADSyncParams
                Write-Log -Message "Succeeded: Connect to $sys-AADSync."
                $ProcessStatus.Connections += [pscustomobject]@{Type='AADSync';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                Write-Log -Message "Failed: Connect to $sys-AADSync." -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='AADSync';Name=$sys;ConnectionStatus=$Status}
            }#catch    
        }
        # Connect to Active Directory Forests
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Where-Object AutoConnect -EQ $true | Select-Object -ExpandProperty Name))
        {
            if (Import-RequiredModule -ModuleName ActiveDirectory -ErrorAction Stop)
            {
                try {
                    Write-Log -Message "Attempting: Connect to AD Instance $sys."
                    $Status = Connect-ADInstance -ActiveDirectoryInstance $sys -ErrorAction Stop
                    Write-Log -Message "Succeeded: Connect to AD Instance $sys."
                    $ProcessStatus.Connections += [pscustomobject]@{Type='AD Instance';Name=$sys;ConnectionStatus=$Status}
                }
                catch {
                    Write-Log -Message "FAILED: Connect to AD Instance $sys." -Verbose -ErrorLog
                    Write-Log -Message $_.tostring() -ErrorLog
                    $Status = $false
                    $ProcessStatus.Connections += [pscustomobject]@{Type='AD Instance';Name=$sys;ConnectionStatus=$Status}
                }
            }
        }
        # Connect to default Legacy MSOnline Tenant
        $DefaultTenant = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.autoconnect -eq $true} | Select-Object -First 1)
        if ($DefaultTenant.Count -eq 1) 
        {
            try
            {
                $message = "Connect to Azure AD Tenant $sys"
                $Status = Connect-MSOnlineTenant -Tenant $DefaultTenant.Name -ErrorAction Stop
                $ProcessStatus.Connections += [pscustomobject]@{Type='MSOnline';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
            catch
            {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='MSOnline';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
        }
        # Connect to default Azure AD Tenant
        $DefaultTenant = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AzureADTenants' | Where-Object -FilterScript {$_.autoconnect -eq $true} | Select-Object -First 1)
        if ($DefaultTenant.Count -eq 1) 
        {
            try
            {
                $message = "Connect to Azure AD Tenant $sys"
                $Status = Connect-AzureADTenant -Tenant $DefaultTenant.Name -ErrorAction Stop
                $ProcessStatus.Connections += [pscustomobject]@{Type='Azure AD';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
            catch
            {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='Azure AD';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
        }        
        # Connect to default Azure AD RMS
        $DefaultTenant = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AzureADRMS' | Where-Object -FilterScript {$_.autoconnect -eq $true} | Select-Object -First 1)
        if ($DefaultTenant.Count -eq 1) 
        {
            try
            {
                $message = "Connect to Azure AD RMS Tenant $sys"
                $Status = Connect-AADRM -Tenant $DefaultTenant.Name -ErrorAction Stop
                $ProcessStatus.Connections += [pscustomobject]@{Type='Azure AD RMS';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
            catch
            {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='Azure AD RMS';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
        }
        # Connect To PowerShell Systems
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'PowershellSystems' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to PowerShell on System $sys"
                Write-Log -Message $message -EntryType Attempting
                $Status = Connect-PowerShellSystem -PowerShellSystem $sys -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
                $ProcessStatus.Connections += [pscustomobject]@{Type='PowerShell';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='PowerShell';Name=$sys;ConnectionStatus=$Status}
            }#catch
        }
        # Connect To SQL Database Systems
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to SQL Database $sys"
                Write-Log -Message $message -EntryType Attempting
                $Status = Connect-SQLDatabase -SQLDatabase $sys -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
                $ProcessStatus.Connections += [pscustomobject]@{Type='SQL Database';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='SQL Database';Name=$sys;ConnectionStatus=$Status}
            }#catch
        }
        # Connect To Lotus Notes Databases
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'LotusNotesDatabases' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to Notes Database $sys"
                Write-Log -Message $message -EntryType Attempting
                $Status = Connect-LotusNotesDatabase -LotusNotesDatabase $sys -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
                $ProcessStatus.Connections += [pscustomobject]@{Type='Lotus Notes Database';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='Lotus Notes Database';Name=$sys;ConnectionStatus=$Status}
            }#catch
        }
        # Connect To MigrationWiz Accounts
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'MigrationWizAccounts' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to Migration Wiz Account $sys"
                Write-Log -Message $message -EntryType Attempting
                $Status = Connect-MigrationWiz -Account $sys -ErrorAction Stop 
                Write-Log -Message $message -EntryType Succeeded
                $ProcessStatus.Connections += [pscustomobject]@{Type='Migration Wiz Account';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='Migration Wiz Account';Name=$sys;ConnectionStatus=$Status}
            }#catch
        }
        # Connect To BitTitan Accounts
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'BitTitanAccounts' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to BitTitan Account $sys"
                Write-Log -Message $message -EntryType Attempting
                $Status = Connect-BitTitan -Account $sys -ErrorAction Stop 
                Write-Log -Message $message -EntryType Succeeded
                $ProcessStatus.Connections += [pscustomobject]@{Type='BitTitan Account';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='BitTitan Account';Name=$sys;ConnectionStatus=$Status}
            }#catch
        }        
        $ProcessStatus.Outcome = $true
        Write-Output -InputObject $ProcessStatus.Connections
    }
    catch {
        $ProcessStatus.Outcome = $false
        Write-Output -InputObject $ProcessStatus.Connections
    }
}
function Invoke-ExchangeCommand {
[cmdletbinding(DefaultParameterSetName = 'String')]
param(
    [parameter(Mandatory,Position = 1)]
    [ValidateScript({$_ -like '*-*'})]
    [string]$cmdlet
    ,
    [parameter(Position = 3,ParameterSetName='Splat')]
    [hashtable]$splat
    ,
    [parameter(Position = 3,ParameterSetName = 'String')]
    [string]$string = ''
    ,
    [string]$CommandPrefix
    ,
    [switch]$checkConnection
)#Param
DynamicParam
{
    $Dictionary = New-ExchangeOrganizationDynamicParameter -Mandatory
    Write-Output -InputObject $Dictionary
}#DynamicParam
begin
{
    #Dynamic Parameter to Variable Binding
    Set-DynamicParameterVariable -dictionary $Dictionary
    # Bind the dynamic parameter to a friendly variable
    if ([string]::IsNullOrWhiteSpace($CommandPrefix))
    {
        $Org = $ExchangeOrganization
        if (-not [string]::IsNullOrWhiteSpace($Org))
        {
            $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object {$_.name -eq $org}
            $CommandPrefix = $orgobj.CommandPrefix
        }#if
        else {$CommandPrefix = ''}#else
    }#if
    if ($checkConnection -eq $true)
    {
        if ((Connect-Exchange -exchangeorganization $ExchangeOrganization) -ne $true)
        {throw ("Connection to Exchange Organization $ExchangeOrganization failed.")}
    }
}#begin
Process
{
    #Build the Command String and convert to Scriptblock
    switch ($PSCmdlet.ParameterSetName)
    {
        'splat' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) @splat")}#splat
        'string' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) $string")}#string
    }#switch
    #Store and Set and Restore ErrorAction Preference; Execute the command String
    try
    {
        if ($ErrorActionPreference -eq 'Stop')
        {
            $originalGlobalErrorAction = $global:ErrorActionPreference
            $global:ErrorActionPreference = 'Stop'
        }
        &$commandstring
        if ($ErrorActionPreference -eq 'Stop')
        {
            $global:ErrorActionPreference = $originalGlobalErrorAction
        }
    }#try
    catch
    {
        $myerror = $_
        if ($ErrorActionPreference -eq 'Stop')
        {
            $global:ErrorActionPreference = $originalGlobalErrorAction
        }
        throw $myerror
    }#catch
}#Process
}#Function Invoke-ExchangeCommand
function Test-ExchangeCommandExists
{
[cmdletbinding(DefaultParameterSetName = 'Organization')]
param(
    [parameter(Mandatory,Position = 1)]
    [ValidateScript({$_ -like '*-*'})]
    [string]$cmdlet
    ,
    [switch]$checkConnection
)#Param
DynamicParam
{
    $Dictionary = New-ExchangeOrganizationDynamicParameter -ParameterSetName 'Organization' -Mandatory
    Write-Output -InputObject $Dictionary
}#DynamicParam
begin
{
    #Dynamic Parameter to Variable Binding
    Set-DynamicParameterVariable -dictionary $Dictionary
    # Bind the dynamic parameter to a friendly variable
    $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object {$_.name -eq $ExchangeOrganization}
    $CommandPrefix = $orgobj.CommandPrefix
    if ($checkConnection -eq $true)
    {
        if ((Connect-Exchange -exchangeorganization $ExchangeOrganization) -ne $true)
        {throw ("Connection to Exchange Organization $ExchangeOrganization failed.")}
    }
}#begin
Process
{
    #Build the Command String
    $commandstring = "$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1])"

    #Store and Set and Restore ErrorAction Preference; Execute the command String
    Test-CommandExists -command $commandstring
}#Process
}#Function Test-ExchangeCommandExists
function Invoke-SkypeCommand {
    [cmdletbinding(DefaultParameterSetName = 'String')]
    param(
        [parameter(Mandatory = $true,Position = 1)]
        [ValidateScript({$_ -like '*-*'})]
        [string]$cmdlet
        ,
        [parameter(Position = 3,ParameterSetName='Splat')]
        [hashtable]$splat
        ,
        [parameter(Position = 3,ParameterSetName = 'String')]
        [string]$string = ''
        ,
        [string]$CommandPrefix
    )#Param
    DynamicParam
    {
        $NewDynamicParameterParams=@{
            Name = 'SkypeOrganization'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SkypeOrganizations' | Select-Object -ExpandProperty Name)
            Alias = @('Org','SkypeOrg')
            Position = 2
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        # Bind the dynamic parameter to a friendly variable
        if ([string]::IsNullOrWhiteSpace($CommandPrefix)) {
            $Org = $SkypeOrganization
            if (-not [string]::IsNullOrWhiteSpace($Org)) {
                $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'SkypeOrganizations' | Where-Object {$_.name -eq $org}
                $CommandPrefix = $orgobj.CommandPrefix
            }
            else {$CommandPrefix = ''}
        }
    }
    Process {

        #Build the Command String and convert to Scriptblock
        switch ($PSCmdlet.ParameterSetName) {
            'splat' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) @splat")}#splat
            'string' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) $string")}#string
        }
        #Execute the command String
        &$commandstring

    }#Process
}#Function Invoke-SkypeCommand

function Export-FunctionToPSSession
{
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [string[]]$FunctionNames
    ,
    [parameter(ParameterSetName = 'SessionID',Mandatory,ValuefromPipelineByPropertyName)]
    [int]$ID
    ,
    [parameter(ParameterSetName = 'SessionName',Mandatory,ValueFromPipelineByPropertyName)]
    [string]$Name
    ,
    [parameter(ParameterSetName = 'SessionObject',Mandatory,ValueFromPipeline)]
    [Management.Automation.Runspaces.PSSession]$PSSession
    ,
    [switch]$Refresh
  )
  #Find the session
  $GetPSSessionParams=@{
    ErrorAction = 'Stop'
  }
  switch ($PSCmdlet.ParameterSetName)
  {
    'SessionID'
    {
        $GetPSSessionParams.ID = $ID
        $PSSession = Get-PSSession @GetPSSessionParams
    }
    'SessionName'
    {
        $GetPSSessionParams.Name = $Name
        $PSSession = Get-PSSession @GetPSSessionParams
    }
    'SessionObject'
    {
        #nothing required here
    }
  }
  #Verify the session availability
  if (-not $PSSession.Availability -eq 'Available')
  {
    throw "Availability Status for PSSession $($PSSession.Name) is $($PSSession.Availability).  It must be Available."
  }
  #Verify if the functions already exist in the PSSession unless Refresh
  foreach ($FN in $FunctionNames)
  {
    $script = "Get-Command -Name '$FN' -ErrorAction SilentlyContinue"
    $scriptblock = [scriptblock]::Create($script)
    $remoteFunction = Invoke-Command -Session $PSSession -ScriptBlock $scriptblock -ErrorAction SilentlyContinue
    if ($remoteFunction.CommandType -ne $null -and -not $Refresh)
    {
        $FunctionNames = $FunctionNames | Where-Object -FilterScript {$_ -ne $FN}
    }
  }
  Write-Verbose -Message "Functions remaining: $($FunctionNames -join ',')"
  #Verify the local function availiability
  $Functions = @(
    foreach ($FN in $FunctionNames)
    {
        Get-Command -ErrorAction Stop -Name $FN -CommandType Function
    }
  )
  #build functions text to initialize in PsSession 
  $FunctionsText = ''
  foreach ($Function in $Functions) {
    $FunctionText = 'function ' + $Function.Name + "`r`n {`r`n" + $Function.Definition + "`r`n}`r`n"
    $FunctionsText = $FunctionsText + $FunctionText
  }
  #convert functions text to scriptblock
  $ScriptBlock = [scriptblock]::Create($FunctionsText)
  Invoke-Command -Session $PSSession -ScriptBlock $ScriptBlock -ErrorAction Stop
}
Function Get-MCTLSourceData
{
  [cmdletbinding()]
  param(
    [parameter(Mandatory)]
    [ValidateSet('SQL','SharePoint','LocalFile')]
    $SourceType
    ,
    [parameter(Mandatory,ParameterSetName='SQL')]
    $SQLConnection
  )
  try
  {
    $message = "Retrieve MCTL Source Data from source $sourcetype"
    Write-Log -Message $message -EntryType Attempting
    $Global:MCTLSourceData = Invoke-SQLServerQuery -sql 'Select * FROM dbo.ExpandedMCTL' -connection $SQLConnection
    Write-Log -Message $message -EntryType Succeeded -Verbose
    Write-Log -Message "$($Global:MCTLSourceData.count) MCTL Records Retrieved and stored in `$Global:MCTLSourceData" -Verbose
  }
  catch{}
}
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
