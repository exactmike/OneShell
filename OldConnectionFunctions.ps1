Function Import-RequiredModule
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateSet('ActiveDirectory', 'AzureAD', 'MSOnline', 'AADRM', 'LyncOnlineConnector', 'POSH_ADO_SQLServer', 'MigrationPowershell', 'BitTitanPowerShell')]
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
    }
    else
    {
        Write-Log -EntryType Notification -Message "$ModuleName Module is already loaded."
        Write-Output -InputObject $true
    }
}# Function Import-RequiredModule

Function Connect-AADRM
{
    [cmdletbinding(DefaultParameterSetName = 'Tenant')]
    Param(
        [parameter(ParameterSetName = 'Manual')]
        $Credential
    )#param
    DynamicParam
    {
        $NewDynamicParameterParams = @{
            Name             = 'Tenant'
            ValidateSet      = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Select-Object -ExpandProperty Name)
            Position         = 2
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
            Command         = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome         = $null
        }
        switch ($PSCmdlet.ParameterSetName)
        {
            'Tenant'
            {
                $Identity = $PSBoundParameters['Tenant']
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
Function Connect-SQLDatabase
{
    [cmdletbinding(DefaultParameterSetName = 'SQLDatabase')]
    Param(
        [parameter(ParameterSetName = 'Manual')]
        $Credential
    )#param
    DynamicParam
    {
        $NewDynamicParameterParams = @{
            Name             = 'SQLDatabase'
            ValidateSet      = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Select-Object -ExpandProperty Name)
            Position         = 2
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
            Command         = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome         = $null
        }
        switch ($PSCmdlet.ParameterSetName)
        {
            'SQLDatabase'
            {
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
            'Manual'
            {
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

Function Connect-MigrationWiz
{
    [cmdletbinding(DefaultParameterSetName = 'Account')]
    Param
    (
        [parameter(ParameterSetName = 'Manual')]
        $Credential
    )#param
    DynamicParam
    {
        $NewDynamicParameterParams = @{
            Name             = 'Account'
            ValidateSet      = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'MigrationWizAccounts' | Select-Object -ExpandProperty Name)
            Position         = 2
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
            Command         = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome         = $null
        }
        switch ($PSCmdlet.ParameterSetName)
        {
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
        [parameter(ParameterSetName = 'Manual')]
        $Credential
    )#param
    DynamicParam
    {
        $NewDynamicParameterParams = @{
            Name             = 'Account'
            ValidateSet      = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'BitTitanAccounts' | Select-Object -ExpandProperty Name)
            Position         = 2
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
            Command         = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome         = $null
        }
        switch ($PSCmdlet.ParameterSetName)
        {
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
        [parameter(ParameterSetName = 'Manual')]
        $Credential
    )#param
    DynamicParam
    {
        $NewDynamicParameterParams = @{
            Name             = 'LotusNotesDatabase'
            ValidateSet      = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'LotusNotesDatabases' | Select-Object -ExpandProperty Name)
            Position         = 2
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
            Command         = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome         = $null
        }
        switch ($PSCmdlet.ParameterSetName)
        {
            'LotusNotesDatabase'
            {
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
            'Manual'
            {
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

Function Update-SQLConnections
{
    [cmdletbinding()]
    Param(
        [parameter(Mandatory = $true)]
        $ConnectionName
        , [parameter(Mandatory = $true)]
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
        }
        else
        {
            $newvalue = @($existingConnections)
            $newvalue += $SQLConnection
            Set-Variable -Name 'SQLConnections' -Value $newvalue -Scope Global
        }

    }
    else
    {
        #since the session group does not exist, create it and add the session to it
        New-Variable -Name 'SQLConnections' -Value @(, $SQLConnection) -Scope Global
    }#else
}#function Update-SQLConnections
Function Update-SQLConnectionStrings
{
    [cmdletbinding()]
    Param(
        [parameter(Mandatory = $true)]
        $ConnectionName
        , [parameter(Mandatory = $true)]
        $SQLConnectionString
    )#param
    #Check if the Session Group already exists
    if (Test-Path -Path 'variable:\SQLConnectionStrings')
    {
        $Global:SQLConnectionStrings.$($ConnectionName) = $SQLConnectionString
    }
    else
    {
        #since the session group does not exist, create it and add the session to it
        New-Variable -Name 'SQLConnectionStrings' -Value @{$ConnectionName = $SQLConnectionString} -Scope Global
    }#else
}#function Update-SQLConnectionStrings
Function Update-MigrationWizTickets
{
    [cmdletbinding()]
    Param(
        [parameter(Mandatory = $true)]
        $AccountName
        , [parameter(Mandatory = $true)]
        $MigrationWizTicket
    )#param
    if (Test-Path -Path 'variable:Global:MigrationWizTickets')
    {
        $Global:MigrationWizTickets.$($AccountName) = $MigrationWizTicket
    }
    else
    {
        New-Variable -Name 'MigrationWizTickets' -Value @{$AccountName = $MigrationWizTicket} -Scope Global
    }#else
}#function Update-MigrationWizTickets
Function Update-BitTitanTickets
{
    [cmdletbinding()]
    Param(
        [parameter(Mandatory = $true)]
        $AccountName
        , [parameter(Mandatory = $true)]
        $BitTitanTicket
    )#param
    if (Test-Path -Path 'variable:Global:BitTitanTickets')
    {
        $Global:BitTitanTickets.$($AccountName) = $BitTitanTicket
    }
    else
    {
        New-Variable -Name 'BitTitanTickets' -Value @{$AccountName = $BitTitanTicket} -Scope Global
    }#else
}#function Update-BitTitanTickets
function Invoke-ExchangeCommand
{
    [cmdletbinding(DefaultParameterSetName = 'String')]
    param(
        [parameter(Mandatory, Position = 1)]
        [ValidateScript( {$_ -like '*-*'})]
        [string]$cmdlet
        ,
        [parameter(Position = 3, ParameterSetName = 'Splat')]
        [hashtable]$splat
        ,
        [parameter(Position = 3, ParameterSetName = 'String')]
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
    process
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
}
#End Function Invoke-ExchangeCommand
function Invoke-SkypeCommand
{
    [cmdletbinding(DefaultParameterSetName = 'String')]
    param(
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateScript( {$_ -like '*-*'})]
        [string]$cmdlet
        ,
        [parameter(Position = 3, ParameterSetName = 'Splat')]
        [hashtable]$splat
        ,
        [parameter(Position = 3, ParameterSetName = 'String')]
        [string]$string = ''
        ,
        [string]$CommandPrefix
    )#Param
    DynamicParam
    {
        $NewDynamicParameterParams = @{
            Name        = 'SkypeOrganization'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SkypeOrganizations' | Select-Object -ExpandProperty Name)
            Alias       = @('Org', 'SkypeOrg')
            Position    = 2
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        # Bind the dynamic parameter to a friendly variable
        if ([string]::IsNullOrWhiteSpace($CommandPrefix))
        {
            $Org = $SkypeOrganization
            if (-not [string]::IsNullOrWhiteSpace($Org))
            {
                $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'SkypeOrganizations' | Where-Object {$_.name -eq $org}
                $CommandPrefix = $orgobj.CommandPrefix
            }
            else {$CommandPrefix = ''}
        }
    }
    Process
    {

        #Build the Command String and convert to Scriptblock
        switch ($PSCmdlet.ParameterSetName)
        {
            'splat' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) @splat")}#splat
            'string' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) $string")}#string
        }
        #Execute the command String
        &$commandstring

    }#Process
}
#End Function Invoke-SkypeCommand

Function Get-MCTLSourceData
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [ValidateSet('SQL', 'SharePoint', 'LocalFile')]
        $SourceType
        ,
        [parameter(Mandatory, ParameterSetName = 'SQL')]
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
    catch {}
}
#end Function Get-MCTLSourceData