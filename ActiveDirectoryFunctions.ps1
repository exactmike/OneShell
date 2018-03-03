function Find-ADUser
{
    [cmdletbinding(DefaultParameterSetName = 'Default')]
    param(
        [parameter(Mandatory = $true,valuefrompipeline = $true, valuefrompipelinebypropertyname = $true, ParameterSetName='Default')]
        [parameter(ParameterSetName='FirstLast')]
        [string]$Identity
        ,
        [parameter(Mandatory = $true)]
        [validateset('SAMAccountName','UserPrincipalName','ProxyAddress','Mail','mailNickname','employeeNumber','employeeID','extensionattribute5','extensionattribute11','extensionattribute13','DistinguishedName','CanonicalName','ObjectGUID','mS-DS-ConsistencyGuid','SID','GivenNameSurname')]
        $IdentityType
        ,
        [switch]$DoNotPreserveLocation #use this switch when you are already running the commands from the correct AD Drive
        ,
        $properties = $ADUserAttributes
        ,
        [parameter(ParameterSetName='FirstLast',Mandatory = $true)]
        [string]$GivenName
        ,
        [parameter(ParameterSetName='FirstLast',Mandatory = $true)]
        [string]$SurName
        ,
        [switch]$AmbiguousAllowed
        ,
        [switch]$ReportExceptions
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'ADInstance'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -like 'ActiveDirectory*').name

            Position = 2
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams -Type []
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    Begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary        
        $ADInstance = $ActiveDirectoryInstance
        if ($DoNotPreserveLocation -ne $true) {Push-Location -StackName 'Lookup-ADUser'}
        #validate AD Instance
        try {
            #Write-Log -Message "Attempting: Set Location to AD Drive $("$ADInstance`:")"
            Set-Location -Path $("$ADInstance`:\") -ErrorAction Stop
            #Write-Log -Message "Succeeded: Set Location to AD Drive $("$ADInstance`:")" 
        }#try
        catch {
            Write-Log -Message "Failed: Set Location to AD Drive $("$ADInstance`:")" -Verbose -ErrorLog
            Write-Log -Message $_.tostring() -ErrorLog
            $ErrorRecord = New-ErrorRecord -Exception 'System.Exception' -ErrorId ADDriveNotAvailable -ErrorCategory NotSpecified -TargetObject $ADInstance -Message 'Required AD Drive not available'
            $PSCmdlet.ThrowTerminatingError($ErrorRecord)
        }
        #Setup GetADUserParams
        $GetADUserParams = @{ErrorAction = 'Stop'}
        if ($properties.count -ge 1) {
            #Write-Log -Message "Using Property List: $($properties -join ",") with Get-ADUser"
            $GetADUserParams.Properties = $Properties
        }
        #Setup exception reporting
        if ($ReportExceptions) {
            $Script:LookupADUserNotFound = @()
            $Script:LookupADUserAmbiguous = @()
        }
    }#Begin
    Process {
        switch ($IdentityType) {
            'mS-DS-ConsistencyGuid' {
                $Identity = $Identity -join ' '
            }
            'GivenNameSurname' {
                $SurName = $SurName.Trim()
                $GivenName = $GivenName.Trim()                
                $Identity = "$SurName, $GivenName"
            }
            Default {}
        }
        foreach ($ID in $Identity) {
            try {
                Write-Log -Message "Attempting: Get-ADUser with identifier $ID for Attribute $IdentityType" 
                switch ($IdentityType) {
                    'SAMAccountName' {
                        $ADUser = @(Get-ADUser -filter {SAMAccountName -eq $ID} @GetADUserParams)
                    }
                    'UserPrincipalName' {
                        $AdUser = @(Get-ADUser -filter {UserPrincipalName -eq $ID} @GetADUserParams)
                    }
                    'ProxyAddress' {
                        #$wildcardID = "*$ID*"
                        $AdUser = @(Get-ADUser -filter {proxyaddresses -like $ID} @GetADUserParams)
                    }
                    'Mail' {
                        $AdUser = @(Get-ADUser -filter {Mail -eq $ID}  @GetADUserParams)
                    }
                    'mailNickname'{
                        $AdUser = @(Get-ADUser -filter {mailNickname -eq $ID}  @GetADUserParams)
                    }
                    'extensionattribute5' {
                        $AdUser = @(Get-ADUser -filter {extensionattribute5 -eq $ID} @GetADUserParams)
                    }
                    'extensionattribute11' {
                        $AdUser = @(Get-ADUser -filter {extensionattribute11 -eq $ID} @GetADUserParams)
                    }
                    'extensionattribute13' {
                        $AdUser = @(Get-ADUser -filter {extensionattribute13 -eq $ID} @GetADUserParams)
                    }
                    'DistinguishedName' {
                        $AdUser = @(Get-ADUser -filter {DistinguishedName -eq $ID} @GetADUserParams)
                    }
                    'CanonicalName' {
                        $AdUser = @(Get-ADUser -filter {CanonicalName -eq $ID} @GetADUserParams)
                    }
                    'ObjectGUID' {
                        $AdUser = @(Get-ADUser -filter {ObjectGUID -eq $ID} @GetADUserParams)
                    }
                    'SID' {
                        $AdUser = @(Get-ADUser -filter {SID -eq $ID} @GetADUserParams)
                    }
                    'mS-DS-ConsistencyGuid' {
                        $ID = [byte[]]$ID.split(' ')
                        $AdUser = @(Get-ADUser -filter {mS-DS-ConsistencyGuid -eq $ID} @GetADUserParams)
                    }
                    'GivenNameSurName' {
                        $ADUser = @(Get-ADUser -Filter {GivenName -eq $GivenName -and Surname -eq $SurName} @GetADUserParams)
                    }
                    'employeeNumber' {
                        $AdUser = @(Get-ADUser -filter {employeeNumber -eq $ID}  @GetADUserParams)
                    }
                    'employeeID'{
                        $AdUser = @(Get-ADUser -filter {employeeID -eq $ID}  @GetADUserParams)
                    }
                }#switch
                Write-Log -Message "Succeeded: Get-ADUser with identifier $ID for Attribute $IdentityType" 
            }#try
            catch {
                Write-Log -Message "FAILED: Get-ADUser with identifier $ID for Attribute $IdentityType" -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                if ($ReportExceptions) {$Script:LookupADUserNotFound += $ID}
            }
            switch ($aduser.Count) {
                1 {
                    $TrimmedADUser = $ADUser | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                    Write-Output -InputObject $TrimmedADUser
                }#1
                0 {
                    if ($ReportExceptions) {$Script:LookupADUserNotFound += $ID}
                }#0
                Default {
                    if ($AmbiguousAllowed) {
                        $TrimmedADUser = $ADUser | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                        Write-Output -InputObject $TrimmedADUser    
                    }
                    else {
                        if ($ReportExceptions) {$Script:LookupADUserAmbiguous += $ID}
                    }
                }#Default
            }#switch
        }#foreach
    }#Process
    end {
        if ($ReportExceptions) {
            if ($Script:LookupADUserNotFound.count -ge 1) {
                Write-Log -Message 'Review logs or OneShell variable $LookupADUserNotFound for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Script:LookupADUserNotFound -join "`n`t")" -ErrorLog
            }#if
            if ($Script:LookupADUserAmbiguous.count -ge 1) {
                Write-Log -Message 'Review logs or OneShell variable $LookupADUserAmbiguous for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Script:LookupADUserAmbiguous -join "`n`t")" -ErrorLog
            }#if
        }#if
        if ($DoNotPreserveLocation -ne $true) {Pop-Location -StackName 'Lookup-ADUser'}#if
    }#end
}#Find-ADUser
function Find-ADContact
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true,valuefrompipeline = $true, valuefrompipelinebypropertyname = $true)]
        [string]$Identity
        ,
        [parameter(Mandatory  =$true)]
        [validateset('ProxyAddress','Mail','Name','extensionattribute5','extensionattribute11','extensionattribute13','DistinguishedName','CanonicalName','ObjectGUID','mS-DS-ConsistencyGuid')]
        $IdentityType
        ,

        [switch]$DoNotPreserveLocation #use this switch when you are already running the commands from the correct AD Drive
        ,
        $properties = $ADContactAttributes
        ,
        [switch]$AmbiguousAllowed
        ,
        [switch]$ReportExceptions
    )#param
    DynamicParam {
        $NewDynamicParameterParams=@{
            Name = 'ActiveDirectoryInstance'
            ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Select-Object -ExpandProperty Name)
            Alias = @('AD','Instance')
            Position = 2
        }
        $Dictionary = New-DynamicParameter @NewDynamicParameterParams
        Write-Output -InputObject $Dictionary
    }#DynamicParam
    Begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary        
        $ADInstance = $ActiveDirectoryInstance
        if ($DoNotPreserveLocation -ne $true) {Push-Location -StackName 'Find-ADContact'}
        try {
            #Write-Log -Message "Attempting: Set Location to AD Drive $("$ADInstance`:")" -Verbose
            Set-Location -Path $("$ADInstance`:") -ErrorAction Stop
            #Write-Log -Message "Succeeded: Set Location to AD Drive $("$ADInstance`:")" -Verbose
        }#try
        catch {
            Write-Log -Message "Succeeded: Set Location to AD Drive $("$ADInstance`:")" -ErrorLog
            Write-Log -Message $_.tostring() -ErrorLog
            $ErrorRecord = New-ErrorRecord -Exception 'System.Exception' -ErrorId ADDriveNotAvailable -ErrorCategory NotSpecified -TargetObject $ADInstance -Message 'Required AD Drive not available'
            $PSCmdlet.ThrowTerminatingError($ErrorRecord)
        }
        $GetADObjectParams = @{ErrorAction = 'Stop'}
        if ($properties.count -ge 1) {
            #Write-Log -Message "Using Property List: $($properties -join ",") with Get-ADObject"
            $GetADObjectParams.Properties = $Properties
        }
        if ($ReportExceptions) {
            $Script:LookupADContactNotFound = @()
            $Script:LookupADContactAmbiguous = @()
        }
    }#Begin
    Process {
        if ($IdentityType -eq 'mS-DS-ConsistencyGuid') {
            $Identity = $Identity -join ' '
        }
        foreach ($ID in $Identity) {
            try {
                Write-Log -Message "Attempting: Get-ADObject with identifier $ID for Attribute $IdentityType" 
                switch ($IdentityType) {
                    'ProxyAddress' {
                        #$wildcardID = "*$ID*"
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and proxyaddresses -like $ID} @GetADObjectParams)
                    }
                    'Mail' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and Mail -eq $ID}  @GetADObjectParams)
                    }
                    'extensionattribute5' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and extensionattribute5 -eq $ID} @GetADObjectParams)
                    }
                    'extensionattribute11' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and extensionattribute11 -eq $ID} @GetADObjectParams)
                    }
                    'extensionattribute13' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and extensionattribute13 -eq $ID} @GetADObjectParams)
                    }
                    'DistinguishedName' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and DistinguishedName -eq $ID} @GetADObjectParams)
                    }
                    'CanonicalName' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and CanonicalName -eq $ID} @GetADObjectParams)
                    }
                    'ObjectGUID' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and ObjectGUID -eq $ID} @GetADObjectParams)
                    }
                    'mS-DS-ConsistencyGuid' {
                        $ID = [byte[]]$ID.split(' ')
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and mS-DS-ConsistencyGuid -eq $ID} @GetADObjectParams)
                    }
                }#switch
                Write-Log -Message "Succeeded: Get-ADObject with identifier $ID for Attribute $IdentityType" 
            }#try
            catch {
                Write-Log -Message "FAILED: Get-ADObject with identifier $ID for Attribute $IdentityType" -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                if ($ReportExceptions) {$Script:LookupADContactNotFound += $ID}
            }
            switch ($ADContact.Count) {
                1 {
                    $TrimmedADObject = $ADContact | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                    Write-Output -InputObject $TrimmedADObject
                }#1
                0 {
                    if ($ReportExceptions) {$Script:LookupADContactNotFound += $ID}
                }#0
                Default {
                    if ($AmbiguousAllowed) {
                        $TrimmedADObject = $ADContact | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                        Write-Output -InputObject $TrimmedADObject    
                    }
                    else {
                        if ($ReportExceptions) {$Script:LookupADContactAmbiguous += $ID}
                    }
                }#Default
            }#switch
        }#foreach
    }#Process
    end {
        if ($ReportExceptions) {
            if ($Script:LookupADContactNotFound.count -ge 1) {
                Write-Log -Message 'Review logs or OneShell variable $LookupADObjectNotFound for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Script:LookupADContactNotFound -join "`n`t")" -ErrorLog
            }#if
            if ($Script:LookupADContactAmbiguous.count -ge 1) {
                Write-Log -Message 'Review logs or OneShell variable $LookupADObjectAmbiguous for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Script:LookupADContactAmbiguous -join "`n`t")" -ErrorLog
            }#if
        }#if
        if ($DoNotPreserveLocation -ne $true) {Pop-Location -StackName 'Find-ADContact'}#if
    }#end
}#Find-ADContact
function Get-AdObjectDomain
    {
        [cmdletbinding(DefaultParameterSetName='ADObject')]
        param
        (
            [parameter(Mandatory,ParameterSetName='ADObject')]
            [ValidateScript({Test-Member -InputObject $_ -Name CanonicalName})]
            $adobject
            ,
            [parameter(Mandatory,ParameterSetName='ExchangeObject')]
            [ValidateScript({Test-Member -InputObject $_ -Name Identity})]
            $ExchangeObject
        )
        switch ($PSCmdlet.ParameterSetName)
        {
            'ADObject'
            {[string]$domain=$adobject.canonicalname.split('/')[0]}
            'ExchangeObject'
            {[string]$domain=$ExchangeObject.Identity.split('/')[0]}
        }
        $domain
    }
#end function Get-ADObjectDomain
Function Get-ADAttributeSchema
{
  [cmdletbinding()]
  param
  (
    [parameter(Mandatory=$true,ParameterSetName = 'LDAPDisplayName')]
    [string]$LDAPDisplayName
    ,
    [parameter(Mandatory=$true,ParameterSetName = 'CommonName')]
    [string]$CommonName
    ,
    [string[]]$properties = @()
  )
  if (-not ((Test-ForInstalledModule -Name ActiveDirectory) -and (Test-ForImportedModule -Name ActiveDirectory))) 
  {throw "Module ActiveDirectory must be installed and imported to use $($MyInvocation.MyCommand)."}
  if ((Get-ADDrive).count -lt 1) {throw "An ActiveDirectory PSDrive must be connected to use $($MyInvocation.MyCommand)."}
  try
  {
    if (-not (Test-Path -path variable:script:LoggedOnUserActiveDirectoryForest))
    {$script:LoggedOnUserActiveDirectoryForest = Get-ADForest -Current LoggedOnUser -ErrorAction Stop}
  }
  catch
  {
    $_
    throw 'Could not find AD Forest'
  }
  $schemalocation = "CN=Schema,$($script:LoggedOnUserActiveDirectoryForest.PartitionsContainer.split(',',2)[1])"
  $GetADObjectParams = @{
    ErrorAction = 'Stop'
  }
  if ($properties.count -ge 1) {$GetADObjectParams.Properties = $properties}
  switch ($PSCmdlet.ParameterSetName) 
  {
    'LDAPDisplayName'
    {
        $GetADObjectParams.Filter = "lDAPDisplayName -eq `'$LDAPDisplayName`'"
        $GetADObjectParams.SearchBase = $schemalocation
    }
    'CommonName'
    {
        $GetADObjectParams.Identity = "CN=$CommonName,$schemalocation"
    }
  }
  try {
    $ADObjects = @(Get-ADObject @GetADObjectParams)
    if ($ADObjects.Count -eq 0)
    {Write-Warning -Message "Failed: Find AD Attribute with name/Identifier: $($LDAPDisplayName,$GetADObjectParams.Identity)"}
    else
    {
        Write-Output -InputObject $ADObjects[0]
    }
  }
  catch {
  }
}
function Get-ADAttributeRangeUpper
{
  [cmdletbinding()]
  param
  (
    [parameter(Mandatory=$true,ParameterSetName = 'LDAPDisplayName')]
    [string]$LDAPDisplayName
    ,
    [parameter(Mandatory=$true,ParameterSetName = 'CommonName')]
    [string]$CommonName
  )
  $GetADAttributeSchemaParams = @{
    ErrorAction = 'Stop'
    Properties = 'RangeUpper'
  }
  switch ($PSCmdlet.ParameterSetName) 
  {
    'LDAPDisplayName'
    {
        $GetADAttributeSchemaParams.lDAPDisplayName = $LDAPDisplayName
    }
    'CommonName'
    {
        $GetADAttributeSchemaParams.CommonName = $CommonName
    }
  }
  try
  {
    $AttributeSchema = @(Get-ADAttributeSchema @GetADAttributeSchemaParams)
    if ($AttributeSchema.Count -eq 1)
    {
        if ($AttributeSchema[0].RangeUpper -eq $null) {Write-Output -InputObject 'Unlimited'}
        else {Write-Output -InputObject $AttributeSchema[0].RangeUpper}
    }
    else
    {
        Write-Warning -Message 'AD Attribute Not Found'
    }
  }
  catch
  {
    $myerror = $_
    Write-Error $myerror
  }
}
function Get-XADUserPasswordExpirationDate() {
    
        Param ([Parameter(Mandatory,  Position=0,  ValueFromPipeline, HelpMessage='Identity of the Account')]
    
         $accountIdentity)
    
        PROCESS {
    
            $accountObj = Get-ADUser -Identity $accountIdentity -Properties PasswordExpired, PasswordNeverExpires, PasswordLastSet
    
            if ($accountObj.PasswordExpired) {
    
                Write-Output -InputObject $('Password of account: ' + $accountObj.Name + ' already expired!')
    
            } else { 
    
                if ($accountObj.PasswordNeverExpires) {
    
                    Write-Output -InputObject $('Password of account: ' + $accountObj.Name + ' is set to never expires!')
    
                } else {
    
                    $passwordSetDate = $accountObj.PasswordLastSet
    
                    if ($passwordSetDate -eq $null) {
    
                        Write-Output -InputObject $('Password of account: ' + $accountObj.Name + ' has never been set!')
    
                    }  else {
    
                        $maxPasswordAgeTimeSpan = $null
    
                        $dfl = (get-addomain).DomainMode
    
                        if ($dfl -ge 3) { 
    
                            ## Greater than Windows2008 domain functional level
    
                            $accountFGPP = Get-ADUserResultantPasswordPolicy $accountObj
    
                            if ($accountFGPP -ne $null) {
    
                                $maxPasswordAgeTimeSpan = $accountFGPP.MaxPasswordAge
    
                            } else {
    
                                $maxPasswordAgeTimeSpan = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
    
                            }
    
                        } else {
    
                            $maxPasswordAgeTimeSpan = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge
    
                        }
    
                        if ($maxPasswordAgeTimeSpan -eq $null -or $maxPasswordAgeTimeSpan.TotalMilliseconds -eq 0) {
    
                            Write-Output -InputObject $('MaxPasswordAge is not set for the domain or is set to zero!')
    
                        } else {
    
                            Write-Output -InputObject $('Password of account: ' + $accountObj.Name + ' expires on: ' + ($passwordSetDate + $maxPasswordAgeTimeSpan))
    
                        }
    
                    }
    
                }
    
            }
    
        }
    
    }
    function Get-ADRecipientObject {
      [cmdletbinding()]
      param
      (
        [int]$ResultSetSize = 10000
        ,
        [switch]$Passthrough
        ,
        [switch]$ExportData
        ,
        [parameter(Mandatory=$true)]
        $ADInstance
      )
        Set-Location -Path "$($ADInstance):\"
        $AllGroups = Get-ADGroup -ResultSetSize $ResultSetSize -Properties @($AllADAttributesToRetrieve + 'Members') -Filter * | Select-Object -Property * -ExcludeProperty Property*,Item
        $AllMailEnabledGroups = $AllGroups | Where-Object -FilterScript {$_.legacyExchangeDN -ne $NULL -or $_.mailNickname -ne $NULL -or $_.proxyAddresses -ne $NULL}
        $AllContacts = Get-ADObject -Filter {objectclass -eq 'contact'} -Properties $AllADContactAttributesToRetrieve -ResultSetSize $ResultSetSize | Select-Object -Property * -ExcludeProperty Property*,Item
        $AllMailEnabledContacts = $AllContacts | Where-Object -FilterScript {$_.legacyExchangeDN -ne $NULL -or $_.mailNickname -ne $NULL -or $_.proxyAddresses -ne $NULL}
        $AllUsers = Get-ADUser -ResultSetSize $ResultSetSize -Filter * -Properties $AllADAttributesToRetrieve | Select-Object -Property * -ExcludeProperty Property*,Item
        $AllMailEnabledUsers = $AllUsers  | Where-Object -FilterScript {$_.legacyExchangeDN -ne $NULL -or $_.mailNickname -ne $NULL -or $_.proxyAddresses -ne $NULL}
        $AllPublicFolders = Get-ADObject -Filter {objectclass -eq 'publicFolder'} -ResultSetSize $ResultSetSize -Properties $AllADAttributesToRetrieve | Select-Object -Property * -ExcludeProperty Property*,Item
        $AllMailEnabledPublicFolders = $AllPublicFolders  | Where-Object -FilterScript {$_.legacyExchangeDN -ne $NULL -or $_.mailNickname -ne $NULL -or $_.proxyAddresses -ne $NULL}
        $AllMailEnabledADObjects = $AllMailEnabledGroups + $AllMailEnabledContacts + $AllMailEnabledUsers + $AllMailEnabledPublicFolders
        if ($Passthrough) {$AllMailEnabledADObjects}
        if ($ExportData) {Export-Data -DataToExport $AllMailEnabledADObjects -DataToExportTitle 'AllADRecipientObjects' -Depth 3 -DataType xml}
    }
    Function Get-QualifiedADUserObject
    {
      [cmdletbinding()]
      param(
        [parameter(Mandatory)]
        [string]$ActiveDirectoryInstance
        ,
        [string]$LDAPFilter
        #'(&(sAMAccountType=805306368)(proxyAddresses=SMTP:*)(extensionattribute15=DirSync))'
        #'(&((sAMAccountType=805306368))(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        ,
        [string[]]$Properties = $script:ADUserAttributes
      )
      #Retrieve all qualified (per the filter)AD User Objects including the specified properties
      Write-StartFunctionStatus -CallingFunction $MyInvocation.MyCommand
      #Connect-ADInstance -ActiveDirectoryInstance $ActiveDirectoryInstance -ErrorAction Stop > $null
      Set-Location -Path "$($ActiveDirectoryInstance):\"
      $GetADUserParams = @{
        ErrorAction = 'Stop'
        Properties = $Properties
      }
      if ($PSBoundParameters.ContainsKey('LDAPFilter'))
      {
        $GetADUserParams.LDAPFilter = $LDAPFilter
      }
      else
      {
        $GetADUserParams.Filter = '*'
      }
      Try
      {
        $message ='Retrieve qualified Active Directory User Accounts.'
        Write-Log -verbose -message $message -EntryType Attempting
        $QualifiedADUsers = @(Get-ADUser @GetADUserParams | Select-Object -Property $Properties)
        $message = $message + " Count:$($QualifiedADUsers.count)"
        Write-Log -verbose -message $message -EntryType Succeeded
        Write-Output -InputObject $QualifiedADUsers
      }
      Catch
      {
        $myerror = $_
        Write-Log -Message 'Active Directory user objects could not be retrieved.' -ErrorLog -Verbose
        Write-Log -Message $myerror.tostring() -ErrorLog
      }
      Write-EndFunctionStatus $MyInvocation.MyCommand
    }#Get-QualifiedADUserObject
    Function Get-ADDomainNetBiosName
    {
      [cmdletbinding()]
      param(
        [parameter(ValueFromPipeline,Mandatory)]
        [string[]]$DNSRoot
      )
      #If necessary, create the script:ADDomainDNSRootToNetBiosNameHash
      if (-not (Test-Path variable:script:ADDomainDNSRootToNetBiosNameHash))
      {
        $script:ADDomainDNSRootToNetBiosNameHash = @{}
      }
      #Lookup the NetBIOSName for the domain in the script:ADDomainDNSRootToNetBiosNameHash
      if ($script:ADDomainDNSRootToNetBiosNameHash.containskey($DNSRoot))
      {
        $NetBiosName = $script:ADDomainDNSRootToNetBiosNameHash.$DNSRoot
      }
      #or lookup the NetBIOSName from AD and add it to the script:ADDomainDNSRootToNetBiosNameHash
      else
      {
        try
        {
            $message = "Look up $DNSRoot NetBIOSName for the first time."
            Write-Log -Message $message -EntryType Attempting
            $NetBiosName = Get-ADDomain -Identity $DNSRoot -ErrorAction Stop | Select-Object -ExpandProperty NetBIOSName
            $script:ADDomainDNSRootToNetBiosNameHash.$DNSRoot = $NetBiosName
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $myerror = $_
            Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror)
        }
      }
      #Return the NetBIOSName
      Write-Output $NetBiosName
    }#Get-ADDomainNetBiosName