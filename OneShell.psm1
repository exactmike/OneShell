#!/usr/bin/env pwsh
##########################################################################################################
#Module Variables and Variable Functions
##########################################################################################################
function SetOneShellVariables
{
    [cmdletbinding()]
    Param()
    #Write-OneShellLog -message 'Setting OneShell Module Variables'
    $Script:OneShellModuleFolderPath = $PSScriptRoot #Split-Path $((Get-Module -ListAvailable -Name OneShell).Path)
    GetOneShellOrgProfileDirectory
    GetOneShellUserProfileDirectory
    $Script:LogPreference = $True
    #AdvancedOneShell needs updated for the following:
    $Script:ScalarADAttributes = @(
        'altRecipient'
        'c'
        'CanonicalName'
        'city'
        'cn'
        'co'
        'country'
        'company'
        'deliverandRedirect'
        'department'
        'displayName'
        'DistinguishedName'
        'employeeID'
        'employeeNumber'
        'enabled'
        'extensionattribute1'
        'extensionattribute10'
        'extensionattribute11'
        'extensionattribute12'
        'extensionattribute13'
        'extensionattribute14'
        'extensionattribute15'
        'extensionattribute2'
        'extensionattribute3'
        'extensionattribute4'
        'extensionattribute5'
        'extensionattribute6'
        'extensionattribute7'
        'extensionattribute8'
        'extensionattribute9'
        'forwardingAddress'
        'GivenName'
        'homeMDB'
        'homeMTA'
        'legacyExchangeDN'
        'Mail'
        'mailNickname'
        'mS-DS-ConsistencyGuid'
        'msExchArchiveGUID'
        'msExchArchiveName'
        'msExchGenericForwardingAddress'
        'msExchHideFromAddressLists'
        'msExchHomeServerName'
        'msExchMailboxGUID'
        'msExchMasterAccountSID'
        'msExchRecipientDisplayType'
        'msExchRecipientTypeDetails'
        'msExchRemoteRecipientType'
        'msExchUsageLocation'
        'msExchUserCulture'
        'msExchVersion'
        'msExchWhenMailboxCreated'
        'notes'
        'ObjectGUID'
        'physicalDeliveryOfficeName'
        'SamAccountName'
        'SurName'
        'targetAddress'
        'userPrincipalName'
        'whenChanged'
        'whenCreated'
        'AccountExpirationDate'
        'LastLogonDate'
        'createTimeStamp'
        'modifyTimeStamp'
    )#Scalar Attributes to Retrieve
    $Script:MultiValuedADAttributes = @(
        'memberof'
        'msexchextensioncustomattribute1'
        'msexchextensioncustomattribute2'
        'msexchextensioncustomattribute3'
        'msexchextensioncustomattribute4'
        'msexchextensioncustomattribute5'
        'msExchPoliciesExcluded'
        'proxyAddresses'
    )#MultiValuedADAttributesToRetrieve
    $Script:ADUserAttributes = @($script:ScalarADAttributes + $Script:MultiValuedADAttributes)
    $Script:ADContactAttributes = @('CanonicalName', 'CN', 'Created', 'createTimeStamp', 'Deleted', 'Description', 'DisplayName', 'DistinguishedName', 'givenName', 'instanceType', 'internetEncoding', 'isDeleted', 'LastKnownParent', 'legacyExchangeDN', 'mail', 'mailNickname', 'mAPIRecipient', 'memberOf', 'Modified', 'modifyTimeStamp', 'msExchADCGlobalNames', 'msExchALObjectVersion', 'msExchPoliciesExcluded', 'Name', 'ObjectCategory', 'ObjectClass', 'ObjectGUID', 'ProtectedFromAccidentalDeletion', 'proxyAddresses', 'showInAddressBook', 'sn', 'targetAddress', 'textEncodedORAddress', 'uSNChanged', 'uSNCreated', 'whenChanged', 'whenCreated')
    $Script:ADGroupAttributes = $Script:ADUserAttributes |  Where-Object {$_ -notin ('surName', 'country', 'homeMDB', 'homeMTA', 'msExchHomeServerName','city')}
    $Script:ADPublicFolderAttributes = $Script:ADUserAttributes |  Where-Object {$_ -notin ('surName', 'country', 'homeMDB', 'homeMTA', 'msExchHomeServerName')}
    $Script:ADGroupAttributesWMembership = $Script:ADGroupAttributes + 'Members'
    $Script:Stamp = GetTimeStamp
    ##########################################################################################################
    #Import settings from json files
    ##########################################################################################################
    $Script:ServiceTypes = import-JSON -Path (Join-Path $PSScriptRoot ServiceTypes.json) -ErrorAction Stop | Select-Object -ExpandProperty ServiceTypes -ErrorAction Stop
}
#end function Set-OneShellVariables
##########################################################################################################
#Import functions from included ps1 files
##########################################################################################################
#. $(Join-Path $PSScriptRoot 'ProfileWizardFunctions.ps1')
. $(Join-Path $PSScriptRoot 'UtilityFunctions.ps1')
. $(Join-Path $PSScriptRoot 'UserInputFunctions.ps1')
. $(Join-Path $PSScriptRoot 'SystemConnectionFunctions.ps1')
. $(Join-Path $PSScriptRoot 'ProfileFunctions.ps1')
. $(Join-Path $PSScriptRoot 'TestFunctions.ps1')
. $(Join-Path $PSScriptRoot 'SkypeOnline.ps1')
. $(Join-Path $PSScriptRoot 'ParameterFunctions.ps1')
. $(Join-Path $PSScriptRoot 'LoggingFunctions.ps1')
. $(Join-Path $PSScriptRoot 'VariableFunctions.ps1')
. $(Join-Path $PSScriptRoot 'RegisterArgumentCompleter.ps1')
##########################################################################################################
#Initialization
##########################################################################################################
SetOneShellVariables
