# Getting Started With OneShell

## <a name="TOC"></a>Table Of Contents
- [Setting Up The Module](#SettingUp)
- [Creating And Populating the Org Profile](#CreatingOrgProfile)
- [Creating And Populating the AdminUser Profile](#CreatingAdminUserProfile)
- [Importing And Using Your Connections](#ImportingAndUsing)
## <a name="SettingUp"></a>Setting Up The Module
###### [Back to Table of Contents](#TOC)
In order to use OneShell effectively, you'll need to have the module files stored in a place where you can import them easily. If you're already familiar with administering PowerShell Modules, you can ignore this paragraph. If you're not, perhaps the best place to put them is in $env:USERPROFILE\Documents\WindowsPowerShell\Modules. On a vanilla Windows installation, this will be c:\users\<username>\Documents\WindowsPowerShell\Modules. The WindowsPowerShell and Modules folders will not exist. You can create them.

Once you've decided where to store the module, you can either download it by clicking the Download button or clone the repo using git. Either way, you should end up with a folder named OneShell underneath the Modules folder, and you'll be ready to go!

- To get started, open PowerShell.
- Import the module by issuing this cmdlet. If you get warnings about script signing or execution, follow the instructions provided or search the internet for the required instructions to get your computer ready to run downloaded PowerShell code. I won't re-invent the wheel by documenting those steps here.
```PowerShell
Import-Module -Name OneShell
```
- Tell OneShell Where it should store _orgnization_ profiles. This will be $env:ProgramData\OneShell by default. You can add a -Path parameter to the below cmdlet if you want to store them somewhere else. By default, $env:ProgramData\OneShell will still be created and will be used to tell OneShell where to find your org profiles for future imports of the OneShell module. If you don't have Admin rights on the workstation you're installing on, you can specify -Scope User to store them in $env:LOCALAPPDATA\OneShell. _If you do not want to persist this storage location at all, you can specify -DoNotPersist. If you do not persist this storage location, you'll need to run Set-OneShellOrgProfileDirectory every time you/your script imports OneShell._
```PowerShell
Set-OneShellOrgProfileDirectory
```
- Tell OneShell Where it should store _admin user_ profiles. This will be $env:\localappdata\OneShell by default. You can add a -Path parameter to the below cmdlet if you want to store them somewhere else. By default, $env:\localappdata\OneShell will still be created and will be used to tell OneShell where to find your admin user profiles for future imports of the OneShell module. _If you do not want to persist this storage location at all, you can specify -DoNotPersist. If you do not persist this storage location, you'll need to run Set-OneShellAdminUserProfileDirectory every time you/your script imports OneShell._
```PowerShell
Set-OneShellAdminUserProfileDirectory
```
## <a name="CreatingOrgProfile"></a>Creating And Populating The Org Profile
###### [Back to Table of Contents](#TOC)
- Create an empty Organization Profile. The Org Profile is where all of your systems to be administered will be configured. The Org profile can be shared by multiple admin user profiles in one or more user accounts, so you don't have to define the same systems to be administered multiple times. 
```PowerShell
New-OrgProfile -Name DemoOrg
```
- If you'd like to see what the created profile object looks like, you can issue
```PowerShell
Get-OrgProfile -Identity DemoOrg
```
- Add systems that you want to administer to the Org Profile. Here are examples using a few common ServiceTypes.
```PowerShell
New-OrgProfileSystem -Name DemoOrgExchangeOnline -Description "DemoOrg's Exchange Online Tenant" -ServiceType ExchangeOnline -CommandPrefix OL -ProfileIdentity DemoOrg
New-OrgProfileSystem -Name DemoOrgExchangeOnPremises -ServiceType ExchangeOnPremises -CommandPrefix OP -ProfileIdentity DemoOrg
New-OrgProfileSystem -Name DemoOrgAzureAD -ServiceType AzureAD -ProfileIdentity DemoOrg -TenantSubDomain DemoOrg
New-OrgProfileSystem -Name MyAppServer -ServiceType PowerShell -SessionManagementGroups AppServers -ProfileIdentity DemoOrg
```
- Now add system endpoints where that is needed (it's not needed for the Exchange Online connection but for all the others in the examples above it is needed). System endpoints define the endpoint against which connections to this system should be initiated. Multiple endpoints can be defined against a single system which can be helpful for fault tolerance or for specific tasks (e.g. set mailbox settings for an APAC user against an APAC Exchange server endpoint to avoid having to wait for domain controller replication). 
```PowerShell
New-OrgProfileSystemEndpoint -SystemIdentity MyAppServer -ServiceType PowerShell -AddressType FQDN -Address appserver.contoso.com -ProfileIdentity DemoOrg
New-OrgProfileSystemEndpoint -SystemIdentity DemoOrgExchangeOnPremises -ServiceType ExchangeOnPremises -ProfileIdentity DemoOrg -AddressType FQDN -Address usgvlve1401.contoso.com
New-OrgProfileSystemEndpoint -SystemIdentity DemoOrgAzureAD -ServiceType AzureAD -AddressType FQDN -Address localhost -ProfileIdentity DemoOrg
```
## <a name="CreatingAdminUserProfile"></a>Creating And Populating the AdminUser Profile
###### [Back to Table of Contents](#TOC)
- Next, create an admin user profile which is associated with the org profile above. The ProfileFolder is where the logs, exports, and import files will be stored. If this folder doesn't exist, you'll need to create it manually. OneShell will create subfolders underneath it. Remember, the admin user profile is user specific and stores the credentials, preferred endpoints, and other settings used to connect to the systems defined in the (potentially) shared org profile. The MailFromSMTPAddress is used if you use any of the built-in email sending functions of OneShell. OrgProfileIdentity will offer auto-complete values.
```PowerShell
New-AdminUserProfile -ProfileFolder C:\Users\demouser\OneShell -MailFromSMTPAddress demouser@contoso.com -orgprofileidentity DemoOrg
```
- Repeat the below for each credential you want to add. The ProfileIdentity will offer auto-complete values. 
```PowerShell
New-AdminUserProfileCredential -Username demouser@contoso.com -ProfileIdentity DemoOrg-demouser-USGVLW10DESKDU
```
- Repeat the below for each system with which you want to associate a credential. The ProfileIdentity will offer auto-complete values. Select the system and credential you wish to link. You'll need to perform this step multiple times in order to link each system to which you want to connect with a credential you've defined. 
```PowerShell
Set-AdminUserProfileSystemCredential -ProfileIdentity DemoOrg-demouser-USGVLW10DESKDU
```
- Set one or more of your systems to import the PS Session automatically when connected. _The automatic importing will import prefixed cmdlets (if you chose a prefix for the system) into your shell. If you don't set this, you'll either have to import the sessions later, or you'll have to use Invoke-Command to pass cmdlets into the session, or you'll have to use Enter-PSSession to enter the sessions one at a time._ Choose the Admin profile, system, and endpoint, if applicable, when prompted.
```PowerShell
Set-AdminUserProfileSystem -AutoImport:$true
```
- This cmdlet load the admin profile you've been editing into memory for immediate use. The identity parameter should offer auto-complete values.
```PowerShell
Use-AdminUserProfile -Identity DemoOrg-demouser-USGVLW10-DESKMC
```
## <a name="ImportingAndUsing"></a>Importing And Using Your Connections
###### [Back to Table of Contents](#TOC)
- Connect to a system. Identity will offer auto-complete values. If you chose, above, to import automatically, the PSSession will be imported automatically.
```PowerShell
Connect-OneShellSystem -identity DemoOrgExchangeOnline
```
- Issue a command via invoke-command.
```PowerShell
Invoke-Command -Session (Get-OneShellSystemPSSession -Identity DemoOrgExchangeOnline) -ScriptBlock {Get-Mailbox -ResultSize 5}
```
- Issue a command via imported session with prefixed cmdlet.
```PowerShell
Get-OLMailbox -ResultSize 5
```
- Connect-OneShellSystem will check for an existing connection and test for a functional connection before establishing a connection. As such, it can be used as a test to confirm a connection has not timed out for unattended operations. Below, we use Connect-OneShellSystem as a test (it returns true when it's able to establish an effective connection) and also force a reconnection with the Reconnect switch if a failed connection is not automatically repaired.
```PowerShell
$Statistics = @(
 Foreach ($Mailbox in (Get-OLMailbox -ResultSize Unlimited) {
    If (-Not (Connect-OneShellSystem -identity DemoOrgExchangeOnline)) {
      Connect-OneShellSystem -identity DemoOrgExchangeOnline -Reconnect
     }
    Get-OLMailboxStatistics -Identity $Mailbox.DistinguishedName 
    }
)
```
