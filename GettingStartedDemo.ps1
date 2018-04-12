#This file will show how to configure a new organization and User Profile from the command line
Import-Module -Name OneShell
#Tell OneShell Where it should store orgnization profiles. This will be $env:\programdata\OneShell by default. You can add a -Path parameter to the below cmdlet if you want to store them somewhere else. By default, $env:\programdata\OneShell will still be created and will be used to tell OneShell where to find your org profiles. If you don't have administrator rights on the workstation you're installing on, you can specify -Scope User to store them in $env:localappdata\OneShell. If you do not want to persist this storage location at all, you can specify -DoNotPersist.
Set-OneShellOrgProfileDirectory
#Tell OneShell Where it should store User Profiles. This will be $env:\localappdata\OneShell by default. You can add a -Path parameter to the below cmdlet if you want to store them somewhere else. By default, $env:\localappdata\OneShell will still be created and will be used to tell OneShell where to find your User Profiles. If you do not want to persist this storage location at all, you can specify -DoNotPersist.
Set-OneShellUserProfileDirectory
New-OneShellOrgProfile -Name DemoOrg
#if you want to verify that this did something
Get-OneShellOrgProfile -Identity DemoOrg
#now add systems that you want to administer to the Org Profile
New-OneShellOrgProfileSystem -Name DemoOrgExchangeOnline -Description "DemoOrg's Exchange Online Tenant" -ServiceType ExchangeOnline -CommandPrefix OL -ProfileIdentity DemoOrg
New-OneShellOrgProfileSystem -Name DemoOrgExchangeOnPremises -ServiceType ExchangeOnPremises -CommandPrefix OP -ProfileIdentity DemoOrg
New-OneShellOrgProfileSystem -Name DemoOrgAzureAD -ServiceType AzureAD -ProfileIdentity DemoOrg -TenantSubDomain DemoOrg
New-OneShellOrgProfileSystem -Name MyAppServer -ServiceType PowerShell -SessionManagementGroups AppServers -ProfileIdentity DemoOrg
#now add system endpoints where that is needed (it's not needed for the Exchange Online connection but for all the others in the examples above it is needed)
New-OneShellOrgProfileSystemEndpoint -SystemIdentity MyAppServer -ServiceType PowerShell -AddressType FQDN -Address appserver.contoso.com -ProfileIdentity DemoOrg
New-OneShellOrgProfileSystemEndpoint -SystemIdentity DemoOrgExchangeOnPremises -ServiceType ExchangeOnPremises -ProfileIdentity DemoOrg -AddressType FQDN -Address usgvlve1401.contoso.com
New-OneShellOrgProfileSystemEndpoint -SystemIdentity DemoOrgAzureAD -ServiceType AzureAD -AddressType FQDN -Address localhost -ProfileIdentity DemoOrg
#next create an User Profile which is associated with the org profile above. The ProfileFolder is where the logs, exports, and import files will be stored. If this folder doesn't exist, you'll need to create it.
New-OneShellUserProfile -ProfileFolder C:\Users\demouser\OneShell -MailFromSMTPAddress demouser@contoso.com -OneShellOrgProfileidentity DemoOrg
#repeat below for each credential you want to add. The ProfileIdentity will offer auto-complete values.
New-OneShellUserProfileCredential -Username demouser@contoso.com -ProfileIdentity DemoOrg-demouser-USGVLW10DESKDU
#repeat below for each system with which you want to associate a credential -profile identity parameter should offer auto complete values
Set-OneShellUserProfileSystemCredential -ProfileIdentity DemoOrg-demouser-USGVLW10DESKDU
#Set your one of your systems to import the PS Session automatically when connected. Choose the user profile, system, and endpoint, if applicable, when prompted.
Set-OneShellUserProfileSystem -AutoImport:$true
#use your profile - identity parameter should offer autocomplete values. This cmdlet will load the user profile you've been editing into memory for immediate use.
Use-OneShellUserProfile -Identity DemoOrg-demouser-USGVLW10-DESKMC

#connect to a system. Identity will offer auto complete values. If you chose, above, to import automatically, the PSSession will be imported automatically.
Connect-OneShellSystem -identity DemoOrgExchangeOnline

#Issue a command via invoke-command
invoke-command -Session (Get-OneShellSystemPSSession -Identity DemoOrgExchangeOnline) -ScriptBlock {Get-Mailbox -ResultSize 5}
#Issue a command via imported session with prefixed cmdlet
Get-OLMailbox -ResultSize 5
