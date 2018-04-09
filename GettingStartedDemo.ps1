#This file will show how to configure a new organization and admin user profile from the command line
Import-Module -Name OneShell
New-OrgProfile -Name DemoOrg
#if you want to verify that this did something
Get-OrgProfile -Identity DemoOrg
#now add systems that you want to administer to the Org Profile
New-OrgProfileSystem -Name DemoOrgExchangeOnline -Description "DemoOrg's Exchange Online Tenant" -ServiceType ExchangeOnline -CommandPrefix OL -ProfileIdentity DemoOrg
New-OrgProfileSystem -Name DemoOrgExchangeOnPremises -ServiceType ExchangeOnPremises -CommandPrefix OP -ProfileIdentity DemoOrg
New-OrgProfileSystem -Name DemoOrgAzureAD -ServiceType AzureAD -ProfileIdentity DemoOrg -TenantSubDomain DemoOrg
New-OrgProfileSystem -Name MyAppServer -ServiceType PowerShell -SessionManagementGroups AppServers -ProfileIdentity DemoOrg
#now add system endpoints where that is needed (it's not needed for the Exchange Online connection but for all the others in the examples above it is needed)
New-OrgProfileSystemEndpoint -SystemIdentity MyAppServer -ServiceType PowerShell -AddressType FQDN -Address appserver.contoso.com -ProfileIdentity DemoOrg
New-OrgProfileSystemEndpoint -SystemIdentity DemoOrgExchangeOnPremises -ServiceType ExchangeOnPremises -ProfileIdentity DemoOrg -AddressType FQDN -Address usgvlve1401.contoso.com
New-OrgProfileSystemEndpoint -SystemIdentity DemoOrgAzureAD -ServiceType AzureAD -AddressType FQDN -Address localhost -ProfileIdentity DemoOrg
#next create an admin user profile which is associated with the org profile above. The ProfileFolder is where the logs, exports, and import files will be stored. If this folder doesn't exist, you'll need to create it.
New-AdminUserProfile -ProfileFolder C:\Users\demouser\OneShell -MailFromSMTPAddress demouser@contoso.com -orgprofileidentity DemoOrg
#repeat below for each credential you want to add. The ProfileIdentity will offer auto-complete values.
New-AdminUserProfileCredential -Username demouser@contoso.com -ProfileIdentity DemoOrg-demouser-USGVLW10DESKDU
#repeat below for each system with which you want to associate a credential -profile identity parameter should offer auto complete values
Set-AdminUserProfileSystemCredential -ProfileIdentity DemoOrg-demouser-USGVLW10DESKDU
#Set your one of your systems to import the PS Session automatically when connected. Choose the Admin profile, system, and endpoint, if applicable, when prompted.
Set-AdminUserProfileSystem -AutoImport:$true
#use your profile - identity parameter should offer autocomplete values. This cmdlet load the admin profile you've been editing into memory for immediate use.
Use-AdminUserProfile -Identity DemoOrg-demouser-USGVLW10-DESKMC

#connect to a system. Identity will offer auto complete values. If you chose, above, to import automatically, the PSSession will be imported automatically.
Connect-OneShellSystem -identity DemoOrgExchangeOnline

#Issue a command via invoke-command
invoke-command -Session (Get-OneShellSystemPSSession -Identity DemoOrgExchangeOnline) -ScriptBlock {Get-Mailbox -ResultSize 5}
#Issue a command via imported session with prefixed cmdlet
Get-OLMailbox -ResultSize 5
