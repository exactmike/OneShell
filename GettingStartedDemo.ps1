#This file will show how to configure a new organization and admin user profile from the command line
Import-Module -Name OneShell
New-OrgProfile -Name DemoOrg
#if you want to verify that this did something
Get-OrgProfile -Identity DemoOrg
#now add systems that you want to administer to the Org Profile
New-OrgProfileSystem -Name DemoOrgExchangeOnline -Description "DemoOrg's Exchange Online Tenant" -ServiceType ExchangeOnline -ProfileIdentity DemoOrg
New-OrgProfileSystem -Name DemoOrgExchangeOnPremises -ServiceType ExchangeOnPremises -CommandPrefix OP -ProfileIdentity DemoOrg
New-OrgProfileSystem -Name DemoOrgAzureAD -ServiceType AzureAD -ProfileIdentity DemoOrg -TenantSubDomain DemoOrg
New-OrgProfileSystem -Name MyAppServer -ServiceType PowerShell -SessionManagementGroups AppServers -ProfileIdentity DemoOrg
#now add system endpoints where that is needed (it's not needed for the Exchange Online connection but for all the others in the examples above it is needed)
New-OrgProfileSystemEndpoint -SystemIdentity MyAppServer -ServiceType PowerShell -AddressType FQDN -Address appserver.contoso.com -ProfileIdentity DemoOrg
New-OrgProfileSystemEndpoint -SystemIdentity DemoOrgExchangeOnPremises -ServiceType ExchangeOnline -ProfileIdentity DemoOrg -AddressType FQDN -Address usgvlve1401.contoso.com
New-OrgProfileSystemEndpoint -SystemIdentity DemoOrgAzureAD -ServiceType AzureAD -AddressType FQDN -Address localhost -ProfileIdentity DemoOrg
#next create an admin user profile which is associated with the org profile above
New-AdminUserProfile -ProfileFolder C:\Users\demouser\OneShell -MailFromSMTPAddress demouser@contoso.com -orgprofileidentity DemoOrg
#repeat below for each credential you want to add
New-AdminUserProfileCredential -Username demouser@contoso.com -ProfileIdentity DemoOrg-demouser-USGVLW10DESKDU
#repeat below for each system with which you want to associate a credential -profile identity parameter should offer auto complete values
Set-AdminUserProfileSystemCredential -ProfileIdentity DemoOrg-demouser-USGVLW10DESKDU

#use your profile - identity parameter should offer autocomplete valuses
Use-AdminUserProfile -Identity DemoOrg-demouser-USGVLW10-DESKMC

#connect to a system - no PSSession import is configured yet . . . just establishment and initialization - Identity will offer auto complete values
Connect-OneShellSystem -identity DemoOrgAzureAD
