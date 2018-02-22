# To Do Items

- [ ] Write GUI/Wizard Functions for Org and Admin Profile Creation
- [ ] Admin Profile Editing/Creation GUI improvements (compared to the old one that is deprecated): List view for per system configuration like: system, credential (in drop down?), autoconnect check box, autoimport check box
- [ ] Enable pipelined and/or bulk editing of profile elements (systems, endpoints, credentials, etc.)
- [ ] update SkypeForBusinessOnline connection test command to Get-CSTenant?
- [ ] Update Azure AD connection test command to Get-AzureADCurrentSessionInfo?
- [ ] Finish SQL ServiceType support (initialization)
- [ ] Add LotusNotesDatabase ServiceType support
- [ ] Add Exchange 2007 ServiceType support
- [ ] Add MigrationWiz/BitTitan ServiceType Support
- [ ] Add Azure AD RMS ServiceType Support <https://docs.microsoft.com/en-us/information-protection/deploy-use/install-powershell>
- [ ] Add Non-PSRemoting Service Attribute and Connection support
- [x] Add auto-connect of AutoConnect Service types with Use-AdminUserProfile unless suppressed by -NoAutoConnect
- [x] Add suppression of auto Import with -NoAutoImport on Connect-OneShellSystem and Use-AdminUserProfile
- [ ] modify test-directorysynchronization to use Azure AD test as an option and to use non-recipient exchange objects
- [ ] create a Write-Progress helper function for showing progress every nth record, showing time to completion, making the experience more consistent across functions, etc.
- [ ] Follow <http://semver.org/> for Versioning
- [ ] Clean up PSSessions when switching Admin or Org Profiles with Use-*Profile functions
- [ ] Remove imported modules from session when re-connecting to a System
- [ ] Add Clean Up Code for Sessions, imported modules, and the handful of global variables oneshell might create with the module's onremove capability: <https://stackoverflow.com/questions/24475572/restoring-a-powershell-alias-when-a-module-is-unloaded>
- [x] Improve CommandPrefix configurations with profiles - allow NULL or blank
- [ ] Add sophisticated CommandPrefix validation for org and admin profile systems new and set functions (check for duplicate prefixes or nulls across the same service type or overlapping service types)
- [ ] Make parameters which ask for a computer consistently named ComputerName?
- [ ] Convert Write-Log to use System.IO.FileStream . . . 
- [ ] Does $PSSenderInfo have any use cases for OneShell
- [ ] Consider/Test Using $PSModuleAutoloadingPreference = 'none' when creating PSSessions for types of systems other than PowerShell
- [ ] Endpoint prevented from being added to ComplianceCenter and ExchangeOnline types . . . ? no, but warn instead (in progress) (From Joe S)
- [ ] spin off parameter functions to a separate module


## AAD Connect Improvements

- [ ] add function to report AADConnect/AADSync status - that is, if a synchronization is in progress, what kind of sync it is and when it started. (<http://www.anexinet.com/blog/scripting-a-manual-dirsync-with-powershell-in-azure-ad-connect-v-1-1/>)
- [ ] add function to export connectors, disconnectors, etc. from connector spaces for validation of new AAD Connect instances (In Progress)

## Bugs/Known Issues

- [ ] If you use a non-valid dynamic parameter name with New-OrgProfileSystem (and perhaps other commands) you'll get a non-helpful error about postitional parameters "Cannot bind positional parameters because no names were given."
- [ ] Set-OrgProfileSystemEndpoint does not work to update an endpoint address
- [ ] Need to implement SessionManagementGroups logic to create and update/manage the group variables (partially complete - need to integrate connection removals as well)
- [ ] Need to add explicit loading of required module to establish PSSession for special cases (like SkypeForBusinessOnline)
- [ ] Connection to MSOnline system types can fail when a different credential than the logged on user is used.  This may be isolated to SSO/Federation scenarios but the scope is currently unclear. This does not affect connections to other AzureAD system types or Exchange Online.
- [ ] If you remove a credential from an admin user profile the references to that credential in individual systems are left behind.  They have to be updated by usage of Set-AdminUserProfileSystemCredential.
- [ ] Get-AllParametersWithAValue leaves out bound parameters that intentially include a $null value.  Need up add an override switch OR exempt bound parameters from this logic. 

## Requested Features

- [ ] Disconnect-OneShellSystem
- [ ] Multiple OneShellSystem Connections for Jobs, parallel tasking, etc. 
- [ ] MFA support <https://techcommunity.microsoft.com/t5/Windows-PowerShell/Can-I-Connect-to-O365-Security-amp-Compliance-center-via/td-p/68898>

## Completed Items

- [x] Write Org Profile Creation/Editing Functions
- [x] Write Admin Profile Creation/Editing Functions
- [x] AD Properties/Schema info into AD systems in Org Profiles
- [x] Fix Skype Connectivity
- [x] Need to be able to use separate credential for connections to MSOnline,AzureAD,AzureADPReview,etc. (one credential for pssession another for service connection)
- [x] Fix Test existing Session command logic - might need to convert to scriptblock first
- [x] Session Management Groups aren't being written to the org profile system object for powershell type systems
- [x] make exchange org types different system types? - yes, did this for exchange and AD types
- [x] Make Profile Identity parameters non-mandatory and prompt for them with a select-profile function like we do with systems? - yes, done
- [x] per-admin per service prefix configuration
