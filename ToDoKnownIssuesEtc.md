# To Do Items

## In Progress And Help Wanted

- [ ] Add Non-PSRemoting Service Attribute and Connection support
- [ ] Re-Work Connect-OneShellSystem -reconnect for DirectConnect systems.
- [ ] Add Connect-OneShellSystem -autoconnect for autoconnecting all autoconnect systems in the current profile
- [ ] add select-profile prompting anytime a user doesn't specify identity with the set-*profile* commands
- [ ] Add Exchange 2007 ServiceType support - in progress (will likely depend on Non-PSRemoting support for service connections)
- [ ] Add [OutputType([void])] to functions that don't return output and appropriate OutputType to other functions

## Pending and Help Wanted

- [ ] update SkypeForBusinessOnline connection test command to Get-CSTenant?
- [ ] Update Azure AD connection test command to Get-AzureADTenantDetail
- [ ] fix Set-OneShellUserProfile* functions so that path is preserved for user profiles when editing in a non-default location
- [ ] call update-OneShellUserProfilesystem in every set-OneShellUserProfile* cmdlet to catch recently added orgprofilesystems
- [ ] if Set-OneShellUserProfile* functions are used against the current user profile then automatically run use-oneshelluserprofile to update the active profile
- [ ] Add function AddUserProfileFolder to Use-OneShellUserProfile
- [ ] Add function Get-OneShellUserProfileSystemCredential
- [ ] Move Credential Storage to the following options: 1 - Azure based storage, 2 - Credential Manager, 3 - equivalent of credential manager on linux/macOS, 4 - AWS, 5 - Other?  Make a framework that allows options . . .
- [ ] Add support for [multi-geo in Exchange Online Systems]<https://docs.microsoft.com/en-us/office365/enterprise/multi-geo-capabilities-in-exchange-online>
- [ ] Add Remove-* functions for OrgProfile, UserProfile
- [ ] $PSModuleAutoloadingPreference = 'none' when creating PSSessions for types of systems other than PowerShell Remoting Specific sessions
- [ ] add filter to getpotential* functions for profiletype attribute to only return the right kind of profile(s)
- [ ] Clean up/Remove PSSessions when switching user or Org Profiles with Use-*Profile functions
- [ ] Write GUI/Wizard Functions and/or UniveralDashboard interface for Org and user Profile Creation
- [ ] Add Clean Up Code for Sessions, imported modules, and the handful of global variables oneshell might create with the [module's onremove capability:] <https://stackoverflow.com/questions/24475572/restoring-a-powershell-alias-when-a-module-is-unloaded>
- [ ] Add CommandPrefix validation for org and user profile systems new and set functions (check for duplicate prefixes or nulls across the same service type or overlapping service types)
- [ ] Convert Write-OneShellLog to use System.IO.FileStream . . . and allow concurrent/asynch writing.
- [ ] Does $PSSenderInfo have any use cases for OneShell?
- [ ] spin off parameter functions to a separate module and add multiple parameter set support to Dynamic Parameters (so that a parameter can be mandatory in one and not in another)
- [ ] Disconnect-OneShellSystem
- [ ] Add functionality to Update-OneShellServiceType to check for duplicate types and allow override of a ServiceType by user imported ServiceType file.

## Help Wanted Service Types to Add

- [ ] Add LotusNotesDatabase ServiceType support
- [ ] Add MigrationWiz/BitTitan ServiceType Support
- [ ] Add Azure AD RMS ServiceType Support <https://docs.microsoft.com/en-us/information-protection/deploy-use/install-powershell>
- [ ] Add a ServiceType for Network Drive Connections (and cloud storage connections?)
- [ ] Add a ServiceType for Remote Desktop Connections
- [ ] AD LDS support needs to be completed and tested (mostly ServiceTypes.json updated with the right values)
- [ ] Microsoft Teams
- [ ] SharePoint Online

## Help Wanted Requested Features

- [ ] Multiple OneShellSystem Connections for Jobs, parallel tasking, etc.
- [ ] MFA support <https://techcommunity.microsoft.com/t5/Windows-PowerShell/Can-I-Connect-to-O365-Security-amp-Compliance-center-via/td-p/68898>

## Bugs/Known Issues

- [ ] If you use a non-valid dynamic parameter name with New-OneShellOrgProfileSystem (and perhaps other commands) you'll get a non-helpful error about postitional parameters "Cannot bind positional parameters because no names were given."
- [ ] Set-OneShellOrgProfileSystemEndpoint does not seem work to update an endpoint address
- [ ] Need to implement SessionManagementGroups logic to create and update/manage the group variables (partially complete - need to integrate connection removals as well)
- [ ] Need to add explicit loading of required module to establish PSSession for special cases (like SkypeForBusinessOnline)
- [ ] Connection to MSOnline system types can fail when a different credential than the logged on user is used.  This may be isolated to SSO/Federation scenarios but the scope is currently unclear. This does not affect connections to other AzureAD system types or Exchange Online.
- [ ] If you remove a credential from an User Profile the references to that credential in individual systems are left behind.  They have to be updated by usage of Set-OneShellUserProfileSystemCredential.
- [ ] Get-AllParametersWithAValue leaves out bound parameters that intentially include a $null value.  Need to add an override switch OR exempt bound parameters from this logic.

## Completed Items

- [x] Finish SQL ServiceType support (initialization) - use dbatools module instead of the previously used POSH_ADO module? Yes, dbatools IN PROGRESS
- [x] fix user provided User Profile folder path if they include a trailing \
- [x] Endpoint prevented from being added to ComplianceCenter and ExchangeOnline types . . . ? no, but warn instead (in progress) (From Joe S)
- [x] Write Org Profile Creation/Editing Functions
- [x] Write User Profile Creation/Editing Functions
- [x] AD Properties/Schema info into AD systems in Org Profiles
- [x] Fix Skype Connectivity
- [x] Need to be able to use separate credential for connections to MSOnline,AzureAD,AzureADPReview,etc. (one credential for pssession another for service connection)
- [x] Fix Test existing Session command logic - might need to convert to scriptblock first
- [x] Session Management Groups aren't being written to the org profile system object for powershell type systems
- [x] make exchange org types different system types? - yes, did this for exchange and AD types
- [x] Make Profile Identity parameters non-mandatory and prompt for them with a select-profile function like we do with systems? - yes, done
- [x] per-admin per service prefix configuration
- [x] Add a DynamicParameter capability for ValueFromPipeline options (<https://stackoverflow.com/questions/28604116/how-to-get-value-from-pipeline-for-a-dynamicparam-in-powershell>),(<https://beatcracker.wordpress.com/2014/12/18/psboundparameters-pipeline-and-the-valuefrompipelinebypropertyname-parameter-attribute/>)
- [x] Add/Enable Identity parameter for get-oneshellsystem,get-oneshellsystempssession,import-oneshellsystem, etc.
- [x] Add auto-connect of AutoConnect Service types with Use-OneShellUserProfile unless suppressed by -NoAutoConnect
- [x] Add suppression of auto Import with -NoAutoImport on Connect-OneShellSystem and Use-OneShellUserProfile
- [x] Remove imported modules from session when re-connecting to a System
- [x] Improve CommandPrefix configurations with profiles - allow NULL or blank
- [x] Functionalize repeated code in DynamicParam blocks across ProfileFunctions and ConnectionFunctions and/or REPLACE DynamicParams with Register-ArgumentCompleter . . .
- [x] add parameters to Set-OneShellUserProfile to allow setting of ExportData,LogFolder, and InputFiles independently of the ProfileFolder
- [x] replace code in New-OneShellOrgProfileSystemEndpoint that refers specifically to ExchangeOnline and ExchangeOnlineComplianceCenter and instead base the code on the ServiceTypeDefinition having a well known endpoint configured. This will (theoretically) allow for other users to  more easily seemlessly extend OneShell ServiceType support without code changes.