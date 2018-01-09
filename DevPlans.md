# To Do Items

- [x] Write Org Profile Creation/Editing Functions
- [x] Write Admin Profile Creation/Editing Functions
- [ ] Write GUI/Wizard Functions for Org and Admin Profile Creation
- [x] AD Properties/Schema info into AD systems in Org Profiles
- [x] Fix Skype Connectivity
- [ ] update SkypeForBusinessOnline connection test command to Get-CSTenant?
- [ ] Notes/Domino LDAP Connections or ODBC or ? (COM support in place with PSLotusNotes Module)
- [ ] Make parameters which ask for a computer consistently named ComputerName?
- [ ] modify test-directorysynchronization to use Azure AD test as an option and to use non-recipient exchange objects
- [ ] create a Write-Progress helper function for showing progress every nth record, showing time to completion, making the experience more consistent across functions, etc.
- [ ] Admin Profile Editing/Creation GUI improvements: List view for per system configuration like: system, credential (in drop down?), autoconnect check box, autoimport check box
- [x] per-admin per service prefix configuration
- [ ] Follow <http://semver.org/> for Versioning
- [ ] Clean up PSSessions when switching Admin or Org Profiles with Use-*Profile functions
- [ ] Improve CommandPrefix configurations with profiles - allow NULL or blank and check for duplicates in some situations (like between Exchange Orgs)
- [ ] Update Azure AD system test command to Get-AzrueADCurrentSessionInfo
- [ ] Finish SQL Connection logic in ServiceTypes - need to add the right initialization commands

## AAD Connect Improvements

- [ ] add function to report AADConnect/AADSync status - that is, if a synchronization is in progress, what kind of sync it is and when it started. (<http://www.anexinet.com/blog/scripting-a-manual-dirsync-with-powershell-in-azure-ad-connect-v-1-1/>)
- [ ] add function to export connectors, disconnectors, etc. from connector spaces for validation of new AAD Connect instances (In Progress)

## ideas from Joe

- [x] make exchange org types different system types? - yes, did this for exchange and AD types
- [ ] Endpoint prevented from being added to ComplianceCenter and ExchangeOnline types . . . ? no, but warn instead (in progress)
- [x] Make Profile Identity parameters non-mandatory and prompt for them with a select-profile function like we do with systems? - yes, done

## Bugs/Known Issues

- [ ] If you use a non-valid dynamic parameter name with New-OrgProfileSystem (and perhaps other commands) you'll get a non-helpful error about postitional parameters "Cannot bind positional parameters because no names were given."
- [ ] Set-OrgProfileSystemEndpoint does not work to update an endpoint address
- [ ] Need to be able to use separate credential for connections to MSOnline,AzureAD,AzureADPReview,etc. (one credential for pssession another for service connection)
- [ ] Need to implement SessionManagementGroups logic to create and update/manage the group variables
- [ ] Need to add explicit loading of required module to establish PSSession for special cases (like SkypeForBusinessOnline)
- [x] Fix Test existing Session command logic - might need to convert to scriptblock first
- [ ] Session Management Groups aren't being written to the org profile system object for powershell type systems

## Requested Features

- [ ] Disconnect-OneShellSystem
- [ ] Multiple OneShellSystem Connections for Jobs, parallel tasking, etc. 
- [ ] MFA support <https://techcommunity.microsoft.com/t5/Windows-PowerShell/Can-I-Connect-to-O365-Security-amp-Compliance-center-via/td-p/68898>