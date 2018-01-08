# To Do Items

- [x] Write Org Profile Creation/Editing Functions
- [x] Write Admin Profile Creation/Editing Functions
- [ ] Write GUI/Wizard Functions for Org and Admin Profile Creation
- [x] AD Properties/Schema info into AD systems in Org Profiles
- [ ] Fix Skype Connectivity (Untested)
- [ ] Notes/Domino LDAP Connections or ODBC or ? (COM support in place with PSLotusNotes Module)
- [ ] Make parameters which ask for a computer consistently named ComputerName?
- [ ] modify test-directorysynchronization to use Azure AD test as an option and to use non-recipient exchange objects
- [ ] create a Write-Progress helper function for showing progress every nth record, showing time to completion, making the experience more consistent across functions, etc.
- [ ] Admin Profile Editing/Creation GUI improvements: List view for per system configuration like: system, credential (in drop down?), autoconnect check box, autoimport check box
- [x] per-admin per service prefix configuration
- [ ] Follow <http://semver.org/> for Versioning
- [ ] Clean up PSSessions when switching Admin or Org Profiles with Use-*Profile functions
- [ ] Improve CommandPrefix configurations with profiles - allow NULL or blank and check for duplicates in some situations (like between Exchange Orgs)

## AAD Connect Improvements

- [ ] add function to report AADConnect/AADSync status - that is, if a synchronization is in progress, what kind of sync it is and when it started. (<http://www.anexinet.com/blog/scripting-a-manual-dirsync-with-powershell-in-azure-ad-connect-v-1-1/>)
- [ ] add function to export connectors, disconnectors, etc. from connector spaces for validation of new AAD Connect instances (In Progress)

## ideas from Joe

- [x] make exchange org types different system types? - yes, did this for exchange and AD types
- [ ] Endpoint prevented from being added to ComplianceCenter and ExchangeOnline types . . . ? no, but warn instead
- [x] Make Profile Identity parameters non-mandatory and prompt for them with a select-profile function like we do with systems? - yes, done

## Bugs/Known Issues

- [ ] If you use a non-valid dynamic parameter name with New-OrgProfileSystem (and perhaps other commands) you'll get a non-helpful error about postitional parameters "Cannot bind positional parameters because no names were given."