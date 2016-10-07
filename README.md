# What is OneShell?
## Administer Office 365, Supporting Infrastructure, and more from a single PowerShell session
OneShell is a PowerShell module designed for administration of cloud and on premises services (specifically, but not only, Office 365 workloads and supporting on premises infrastructure) in a single PowerShell session.
OneShell provides administrators with a powerful per organization and per administrator profile system which allows for automation of connectivity (and reconnection, when necessary).  
## Key Features
- Org Profiles
  - Store General System Information which can be shared among multiple administrators
  - Defines available administrative endpoints for AD, Exchange, SharePoint, PowerShell, etc. 
- Admin Profiles
  - Stores Administrative Credentials (specific to each administrator)
  - Maps Credentials to administratiave endpoints along with per administrator connectivity preferences
  - Stores some additional administrative preferences and configurations
- Automated Connectivity to administrative endpoints
  - with one command connects an administrator to all desired administrative endpoints and re-connects on demand as well when sessions break
  - connectivity functions are suitable to embed in your own automation scripts to ensure connectivity during long running operations

## Supported services/workloads
OneShell supports automated connectivity to the following list of services, and is continually expanding to include additional workloads and services:
- Azure AD
- Exchange 2010 and later including Exchange Online
- SharePoint Online
- Skype/Lync on premises and Online
- AADSync/AADConnect Servers
- Active Directory Forests (Domain and Global Catalog connections)
- MS SQL Databases
- Migration Wiz
- Any server configured to support incoming PowerShell remote connections with grouping by type for One to Many administration
- Lotus Notes (via COM with other methods being considered)