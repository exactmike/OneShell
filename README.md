# What is OneShell

## Framework for managing connections (credentials, initial connections, re-connections, etc.) to management endpoints for a diverse array of system/service types

OneShell to rule them all . . .
The real world is messy - endpoints fail; connection methods for systems vary widely; you need simultaneous access to multiple forests, tenants, enpoints or sites; sessions go bad (at the PSSession level or the application endpoint level), connection configurations have to be maintained, credentials need to be updated, etc., etc.

OneShell is a (Windows, for now) PowerShell module designed for administration of cloud and on premises services (specifically, but not only, Office 365 workloads and supporting on premises infrastructure) in a single PowerShell session via reliable and easily re-connectable remote PSsessions or other connection types to those remote systems.  Remote here just means remote to your administrative or task-running server or workstation instance. OneShell provides administrators with a framework which allows for automation of connection/reconnection to these systems for interactive, scheduled task and/or scripted administrative or migration tasks. OneShell also provides a rich set of functionality via additional functions and helper modules that can be used in your own automation scripts for provisioning, maintenance, or reporting.

OneShell's currently extensible ServiceType system currently natively supports the following system types (for each of which multiple, _simultaneous_ connections are currently supported):

- Azure AD
- Azure AD Preview
- MSOnline (*-msol* cmdlets)
- Exchange Online
- Exchange On Premises (2010-2016)
- Exchange Compliance Center
- Exchange 2007
- Active Directory Domain
- Active Directory Global Catalog (Forest)
- Active Directory LDS
- Skype for Business Online
- Skype for Business On Premises
- Windows PowerShell PSRemoting Servers (with optional x86 endpoint support)
- Azure AD Sync/Azure AD Connect Servers
- SMTP Relay Endpoints (for email notification delivery from your tasks/scripts/functions)

The following ServiceTypes are close to being supported (an earlier version of OneShell included these and the code to include them in support is in progress):

- Lotus Notes
- SQL Server Databases
- Azure AD RMS
- MigrationWiz/BitTitan

We hope to soon add support for SSH endpoints for heterogenous environments

## Key Features

- Extensible ServiceType configuration.  You can add additional systems usually without any modifications to OneShell code by adding a ServiceType json file.
- Profiles
  - Stores General Organization System Information which can be shared among multiple administrators
  - Defines administrative endpoints and preferences
  - Stores Administrative Credentials (specific to each administrator)
  - Maps Credentials to administrative endpoints along with per administrator connectivity preferences
  - Stores some additional administrative preferences and configurations
- Automated Connectivity to administrative endpoints
  - With one command connects an administrator to all desired administrative endpoints and re-connects on demand as well when sessions break
  - Connectivity functions are suitable to embed in your own automation scripts to ensure connectivity during long running operations
