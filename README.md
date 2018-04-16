# What is OneShell

A Framework for managing connections (credentials, connection modules, app modules, connection configuration details, initial connections, re-connections, etc.) to management endpoints for a diverse array of system/service types

## Overview

OneShell to rule them all . . .

The world is messy - endpoints fail; connection methods vary; forests, tenants, and endpoints multiply; sessions go bad; credentials need updating.

OneShell provides a framework for uniform and reliable connection and re-connection to varied system types for interactive or automated administration.

OneShell is a (Windows, for now) PowerShell module designed for administration of cloud and on premises services (specifically, but not only, Office 365 workloads and supporting on premises infrastructure) in a single PowerShell session via reliable and easily re-connectable remote PSsessions or other connection types to those systems. OneShell provides administrators with a framework which allows for automation of connection/re-connection to these systems for interactive administration or for integration with functions, scheduled tasks and/or long-running operations. OneShell also provides a rich set of functionality via additional functions and helper modules that can be used in your own automation scripts for provisioning, maintenance, or reporting.

OneShell's extensible ServiceType system currently supports the following system types (for each of which multiple, _simultaneous_ connections are supported, avoiding cmdlet 'clobber' issues by using prefixing or invoke-command per session):

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

The following additional ServiceTypes are in development (an earlier version of OneShell included each of these):

- Lotus Notes
- SQL Server Databases
- Azure AD RMS
- MigrationWiz/BitTitan
- *OneShell is designed to be easily extensible - what other system/service types do you want support for?*

We hope to soon add support for SSH remoting and endpoints for heterogenous environments.

## Key Features

- Extensible ServiceType configuration.

  You can add additional system types/service types usually without any modifications to OneShell code by adding a ServiceType json file. See ServiceTypes.json for the current supported types and ServiceTypesTemplate.json for an example of the available options (ServiceTypesTemplate.json does not represent a working configuration but rather includes examples of the kinds of things you can specify in each attribute).

- Org Profiles
  - Store General 'per organization' System/Service instances which can be shared among multiple administrators
  - Define endpoints and preferences
  - Each System/Service can be configured with multiple endpoints
- User Profiles
  - Store Administrative Credentials (specific to each administrator)
  - Map Credentials to services
  - Store AutoConnect and/or AutoImport settings per System/Service instance
  - Store Prefix setting per System/Service instance
  - Stores additional preferences per System/Service instance, such as preferred endpoint
- Automated Connectivity to administrative endpoints
  - With one command connects an administrator to all Systems/Services and re-connects on demand as well when sessions break
  - Connectivity functions are suitable to embed in your own automation scripts to ensure connectivity during long running operations

## Getting Started

See GettingStarted.md

## Contributing

TBA . . .
In the meantime, there are issues and to do items noted in ToDoKnownIssuesEtc.md
