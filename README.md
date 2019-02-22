[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# What is OneShell

A Connection Manager for PowerShell connections to cloud and on premises systems and services designed to be used interactively by administrators, consultants and developers.

## Overview

OneShell to rule them all . . .

The world is messy - endpoints fail; connection methods vary; forests, tenants, and endpoints multiply; sessions go bad; credentials need updating.

OneShell provides a framework for uniform and reliable connection management to assist in your daily administration, automation, or development of solutions.

OneShell is a PowerShell module designed for administration of cloud and on premises services (specifically, but not only, Office 365 workloads and supporting on premises infrastructure) in a single PowerShell session via reliable and easily re-connectable remote PSsessions or other connection types to those systems. OneShell provides administrators with a framework which allows for automation of connection/re-connection to these systems for interactive administration or for integration with functions, scheduled tasks and/or long-running operations. OneShell also provides a rich set of functionality via additional functions and helper modules that can be used in your own automation scripts for provisioning, maintenance, or reporting.

OneShell's extensible ServiceType system currently supports the following system types (for each of which multiple, _simultaneous_ connections are supported, avoiding cmdlet 'clobber' issues by using prefixing or invoke-command per session):

- Azure AD
- MSOnline (*-msol* cmdlets)
- Exchange Online
- Exchange On Premises (2010-2016)
- Exchange Compliance Center
- Exchange 2007 (untested)
- Active Directory Domain
- Active Directory Global Catalog (Forest)
- Skype for Business Online
- Windows PowerShell PSRemoting Servers (with optional x86 endpoint support)
- Azure AD Sync/Azure AD Connect Servers

The following additional ServiceTypes are in development (an earlier version of OneShell included each of these):

- Lotus Notes
- SQL Server Databases
- Azure AD RMS
- MigrationWiz/BitTitan
- *OneShell is designed to be easily extensible - add your own service type and or make a request.  What other system/service types do you want support for?*

We hope to soon add support for SSH remoting and endpoints for heterogenous environments.

## Key Features

- Extensible ServiceType configuration.

  You can add additional system types/service types usually without any modifications to OneShell code by adding a ServiceType json file to the ServiceTypes directory. See the ServiceTypes folder (or run Get-OneShellServiceTypeName) for the current supported types.  Examine the individual .json files in ServiceTypes and/or run Get-OneShellServiceTypeDefinition to examing the Service Type definition objects in detail.

- 'Org' Profiles
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

Guidelines TBA . . .
In the meantime, there are issues and to do items noted in ToDoKnownIssuesEtc.md
