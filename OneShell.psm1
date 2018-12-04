#!/usr/bin/env pwsh
##########################################################################################################
#Import functions from included ps1 files
##########################################################################################################
#. $(Join-Path $PSScriptRoot 'ProfileWizardFunctions.ps1')
. $(Join-Path $PSScriptRoot 'UtilityFunctions.ps1')
. $(Join-Path $PSScriptRoot 'UserInputFunctions.ps1')
. $(Join-Path $PSScriptRoot 'SystemConnectionFunctions.ps1')
. $(Join-Path $PSScriptRoot 'ProfileFunctions.ps1')
. $(Join-Path $PSScriptRoot 'TestFunctions.ps1')
. $(Join-Path $PSScriptRoot 'SkypeOnline.ps1')
. $(Join-Path $PSScriptRoot 'ParameterFunctions.ps1')
. $(Join-Path $PSScriptRoot 'LoggingFunctions.ps1')
. $(Join-Path $PSScriptRoot 'VariableFunctions.ps1')
. $(Join-Path $PSScriptRoot 'RegisterArgumentCompleter.ps1')
##########################################################################################################
#Initialization
##########################################################################################################
SetOneShellVariables
