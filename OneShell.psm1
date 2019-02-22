#!/usr/bin/env pwsh
##########################################################################################################
#Import functions from included ps1 files
##########################################################################################################

. $(Join-Path $PSScriptRoot 'RegisterArgumentCompleter.ps1')

$FunctionFiles = Get-ChildItem -Recurse -File -Path $(Join-Path -Path $PSScriptRoot -ChildPath 'Functions')
foreach ($ff in $FunctionFiles) {. $ff.fullname}
##########################################################################################################
#Initialization
##########################################################################################################
SetOneShellVariables
