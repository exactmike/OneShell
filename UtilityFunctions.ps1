function Get-DateStamp
{
    [string]$Stamp = Get-Date -Format yyyyMMdd
    $Stamp
}#Get-DateStamp
function Get-SpecialFolder
{
    <#
        Original source: https://github.com/gravejester/Communary.ConsoleExtensions/blob/master/Functions/Get-SpecialFolder.ps1
        MIT License
        Copyright (c) 2016 Øyvind Kallstad

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
    #>
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param (
    )
    DynamicParam
    {
            $Dictionary = New-DynamicParameter -Name 'Name' -Type $([string[]]) -ValidateSet @([Enum]::GetValues([System.Environment+SpecialFolder])) -Mandatory:$true -ParameterSetName 'Selected'
            Write-Output -InputObject $dictionary
    }#DynamicParam
    begin
    {
        #Dynamic Parameter to Variable Binding
        Set-DynamicParameterVariable -dictionary $Dictionary
        switch ($PSCmdlet.ParameterSetName)
        {
            'All'
            {
                $Name = [Enum]::GetValues([System.Environment+SpecialFolder])
            }
            'Selected'
            {
            }
        }
        foreach ($folder in $Name)
        {
            $FolderObject = 
                [PSCustomObject]@{
                    Name = $folder.ToString()
                    Path = [System.Environment]::GetFolderPath($folder)
                }
            Write-Output -InputObject $FolderObject
        }#foreach
    }#begin
}#Get-SpecialFolder
function Get-CustomRange
{
  #http://www.vistax64.com/powershell/15525-range-operator.html
  [cmdletbinding()]
  param(
    [string] $first
    ,
    [string] $second
    ,
    [string] $type
  )
    $rangeStart = [int] ($first -as $type)
    $rangeEnd = [int] ($second -as $type)
    $rangeStart..$rangeEnd | ForEach-Object { $_ -as $type }
}
function Compare-ComplexObject
{
  [cmdletbinding()]
  param(
    [Parameter(Mandatory)]
    $ReferenceObject
    ,
    [Parameter(Mandatory)]
    $DifferenceObject
    ,
    [string[]]$SuppressedProperties
    ,
    [parameter()]
    [validateset('All','EqualOnly','DifferentOnly')]
    [string]$Show = 'All'
  )#param
  #setup properties to compare
  #get properties from the Reference Object
  $RefProperties = @($ReferenceObject | get-member -MemberType Properties | Select-Object -ExpandProperty Name)
  #get properties from the Difference Object
  $DifProperties = @($DifferenceObject | get-member -MemberType Properties | Select-Object -ExpandProperty Name)
  #Get unique properties from the resulting list, eliminating duplicate entries and sorting by name
  $ComparisonProperties = @(($RefProperties + $DifProperties) | Select-Object -Unique | Sort-Object)
  #remove properties where they are entries in the $suppressedProperties parameter
  $ComparisonProperties = $ComparisonProperties | where-object {$SuppressedProperties -notcontains $_}
  $results = @()
  foreach ($prop in $ComparisonProperties)
  {
    $property = $prop.ToString()
    $ReferenceObjectValue = @($ReferenceObject.$($property))
    $DifferenceObjectValue = @($DifferenceObject.$($property))
    switch ($ReferenceObjectValue.Count) {
        1 {
            if ($DifferenceObjectValue.Count -eq 1) {
                $ComparisonType = 'Scalar'
                If ($ReferenceObjectValue[0] -eq $DifferenceObjectValue[0]) {$CompareResult = $true}
                If ($ReferenceObjectValue[0] -ne $DifferenceObjectValue[0]) {$CompareResult = $false}
            }#if
            else {
                $ComparisonType = 'ScalarToArray'
                $CompareResult = $false
            }
        }#1
        0 {
            $ComparisonType = 'ZeroCountArray'
            $ComparisonResults = @(Compare-Object -ReferenceObject $ReferenceObjectValue -DifferenceObject $DifferenceObjectValue -PassThru)
            if ($ComparisonResults.Count -eq 0) {$CompareResult = $true}
            elseif ($ComparisonResults.Count -ge 1) {$CompareResult = $false}
        }#0
        Default {
            $ComparisonType = 'Array'
            $ComparisonResults = @(Compare-Object -ReferenceObject $ReferenceObjectValue -DifferenceObject $DifferenceObjectValue -PassThru)
            if ($ComparisonResults.Count -eq 0) {$CompareResult = $true}
            elseif ($ComparisonResults.Count -ge 1) {$CompareResult = $false}
        }#Default
    }#switch
    $ComparisonObject = New-Object -TypeName PSObject -Property @{Property = $property; CompareResult = $CompareResult; ReferenceObjectValue = $ReferenceObjectValue; DifferenceObjectValue = $DifferenceObjectValue; ComparisonType = $comparisontype}
    $results += 
    $ComparisonObject | Select-Object -Property Property,CompareResult,ReferenceObjectValue,DifferenceObjectValue #,ComparisonType
  }#foreach
  switch ($show)
  {
    'All' {$results}#All
    'EqualOnly' {$results | Where-Object {$_.CompareResult}}#EqualOnly
    'DifferentOnly' {$results |Where-Object {-not $_.CompareResult}}#DifferentOnly
  }#switch $show
}#function Compare-ComplexObject
function Start-ComplexJob
{
  <#
      .SYNOPSIS
      Helps Start Complex Background Jobs with many arguments and functions using Start-Job.
      .DESCRIPTION
      Helps Start Complex Background Jobs with many arguments and functions using Start-Job. 
      The primary utility is to bring custom functions from the current session into the background job. 
      A secondary utility is to formalize the input for creation complex background jobs by using a hashtable template and splatting. 
      .PARAMETER  Name
      The name of the background job which will be created.  A string.
      .PARAMETER  JobFunctions
      The name[s] of any local functions which you wish to export to the background job for use in the background job script.  
      The definition of any function listed here is exported as part of the script block to the background job. 
      .EXAMPLE
      $StartComplexJobParams = @{
      jobfunctions = @(
            'Connect-WAAD'
        ,'Get-TimeStamp'
        ,'Write-Log'
        ,'Write-EndFunctionStatus'
        ,'Write-StartFunctionStatus'
        ,'Export-Data'
        ,'Get-MatchingAzureADUsersAndExport'
      )
      name = "MatchingAzureADUsersAndExport"
      arguments = @($SourceData,$SourceDataFolder,$LogPath,$ErrorLogPath,$OnlineCred)
      script = [scriptblock]{
        $PSModuleAutoloadingPreference = "None"
        $sourcedata = $args[0]
        $sourcedatafolder = $args[1]
        $logpath = $args[2]
        $errorlogpath = $args[3]
        $credential = $args[4]
        Connect-WAAD -MSOnlineCred $credential 
        Get-MatchingAzureADUsersAndExport
      }
      }
      Start-ComplexJob @StartComplexJobParams
  #>
  [cmdletbinding()]
  param
  (
    [string]$Name
    ,
    [string[]]$JobFunctions
    ,
    [psobject[]]$Arguments
    ,
    [string]$Script
  )
    #build functions to initialize in job 
    $JobFunctionsText = ''
    foreach ($Function in $JobFunctions) {
        $FunctionText = 'function ' + (Get-Command -Name $Function).Name + "{`r`n" + (Get-Command -Name $Function).Definition + "`r`n}`r`n"
        $JobFunctionsText = $JobFunctionsText + $FunctionText
    }
    $ExecutionScript = $JobFunctionsText + $Script
    #$initializationscript = [scriptblock]::Create($script)
    $ScriptBlock = [scriptblock]::Create($ExecutionScript)
    $StartJobParams = @{
        Name = $Name
        ArgumentList = $Arguments
        ScriptBlock = $ScriptBlock
    }
    #$startjobparams.initializationscript = $initializationscript
    Start-Job @StartJobParams
}#Function Start-ComplexJob
function Get-CSVExportPropertySet
{
    <#
        .SYNOPSIS
        Creates an array of property definitions to be used with Select-Object to prepare data with multi-valued attributes for export to a flat file such as csv.

        .DESCRIPTION
        From existing input arrays of scalar and multi-valued properties, creates an array of property definitions to be used with Select-Object or Format-Table. Automates the creation of the @{n=name;e={expression}} syntax for the multi-valued properties then outputs the whole list as a single array.

        .PARAMETER  Delimiter
        Used to specify the custom delimiter to be used between multi-valued entries in the multi-valued attributes input array.  Default is "|" if not specified.  Avoid using a "," if exporting data to a csv file later in your pipeline.

        .PARAMETER  MultiValuedAttributes
        An array of attributes from your source data which you expect to contain multiple values.  These will be converted to @{n=[PropertyName];e={$_.$propertyname -join $Delimiter} in the output of the function.  

        .PARAMETER  ScalarAttributes
        An array of attributes from your source data which you expect to contain scalar values.  These will be passed through directly in the output of the function.


        .EXAMPLE
        Get-CSVExportPropertySet -Delimiter ';' -MultiValuedAttributes proxyaddresses,memberof -ScalarAttributes userprincipalname,samaccountname,targetaddress,primarysmtpaddress
        Name                           Value                                                                                                                                                                                      
        ----                           -----                                                                                                                                                                                      
        n                              proxyaddresses                                                                                                                                                                             
        e                              $_.proxyaddresses -join ';'                                                                                                                                                                
        n                              memberof                                                                                                                                                                                   
        e                              $_.memberof -join ';'                                                                                                                                                                      
        userprincipalname
        samaccountname
        targetaddress
        primarysmtpaddress

        .OUTPUTS
        [array]

    #>
  param
  (
    $Delimiter = '|'
    ,
    [string[]]$MultiValuedAttributes
    ,
    [string[]]$ScalarAttributes
    ,
    [switch]$SuppressCommonADProperties
  )
  $ADUserPropertiesToSuppress = @('CanonicalName','DistinguishedName')
  $CSVExportPropertySet = @()
  foreach ($mv in $MultiValuedAttributes) {
    $ExpressionString = "`$_." + $mv + " -join '$Delimiter'"
    $CSVExportPropertySet += 
    @{
        n=$mv
        e=[scriptblock]::Create($ExpressionString)
    }
  }#foreach
  if ($SuppressCommonADProperties) {$CSVExportPropertySet += ($ScalarAttributes | Where-Object {$ADUserPropertiesToSuppress -notcontains $_})}
  else {$CSVExportPropertySet += $ScalarAttributes}
  $CSVExportPropertySet
}#get-CSVExportPropertySet
function Start-WindowsSecurity
{
  #useful in RDP sessions especially on Windows 2012
  (New-Object -ComObject Shell.Application).WindowsSecurity()
}
function Get-RandomFileName
{([IO.Path]::GetRandomFileName())}