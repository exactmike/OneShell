##########################################################################################################
#Utility and Support Functions
##########################################################################################################
#Used By Other OneShell Functions
function Get-ArrayIndexForValue {
    [cmdletbinding()]
    param(
        [parameter(mandatory=$true)]
        $array
        ,
        [parameter(mandatory=$true)]
        $value
        ,
        [parameter()]
        $property
    )
    if ([string]::IsNullOrWhiteSpace($Property)) {
        Write-Verbose -Message "Using Simple"
        [array]::indexof($array,$value)
    }#if
    else {
        Write-Verbose -Message "Using Property"
        [array]::indexof($array.$property,$value)
    }#else
}#function
function Get-TimeStamp {
    [string]$Stamp = Get-Date -Format yyyyMMdd-HHmm
    $Stamp
}#Get-TimeStamp
function Get-DateStamp {
    [string]$Stamp = Get-Date -Format yyyyMMdd
    $Stamp
}
#Error Handling Functions and used by other OneShell Functions
function Get-AvailableExceptionsList
{
[CmdletBinding()]
param()
end {
        $irregulars = 'Dispose|OperationAborted|Unhandled|ThreadAbort|ThreadStart|TypeInitialization'
        $appDomains = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {-not $_.IsDynamic}
        $ExportedTypes = $appDomains | ForEach-Object {$_.GetExportedTypes()}
        $Exceptions = $ExportedTypes | Where-Object {$_.name -like '*exception*' -and $_.name -notmatch $irregulars}
        $exceptionsWithGetConstructorsMethod = $Exceptions | Where-Object -FilterScript {'GetConstructors' -in @($_ | Get-Member -MemberType Methods | Select-Object -ExpandProperty Name)}
        $exceptionsWithGetConstructorsMethod | Select-Object -ExpandProperty FullName
<#  
.Synopsis      Retrieves all available Exceptions to construct ErrorRecord objects.
.Description      Retrieves all available Exceptions in the current session to construct ErrorRecord objects.
.Example      $availableExceptions = Get-AvailableExceptionsList      Description      ===========      Stores all available Exception objects in the variable 'availableExceptions'.
.Example      Get-AvailableExceptionsList | Set-Content $env:TEMP\AvailableExceptionsList.txt      Description      ===========      Writes all available Exception objects to the 'AvailableExceptionsList.txt' file in the user's Temp directory.
.Inputs     None
.Outputs     System.String
.Link      New-ErrorRecord
.Notes Name:  Get-AvailableExceptionsList  Original Author: Robert Robelo  ModifiedBy: Mike Campbell
#>
}#end
}
function New-ErrorRecord
{
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [System.String]
    $Exception
    ,
    [Parameter(Mandatory = $true, Position = 1)]
    [Alias('ID')]
    [System.String]
    $ErrorId
    ,
    [Parameter(Mandatory = $true, Position = 2)]
    [Alias('Category')]
    [System.Management.Automation.ErrorCategory]
    [ValidateSet('NotSpecified', 'OpenError', 'CloseError', 'DeviceError',
            'DeadlockDetected', 'InvalidArgument', 'InvalidData', 'InvalidOperation',
            'InvalidResult', 'InvalidType', 'MetadataError', 'NotImplemented',
            'NotInstalled', 'ObjectNotFound', 'OperationStopped', 'OperationTimeout',
            'SyntaxError', 'ParserError', 'PermissionDenied', 'ResourceBusy',
            'ResourceExists', 'ResourceUnavailable', 'ReadError', 'WriteError',
    'FromStdErr', 'SecurityError')]
    $ErrorCategory
    ,
    [Parameter(Mandatory = $true, Position = 3)]
    [System.Object]
    $TargetObject
    ,
    [Parameter()]
    [System.String]
    $Message
    ,
    [Parameter()]
    [System.Exception]
    $InnerException
)
begin
{
    if (-not (Test-Path variable:script:AvailableExceptionsList))
    {$script:AvailableExceptionsList = Get-AvailableExceptionsList}
    if (-not $Exception -in $script:AvailableExceptionsList)
    {
        $message2 = "Exception '$Exception' is not available."
        $exception2 = New-Object System.InvalidOperationException $message2
        $errorID2 = 'BadException'
        $errorCategory2 = 'InvalidOperation'
        $targetObject2 = 'Get-AvailableExceptionsList'
        $errorRecord2 = New-Object Management.Automation.ErrorRecord $exception2, $errorID2,
        $errorCategory2, $targetObject2
        $PSCmdlet.ThrowTerminatingError($errorRecord2)
    }
}
process
{
    # trap for any of the "exceptional" Exception objects that made through the filter
    trap [Microsoft.PowerShell.Commands.NewObjectCommand] {
        $PSCmdlet.ThrowTerminatingError($_)
    }
    # ...build and save the new Exception depending on present arguments, if it...
    $newObjectParams1 = @{
        TypeName = $Exception
    }
    if ($PSBoundParameters.ContainsKey('Message'))
    {
        $newObjectParams1.ArgumentList = @()
        $newObjectParams1.ArgumentList += $Message
        if ($PSBoundParameters.ContainsKey('InnerException'))
        {
            $newObjectParams1.ArgumentList += $InnerException
        }
    }
    $ExceptionObject = New-Object @newObjectParams1

    # now build and output the new ErrorRecord
    New-Object Management.Automation.ErrorRecord $ExceptionObject, $ErrorID, $ErrorCategory, $TargetObject
}#Process
<#  
.Synopsis      Creates an custom ErrorRecord that can be used to report a terminating or non-terminating error.
.Description      Creates an custom ErrorRecord that can be used to report a terminating or non-terminating error.
.Parameter Exception      The Exception that will be associated with the ErrorRecord.
.Parameter ErrorID      A scripter-defined identifier of the error.      This identifier must be a non-localized string for a specific error type.
.Parameter ErrorCategory      An ErrorCategory enumeration that defines the category of the error.
.Parameter TargetObject      The object that was being processed when the error took place.
.Parameter Message      Describes the Exception to the user.
.Parameter InnerException      The Exception instance that caused the Exception association with the ErrorRecord.
.Example
# advanced functions for testing
function Test-1
{
[CmdletBinding()] 
param
(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [String]$Path
)
process
{
foreach ($_path in $Path)
{
    $content = Get-Content -LiteralPath $_path -ErrorAction SilentlyContinue
    if (-not $content)
    {
        $errorRecord = New-ErrorRecord InvalidOperationException FileIsEmpty InvalidOperation $_path -Message "File '$_path' is empty."
        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }
}  
}
} 
function Test-2
{
[CmdletBinding()]
param(
[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
[String]$Path
)
process
{
    foreach ($_path in $Path)
    {
        $content = Get-Content -LiteralPath $_path -ErrorAction SilentlyContinue
        if (-not $content)
        {
            $errorRecord = New-ErrorRecord InvalidOperationException FileIsEmptyAgain InvalidOperation $_path -Message "File '$_path' is empty again." -InnerException $Error[0].Exception
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }
}
} 
# code to test the custom terminating error reports 
Clear-Host $null = New-Item -Path .\MyEmptyFile.bak -ItemType File -Force -Verbose 
Get-ChildItem *.bak | Where-Object {-not $_.PSIsContainer} | Test-1 Write-Host System.Management.Automation.ErrorRecord -ForegroundColor Green 
$Error[0] | Format-List * -Force Write-Host Exception -ForegroundColor Green 
$Error[0].Exception | Format-List * -Force Get-ChildItem *.bak | Where-Object {-not $_.PSIsContainer} | Test-2 Write-Host System.Management.Automation.ErrorRecord -ForegroundColor Green 
$Error[0] | Format-List * -Force Write-Host Exception -ForegroundColor Green 
$Error[0].Exception | Format-List * -Force 
Remove-Item .\MyEmptyFile.bak -Verbose
Description
===========
Both advanced functions throw a custom terminating error when an empty file is being processed.
Function Test-2's custom ErrorRecord includes an inner exception, which is the ErrorRecord reported by function Test-1.
The test code demonstrates this by creating an empty file in the curent directory -which is deleted at the end- and passing its path to both test functions.
The custom ErrorRecord is reported and execution stops for function Test-1, then the ErrorRecord and its Exception are displayed for quick analysis.
Same process with function Test-2; after analyzing the information, compare both ErrorRecord objects and their corresponding Exception objects.
    -In the ErrorRecord note the different Exception, CategoryInfo and FullyQualifiedErrorId data.
    -In the Exception note the different Message and InnerException data.
.Example
$errorRecord = New-ErrorRecord System.InvalidOperationException FileIsEmpty InvalidOperation
$Path -Message "File '$Path' is empty."
$PSCmdlet.ThrowTerminatingError($errorRecord)
Description
===========
A custom terminating ErrorRecord is stored in variable 'errorRecord' and then it is reported through $PSCmdlet's ThrowTerminatingError method.
The $PSCmdlet object is only available within advanced functions.
.Example
$errorRecord = New-ErrorRecord System.InvalidOperationException FileIsEmpty InvalidOperation $Path -Message "File '$Path' is empty."
Write-Error -ErrorRecord $errorRecord
Description
===========
A custom non-terminating ErrorRecord is stored in variable 'errorRecord' and then it is reported through the Write-Error Cmdlet's ErrorRecord parameter.
.Inputs System.String
.Outputs System.Management.Automation.ErrorRecord
.Link Write-Error Get-AvailableExceptionsList
.Notes
    Name:      New-ErrorRecord
    OriginalAuthor:    Robert Robelo
    ModifiedBy: Mike Campbell
#>
}
#Useful Functions
function Get-CustomRange
{
#Start http://www.vistax64.com/powershell/15525-range-operator.html
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
function Compare-ComplexObject #MC
{
[cmdletbinding()]
param(
    $ReferenceObject
    ,
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
        $FunctionText = 'function ' + (Get-Command $Function).Name + "{`r`n" + (Get-Command $Function).Definition + "`r`n}`r`n"
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
function Get-ADdrive {get-psdrive -PSProvider ActiveDirectory}
function Start-WindowsSecurity
{
#useful in RDP sessions especially on Windows 2012
(New-Object -COM Shell.Application).WindowsSecurity()
}
function New-GUID {[GUID]::NewGuid()}
#Conversion and Testing Functions
function Merge-Hashtables
{
    #requires -Version 2.0
    <#
        .NOTES
        ===========================================================================
        Filename              : Merge-Hashtables.ps1
        Created on            : 2014-09-04
        Created by            : Frank Peter Schultze
        ===========================================================================

        .SYNOPSIS
        Create a single hashtable from two hashtables where the second given
        hashtable will override.

        .DESCRIPTION
        Create a single hashtable from two hashtables. In case of duplicate keys
        the function the second hashtable's key values "win". Merge-Hashtables
        supports nested hashtables.

        .EXAMPLE
        $configData = Merge-Hashtables -First $defaultData -Second $overrideData

        .INPUTS
        None

        .OUTPUTS
        System.Collections.Hashtable
    #>

    [CmdletBinding()]
    Param
    (
        #Identifies the first hashtable
        [Parameter(Mandatory=$true)]
        [Hashtable]
        $First
        ,
        #Identifies the second hashtable
        [Parameter(Mandatory=$true)]
        [Hashtable]
        $Second
    )

    function Set-Keys ($First, $Second)
    {
        @($First.Keys) | Where-Object {
            $Second.ContainsKey($_)
        } | ForEach-Object {
            if (($First.$_ -is [Hashtable]) -and ($Second.$_ -is [Hashtable]))
            {
                Set-Keys -First $First.$_ -Second $Second.$_
            }
            else
            {
                $First.Remove($_)
                $First.Add($_, $Second.$_)
            }
        }
    }

    function Add-Keys ($First, $Second)
    {
        @($Second.Keys) | ForEach-Object {
            if ($First.ContainsKey($_))
            {
                if (($Second.$_ -is [Hashtable]) -and ($First.$_ -is [Hashtable]))
                {
                    Add-Keys -First $First.$_ -Second $Second.$_
                }
            }
            else
            {
                $First.Add($_, $Second.$_)
            }
        }
    }

    # Do not touch the original hashtables
    $firstClone  = $First.Clone()
    $secondClone = $Second.Clone()

    # Bring modified keys from secondClone to firstClone
    Set-Keys -First $firstClone -Second $secondClone

    # Bring additional keys from secondClone to firstClone
    Add-Keys -First $firstClone -Second $secondClone

    # return firstClone
    $firstClone
}
function Convert-HashtableToObject
{
    [CmdletBinding()]
    PARAM(
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [HashTable]$hashtable
        ,
        [switch]$Combine
        ,
        [switch]$Recurse
    )
    BEGIN {
        $output = @()
    }
    PROCESS {
        if($recurse) {
            $keys = $hashtable.Keys | ForEach-Object { $_ }
            Write-Verbose "Recursing $($Keys.Count) keys"
            foreach($key in $keys) {
                if($hashtable.$key -is [HashTable]) {
                    $hashtable.$key = ConvertFrom-Hashtable $hashtable.$key -Recurse # -Combine:$combine
                }
            }
        }
        if($combine) {
            $output += @(New-Object PSObject -Property $hashtable)
            Write-Verbose "Combining Output = $($Output.Count) so far"
        } else {
            New-Object PSObject -Property $hashtable
        }
    }
    END {
        if($combine -and $output.Count -gt 1) {
            Write-Verbose "Combining $($Output.Count) cached outputs"
            $output | Join-Object
        } else {
            $output
        }
    }
}
Function Convert-ObjectToHashTable
{

    <#
        .Synopsis
        Convert an object into a hashtable.
        .Description
        This command will take an object and create a hashtable based on its properties.
        You can have the hashtable exclude some properties as well as properties that
        have no value.
        .Parameter Inputobject
        A PowerShell object to convert to a hashtable.
        .Parameter NoEmpty
        Do not include object properties that have no value.
        .Parameter Exclude
        An array of property names to exclude from the hashtable.
        .Example
        PS C:\> get-process -id $pid | select name,id,handles,workingset | ConvertTo-HashTable

        Name                           Value                                                      
        ----                           -----                                                      
        WorkingSet                     418377728                                                  
        Name                           powershell_ise                                             
        Id                             3456                                                       
        Handles                        958                                                 
        .Example
        PS C:\> $hash = get-service spooler | ConvertTo-Hashtable -Exclude CanStop,CanPauseandContinue -NoEmpty
        PS C:\> $hash

        Name                           Value                                                      
        ----                           -----                                                      
        ServiceType                    Win32OwnProcess, InteractiveProcess                        
        ServiceName                    spooler                                                    
        ServiceHandle                  SafeServiceHandle                                          
        DependentServices              {Fax}                                                      
        ServicesDependedOn             {RPCSS, http}                                              
        Name                           spooler                                                    
        Status                         Running                                                    
        MachineName                    .                                                          
        RequiredServices               {RPCSS, http}                                              
        DisplayName                    Print Spooler                                              

        This created a hashtable from the Spooler service object, skipping empty 
        properties and excluding CanStop and CanPauseAndContinue.
        .Notes
        Version:  2.0
        Updated:  January 17, 2013
        Author :  Jeffery Hicks (http://jdhitsolutions.com/blog)

        Read PowerShell:
        Learn Windows PowerShell 3 in a Month of Lunches
        Learn PowerShell Toolmaking in a Month of Lunches
        PowerShell in Depth: An Administrator's Guide

        "Those who forget to script are doomed to repeat their work."

        .Link
        http://jdhitsolutions.com/blog/2013/01/convert-powershell-object-to-hashtable-revised
        .Link
        About_Hash_Tables
        Get-Member
        .Inputs
        Object
        .Outputs
        hashtable
    #>

    [cmdletbinding()]

    Param(
        [Parameter(Position=0,Mandatory=$True,
        HelpMessage="Please specify an object",ValueFromPipeline=$True)]
        [ValidateNotNullorEmpty()]
        [object]$InputObject,
        [switch]$NoEmpty,
        [string[]]$Exclude
    )

    Process {
        #get type using the [Type] class because deserialized objects won't have
        #a GetType() method which is what we would normally use.

        $TypeName = [system.type]::GetTypeArray($InputObject).name
        Write-Verbose "Converting an object of type $TypeName"
    
        #get property names using Get-Member
        $names = $InputObject | Get-Member -MemberType properties | 
        Select-Object -ExpandProperty name 

        #define an empty hash table
        $hash = @{}
    
        #go through the list of names and add each property and value to the hash table
        $names | ForEach-Object {
            #only add properties that haven't been excluded
            if ($Exclude -notcontains $_) {
                #only add if -NoEmpty is not called and property has a value
                if ($NoEmpty -AND -Not ($inputobject.$_)) {
                    Write-Verbose "Skipping $_ as empty"
                }
                else {
                    Write-Verbose "Adding property $_"
                    $hash.Add($_,$inputobject.$_)
                }
            } #if exclude notcontains
            else {
                Write-Verbose "Excluding $_"
            }
        } #foreach
        Write-Verbose "Writing the result to the pipeline"
        Write-Output $hash
    }#close process

}
function Convert-SecureStringToString
{
    <#
        .SYNOPSIS
        Decrypts System.Security.SecureString object that were created by the user running the function.  Does NOT decrypt SecureString Objects created by another user. 
        .DESCRIPTION
        Decrypts System.Security.SecureString object that were created by the user running the function.  Does NOT decrypt SecureString Objects created by another user.
        .PARAMETER SecureString
        Required parameter accepts a System.Security.SecureString object from the pipeline or by direct usage of the parameter.  Accepts multiple inputs.
        .EXAMPLE
        Decrypt-SecureString -SecureString $SecureString
        .EXAMPLE
        $SecureString1,$SecureString2 | Decrypt-SecureString
        .LINK
        This function is based on the code found at the following location:
        http://blogs.msdn.com/b/timid/archive/2009/09/09/powershell-one-liner-decrypt-securestring.aspx
        .INPUTS
        System.Security.SecureString
        .OUTPUTS
        System.String
    #>

    [cmdletbinding()]
    param (
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [System.Security.SecureString]$SecureString
    )
    
    BEGIN {}
    PROCESS {
        [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($securestring))
    }
    END {}
}
function Get-GuidFromByteArray
{
    param(
        [byte[]]$GuidByteArray
    )
    New-Object -TypeName guid -ArgumentList (,$GuidByteArray)   
}
function Get-ImmutableIDFromGUID
{
    param(
        [guid]$Guid
    )
    [System.Convert]::ToBase64String($Guid.ToByteArray())
}
function Get-GUIDFromImmutableID
{
    param(
        $ImmutableID
    )
    [GUID][system.convert]::frombase64string($ImmutableID) 
}
function Get-Checksum
{
    Param (
        [parameter(Mandatory=$True)]
        [ValidateScript({Test-FilePath -path $_})]
        [string]$File
        ,
        [ValidateSet("sha1","md5")]
        [string]$Algorithm="sha1"
    )
    $FileObject = Get-Item -Path $File
    $fs = new-object System.IO.FileStream $($FileObject.FullName), "Open"
    $algo = [type]"System.Security.Cryptography.$Algorithm"
    $crypto = $algo::Create()
    $hash = [BitConverter]::ToString($crypto.ComputeHash($fs)).Replace("-", "")
    $fs.Close()
    $hash
}
function Test-Member
{ 
    <# 
        .ForwardHelpTargetName Get-Member 
        .ForwardHelpCategory Cmdlet 
    #> 
    [CmdletBinding()] 
    param( 
        [Parameter(ValueFromPipeline=$true)] 
        [System.Management.Automation.PSObject] 
        ${InputObject}, 

        [Parameter(Position=0)] 
        [ValidateNotNullOrEmpty()] 
        [System.String[]] 
        ${Name}, 

        [Alias('Type')] 
        [System.Management.Automation.PSMemberTypes] 
        ${MemberType}, 

        [System.Management.Automation.PSMemberViewTypes] 
        ${View}, 

        [Switch] 
        ${Static}, 

        [Switch] 
        ${Force} 
    ) 
    begin { 
        try { 
            $outBuffer = $null 
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) 
            { 
                $PSBoundParameters['OutBuffer'] = 1 
            } 
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Get-Member', [System.Management.Automation.CommandTypes]::Cmdlet) 
            $scriptCmd = {& $wrappedCmd @PSBoundParameters | ForEach-Object -Begin {$members = @()} -Process {$members += $_} -End {$members.Count -ne 0}} 
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin) 
            $steppablePipeline.Begin($PSCmdlet) 
        } 
        catch { 
            throw 
        } 
    } 
    process { 
        try { 
            $steppablePipeline.Process($_) 
        } 
        catch { 
            throw 
        } 
    } 
    end { 
        try { 
            $steppablePipeline.End() 
        } 
        catch { 
            throw 
        } 
    } 
}
function Test-IP
{
#https://gallery.technet.microsoft.com/scriptcenter/A-short-tip-to-validate-IP-4f039260
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -match [IPAddress]$_ })]
        [String]$ip    
    )
    $ip
}
Function Test-FilePath
{
[cmdletbinding()]
param(
[parameter(Mandatory = $true)]
[string]$path
)
if (Test-Path -Path $path)
{
    $item = Get-Item -Path $path
    if ($item.GetType().fullname -eq 'System.IO.FileInfo')
    {Write-Output $true}
    else
    {Write-Output $false}
}
else
{Write-Output $false}
}
Function Test-DirectoryPath
{
[cmdletbinding()]
param(
[parameter(Mandatory = $true)]
[string]$path
)
if (Test-Path -Path $path)
{
    $item = Get-Item -Path $path
    if ($item.GetType().fullname -eq 'System.IO.DirectoryInfo')
    {Write-Output $true}
    else
    {Write-Output $false}
}
else
{Write-Output $false}
}
function Test-IsWriteableDirectory
{
#Credits to the following:
#http://poshcode.org/2236
#http://stackoverflow.com/questions/9735449/how-to-verify-whether-the-share-has-write-access
    [CmdletBinding()]
    param (
        [parameter()]
        [ValidateScript({
            $IsContainer = Test-Path -Path ($_) -PathType Container
            if ($IsContainer) 
            {
                $Item = Get-Item -Path $_ 
                if ($item.PsProvider.Name -eq 'FileSystem')
                {
                    $true
                }
                else
                {
                    $false
                }
            }
            else
            {
                $false
            }
        })]
        [string]$Path
    )
    try {
        $testPath = Join-Path $Path ([IO.Path]::GetRandomFileName())
            New-Item -Path $testPath -ItemType File -ErrorAction Stop > $null
        $true
    } catch {
        $false
    } finally {
        Remove-Item $testPath -ErrorAction SilentlyContinue
    }
}
function Test-CurrentPrincipalIsAdmin
{
    $currentPrincipal = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
}
Function Test-ForLocalModule
{
    Param(
        [parameter(Mandatory=$True)]
        [string]$Name
    )
    If ((Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue) `
        -or (Get-PSSnapin -Name $Name -ErrorAction SilentlyContinue) `
    -or (Get-PSSnapin -Name $Name -Registered -ErrorAction SilentlyContinue)) {
        $True
    }
    Else {$False}
}
Function Test-CommandExists
{
 Param ([string]$command)
 Try {if(Get-Command $command -ErrorAction Stop){$true}}
 Catch {$false}
} #end function Test-CommandExists
function Get-UninstallEntry
{
[cmdletbinding(DefaultParameterSetName = 'SpecifiedProperties')]
param(
[parameter(ParameterSetName = 'Raw')]
[switch]$raw
,
[parameter(ParameterSetName = 'SpecifiedProperties')]
[string[]]$property = @('DisplayName','DisplayVersion','InstallDate','Publisher')
)
    # paths: x86 and x64 registry keys are different
    if ([IntPtr]::Size -eq 4) {
        $path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    else {
        $path = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }
    $UninstallEntries = Get-ItemProperty $path 
    # use only with name and unistall information
    #.{process{ if ($_.DisplayName -and $_.UninstallString) { $_ } }} |
    # select more or less common subset of properties
    #Select-Object DisplayName, Publisher, InstallDate, DisplayVersion, HelpLink, UninstallString |
    # and finally sort by name
    #Sort-Object DisplayName
    if ($raw) {$UninstallEntries | Sort-Object DisplayName}
    else {
        $UninstallEntries | Sort-Object DisplayName | Select-Object -Property $property
    }
} 
function New-TestExchangeAlias
{
[cmdletbinding()]
param
(
[parameter(Mandatory=$true)]
[string]$ExchangeOrganization
)
    $Script:TestExchangeAlias =@{}
    Connect-Exchange -ExchangeOrganization $ExchangeOrganization
    $AllRecipients = Invoke-ExchangeCommand -ExchangeOrganization $exchangeOrganization -cmdlet Get-Recipient -string '-ResultSize Unlimited'
    foreach ($r in $AllRecipients) 
    {
        $alias = $r.alias
        if ($Script:TestExchangeAlias.ContainsKey($alias)) 
        {
            $Script:TestExchangeAlias.$alias += $r.guid.tostring()
        }
        else 
        {
            $Script:TestExchangeAlias.$alias = @()
            $Script:TestExchangeAlias.$alias += $r.guid.tostring()
        }
    }
}
Function Test-ExchangeAlias
{
[cmdletbinding()]
param(
[string]$Alias
,
[string[]]$ExemptObjectGUIDs
,
[switch]$RefreshAliasData
,
[switch]$ReturnConflicts
,
[parameter(Mandatory=$true)]
[string]$ExchangeOrganization
)
#Populate the Global TestExchangeAlias Hash Table if needed
if (Test-Path -Path variable:Script:TestExchangeAlias) 
{
    if ($RefreshAliasData) 
    {
        Write-Log -message "Running New-TestExchangeAlias"
        New-TestExchangeAlias -ExchangeOrganization $ExchangeOrganization
    }
}
else 
{
    Write-Log -message "Running New-TestExchangeAlias"
    New-TestExchangeAlias -ExchangeOrganization $ExchangeOrganization
}
#Test the Alias
if ($Script:TestExchangeAlias.ContainsKey($Alias))
{
    $ConflictingGUIDs = @($Script:TestExchangeAlias.$Alias | Where-Object {$_ -notin $ExemptObjectGUIDs})
    if ($ConflictingGUIDs.count -gt 0) {
        if ($ReturnConflicts) {
            Return $ConflictingGUIDs
        }
        else {
            Write-Output $false
        }
    }
    else {
        Write-Output $true
    }
}
else {
    Write-Output $true
}
}
Function Add-ExchangeAliasToTestExchangeAlias 
{
[cmdletbinding()]
param(
    [string]$Alias
    ,
    [string]$ObjectGUID #should be the AD ObjectGuid
)
    if ($Script:TestExchangeAlias.ContainsKey($alias))
    {
        Write-Log -Message "Alias already exists in the TestExchangeAlias Table" -EntryType Failed
        Write-Output $false
    }
    else
    {
        $Script:TestExchangeAlias.$alias = @()
        $Script:TestExchangeAlias.$alias += $ObjectGUID
    }
}
function New-TestExchangeProxyAddress
{
[cmdletbinding()]
param
(
[parameter(Mandatory=$true)]
[string]$ExchangeOrganization
)
    $Script:TestExchangeProxyAddress =@{}
    Connect-Exchange -ExchangeOrganization $ExchangeOrganization
    $AllRecipients = Invoke-ExchangeCommand -ExchangeOrganization $exchangeOrganization -cmdlet Get-Recipient -string '-ResultSize Unlimited'
    $RecordCount = $AllRecipients.count
    $cr=0
    foreach ($r in $AllRecipients) {
        $cr++
        $writeProgressParams = @{
            Activity = 'Processing Recipient Proxy Addresses for Test-ExchangeProxyAddress.  Building Global Variable which future uses of Test-ExchangeProxyAddress will use unless the -RefreshProxyAddressData parameter is used.'
            Status = "Record $cr of $RecordCount"
            PercentComplete = $cr/$RecordCount * 100
            CurrentOperation = "Processing Recipient: $($r.GUID.tostring())"
        }
        Write-Progress @writeProgressParams
        $ProxyAddresses = $r.EmailAddresses
        foreach ($ProxyAddress in $ProxyAddresses) {
            if ($Script:TestExchangeProxyAddress.ContainsKey($ProxyAddress)) {
                $Script:TestExchangeProxyAddress.$ProxyAddress += $r.guid.tostring()
            }
            else {
                $Script:TestExchangeProxyAddress.$ProxyAddress = @()
                $Script:TestExchangeProxyAddress.$ProxyAddress += $r.guid.tostring()
            }
        }
    }
    Write-Progress @writeProgressParams -Completed
}
Function Test-ExchangeProxyAddress 
{
[cmdletbinding()]
param(
[string]$ProxyAddress
,
[string[]]$ExemptObjectGUIDs
,
[switch]$RefreshProxyAddressData
,
[switch]$ReturnConflicts
,
[parameter(Mandatory=$true)]
[string]$ExchangeOrganization
,
[parameter()]
[ValidateSet('SMTP','X500')]
[string]$ProxyAddressType = 'SMTP'
)
#Populate the Global TestExchangeProxyAddress Hash Table if needed
if (Test-Path -Path variable:Script:TestExchangeProxyAddress)
{
    if ($RefreshProxyAddressData)
    {
        Write-Log -message "Running New-TestExchangeProxyAddress"
        New-TestExchangeProxyAddress -ExchangeOrganization $ExchangeOrganization
    }
}
else
{
    Write-Log -message "Running New-TestExchangeProxyAddress"
    New-TestExchangeProxyAddress -ExchangeOrganization $ExchangeOrganization
}
#Fix the ProxyAddress if needed
if ($ProxyAddress -notlike "$($proxyaddresstype):*")
{
    $ProxyAddress = "$($proxyaddresstype):$ProxyAddress"
}
#Test the ProxyAddress
if ($Script:TestExchangeProxyAddress.ContainsKey($ProxyAddress))
{
    $ConflictingGUIDs = @($Script:TestExchangeProxyAddress.$ProxyAddress | Where-Object {$_ -notin $ExemptObjectGUIDs})
    if ($ConflictingGUIDs.count -gt 0)
    {
        if ($ReturnConflicts)
        {
            Return $ConflictingGUIDs
        }
        else {
            Write-Output $false
        }
    }
    else {
        Write-Output $true
    }
}
else {
    Write-Output $true
}
}
Function Add-ExchangeProxyAddressToTestExchangeProxyAddress
{
[cmdletbinding()]
param(
    [string]$ProxyAddress
    ,
    [string]$ObjectGUID #should be the AD ObjectGuid
    ,
    [parameter()]
    [ValidateSet('SMTP','X500')]
    [string]$ProxyAddressType = 'SMTP'
)

#Fix the ProxyAddress if needed
if ($ProxyAddress -notlike "{$proxyaddresstype}:*")
{
    $ProxyAddress = "${$proxyaddresstype}:$ProxyAddress"
}
#Test the Proxy Address
if ($Script:TestExchangeProxyAddress.ContainsKey($ProxyAddress))
{
    Write-Log -Message "ProxyAddress $ProxyAddress already exists in the TestExchangeProxyAddress Table" -EntryType Failed
    Write-Output $false
}
else
{
    $Script:TestExchangeProxyAddress.$ProxyAddress = @()
    $Script:TestExchangeProxyAddress.$ProxyAddress += $ObjectGUID
}
}#function Add-ExchangeProxyAddressToTestExchangeProxyAddress
Function Test-EmailAddress
{
[cmdletbinding()]
param
(
[string]$EmailAddress
)
#Regex borrowed from: http://www.regular-expressions.info/email.html
$EmailAddress -imatch '^(?=[A-Z0-9][A-Z0-9@._%+-]{5,253}$)[A-Z0-9._%+-]{1,64}@(?:(?=[A-Z0-9-]{1,63}\.)[A-Z0-9]+(?:-[A-Z0-9]+)*\.){1,8}[A-Z]{2,63}$'
}
Function Test-DirectorySynchronization
{
[cmdletbinding()]
Param(
[string]$identity
,
[int]$MaxSyncWaitMinutes = 15
,
#could possibly look this up on the DirSync Server task history?
[int]$DeltaSyncExpectedMinutes = 2
,
$SyncCheckInterval = 15
, 
$ExchangeOrganization = 'OL'
,
$RecipientAttributeToCheck = 'RecipientType'
,
$RecipientAttributeValue
,
[switch]$InitiateSynchronization
)
Begin {}
Process {
    Connect-Exchange -ExchangeOrganization $ExchangeOrganization
    $Recipient = Invoke-ExchangeCommand -cmdlet Get-Recipient -ExchangeOrganization $ExchangeOrganization -string "-Identity $Identity -ErrorAction SilentlyContinue" -ErrorAction SilentlyContinue
    if ($Recipient.$RecipientAttributeToCheck -eq $RecipientAttributeValue) {
        Write-Log -Message "Checking $identity for value $RecipientAttributeValue in attribute $RecipientAttributeToCheck." -EntryType Succeeded  
        Write-Output $true
    }
    elseif ($InitiateSynchronization) {
        Write-Log -Message "Initiating Directory Synchronization and Checking/Waiting for a maximum of $MaxSyncWaitMinutes minutes." -EntryType Notification
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $minutes = 0
        Start-DirectorySynchronization
        do {
            Start-Sleep -Seconds $SyncCheckInterval
            Connect-Exchange -ExchangeOrganization $ExchangeOrganization
            Write-Log -Message "Checking $identity for value $RecipientAttributeValue in attribute $RecipientAttributeToCheck." -EntryType Attempting
            $Recipient = Invoke-ExchangeCommand -cmdlet Get-Recipient -ExchangeOrganization $ExchangeOrganization -string "-Identity $Identity -ErrorAction SilentlyContinue" -ErrorAction SilentlyContinue
            #check if we have already waited the DeltaSyncExpectedMinutes.  If so, request a new directory synchronization
            if (($stopwatch.Elapsed.Minutes % $DeltaSyncExpectedMinutes -eq 0) -and ($stopwatch.Elapsed.Minutes -ne $minutes)) {
                $minutes = $stopwatch.Elapsed.Minutes
                Write-Log -Message "$minutes minutes of a maximum $MaxSyncWaitMinutes minutes elapsed. Initiating additional Directory Synchronization attempt." -EntryType Notification
                Start-DirectorySynchronization
            }
        }
        until ($Recipient.$RecipientAttributeToCheck -eq $RecipientAttributeValue -or $stopwatch.Elapsed.Minutes -ge $MaxSyncWaitMinutes)
        $stopwatch.Stop()
        if ($stopwatch.Elapsed.Minutes -ge $MaxSyncWaitMinutes) {
            Write-Log -Message "Maximum Synchronization Wait Time Met or Exceeded" -EntryType Notification -ErrorLog
        }
        if ($Recipient.$RecipientAttributeToCheck -eq $RecipientAttributeValue) {
            Write-Log -Message "Checking $identity for value $RecipientAttributeValue in attribute $RecipientAttributeToCheck." -EntryType Succeeded
            Write-Output $true
        }
        else {Write-Output $false}
    }
    else {Write-Output $false}
}#Process
End {}
}
#Logging and Data Export Functions
function Get-FirstNonNullEmptyStringVariableValueFromScopeHierarchy
{
Param(
[string]$VariableName
,
[int]$ScopeLevels = 15
,
[int]$timeout = 500 #In Milliseconds
)
$scope = 0
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
do {
    Try {
        $value = Get-Variable -Name $VariableName -ValueOnly -Scope $scope -ErrorAction SilentlyContinue
    }
    Catch {
    }
    $scope++
}
until (-not [string]::IsNullOrWhiteSpace($value) -or $stopwatch.ElapsedMilliseconds -ge $timeout -or $scope -ge $ScopeLevels)
Write-Output $value
}
Function Write-Log
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
        ,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$LogPath
        ,
        [Parameter(Position=2)]
        [switch]$ErrorLog
        ,
        [Parameter(Mandatory=$false,Position=3)]
        [string]$ErrorLogPath
        ,
        [Parameter(Mandatory=$false,Position=4)]
        [ValidateSet('Attempting','Succeeded','Failed','Notification')]
        [string]$EntryType
    )
    #Add the Entry Type to the message or add nothing to the message if there is not EntryType specified - preserves legacy functionality and adds new EntryType capability
    if (-not [string]::IsNullOrWhiteSpace($EntryType)) {$Message = $EntryType + ':' + $Message}
    #check the Log Preference to see if the message should be logged or not
    if ($LogPreference -eq $null -or $LogPreference -eq $true) {
        $writelog++
        #Set the LogPath and ErrorLogPath to the parent scope values if they were not specified in parameter input.  This allows either global or parent scopes to set the path if not set locally
        if ([string]::IsNullOrWhiteSpace($LogPath)) {
            $TrialLogPath = Get-FirstNonNullEmptyStringVariableValueFromScopeHierarchy -VariableName LogPath
            if (-not [string]::IsNullOrWhiteSpace($TrialLogPath)) {
                $Local:LogPath = $TrialLogPath
            }
        }
        if ([string]::IsNullOrWhiteSpace($ErrorLogPath)) {
            $TrialErrorLogPath = Get-FirstNonNullEmptyStringVariableValueFromScopeHierarchy -VariableName ErrorLogPath
            if (-not [string]::IsNullOrWhiteSpace($TrialErrorLogPath)) {
                $Local:ErrorLogPath = $TrialErrorLogPath
            }
        }
        #Write to Log file if LogPreference is not $false and LogPath has been provided
        if (-not [string]::IsNullOrWhiteSpace($LogPath)) {$writelog++}
        else {Write-Error -Message 'No LogPath has been provided.' -ErrorAction SilentlyContinue
        }
        switch ($writelog) {
            2 {
                #send to user specified log or to global default log
                Write-Output -InputObject "$(Get-Date) $Message" | Out-File -FilePath $LogPath -Append
            }#2
            1 {
                if (Test-Path -Path variable:script:UnwrittenLogEntries) {
                    $Script:UnwrittenLogEntries += Write-Output -InputObject "$(Get-Date) $Message" 
                }
                else {
                    $Script:UnwrittenLogEntries = @()
                    $Script:UnwrittenLogEntries += Write-Output -InputObject "$(Get-Date) $Message" 
                }
            }#1
        }#switch
        #if ErrorLog switch is present also write log to Error Log
        if ($ErrorLog) {
            $writeerror++
            if (-not [string]::IsNullOrWhiteSpace($ErrorLogPath)) {$writeerror++}
            switch ($writeerror) {
                2 {
                    Write-Output -InputObject "$(Get-Date) $Message" | Out-File -FilePath $ErrorLogPath -Append
                }#2
                1 {
                    if (Test-Path -Path variable:\UnwrittenErrorLogEntries) {
                        $Script:UnwrittenErrorLogEntries += Write-Output -InputObject "$(Get-Date) $Message" 
                    }
                    else {
                        $Script:UnwrittenErrorLogEntries = @()
                        $Script:UnwrittenErrorLogEntries += Write-Output -InputObject "$(Get-Date) $Message" 
                    }
                }#1
            }#Switch
        }
    }
    #Pass on the message to Write-Verbose if -Verbose was detected
    Write-Verbose -Message $Message
}
Function Write-EndFunctionStatus {
    param($CallingFunction)
Write-Log -Message "$CallingFunction completed."}
Function Write-StartFunctionStatus {
    param($CallingFunction)
Write-Log -Message "$CallingFunction starting."}
Function Export-Data {
[cmdletbinding(DefaultParameterSetName='delimited')]
param(
    $ExportFolderPath = $script:ExportDataPath
    ,
    [string]$DataToExportTitle
    ,
    $DataToExport
    ,
    [parameter(ParameterSetName='xml/json')]
    [int]$Depth = 2
    ,
    [parameter(ParameterSetName='delimited')]
    [parameter(ParameterSetName='xml/json')]
    [ValidateSet('xml','csv','json')]
    [string]$DataType
    ,
    [parameter(ParameterSetName='delimited')]
    [switch]$Append
    ,
    [switch]$ReturnExportFilePath
)
#Determine Export File Path
$stamp = Get-TimeStamp
    switch ($DataType)
    {
        'xml'
        {
            $ExportFilePath = $exportFolderPath +  $Stamp  + $DataToExportTitle + '.xml'
        }#xml
        'json'
        {
            $ExportFilePath = $exportFolderPath +  $Stamp  + $DataToExportTitle + '.json'
        }#json
        'csv'
        {
            if ($Append) {
                $mostrecent = @(get-childitem -Path $ExportFolderPath -Filter "*$DataToExportTitle.csv" | Sort-Object -Property CreationTime -Descending | Select-Object -First 1)
                if ($mostrecent.count -eq 1) {
                    $ExportFilePath = $mostrecent[0].fullname
                }#if
                else {$ExportFilePath = $exportFolderPath +  $Stamp  + $DataToExportTitle + '.csv'}#else
            }#if
            else {$ExportFilePath = $exportFolderPath +  $Stamp  + $DataToExportTitle + '.csv'}#else
        }#csv
    }#switch $dataType
    #Attempt Export of Data to File
    $message = "Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath"
    Write-Log -Message $message -EntryType Attempting
    Try
    {
        switch ($DataType)
        {
            'xml'
            {
                $DataToExport | Export-Clixml -Depth $Depth -Path $ExportFilePath -ErrorAction Stop -Encoding Unicode
            }#xml
            'json'
            {
                $DataToExport | ConvertTo-Json -Depth $Depth -ErrorAction Stop  | Out-File -FilePath $ExportFilePath -Encoding unicode -ErrorAction Stop
            }#json
            'csv'
            {
                if ($append) {$DataToExport | Export-csv -Path $ExportFilePath -NoTypeInformation -ErrorAction Stop -Append}#if
                else {$DataToExport | Export-csv -Path $ExportFilePath -NoTypeInformation -ErrorAction Stop}#else
            }#csv
        }
        if ($ReturnExportFilePath) {Write-Output $ExportFilePath}
        Write-Log -Message $message -EntryType Succeeded
    }#try
    Catch
    {
        Write-Log -Message "FAILED: Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath" -Verbose -ErrorLog
        Write-Log -Message $_.tostring() -ErrorLog
    }#catch
}#Export-Data
function Export-Credential
{
    param(
        [string]$message
        ,
        [string]$username
        ,
        [string[]]$Systems
    )
    $GetCredentialParams=@{}
    if ($message) {$GetCredentialParams.Message = $message}
    if ($username) {$GetCredentialParams.Username = $username}

    $credential = Get-Credential @GetCredentialParams

    $ExportUserName = $credential.UserName
    $ExportPassword = ConvertFrom-SecureString -Securestring $credential.Password

    $exportCredential = [pscustomobject]@{
        UserName = $ExportUserName
        Password = $ExportPassword
        Systems = @($systems)
    }
    Write-Output $exportCredential
}
Function Remove-AgedFiles
{
[cmdletbinding(SupportsShouldProcess,ConfirmImpact = 'Medium')]
param(
    [int]$Days
    ,
    [parameter()]
    [validatescript({if ((Test-Path $_) -and (Get-Item -Path $_).PSIsContainer) {$true} else {$false}})]
    [string[]]$Directory
)
    $now = Get-Date
    $daysAgo = $now.AddDays(-$days)
    foreach ($d in $Directory)
    {
        $files = Get-ChildItem -Path $d
        $filestodelete = $files | Where-Object {$_.CreationTime -lt $daysAgo -and $_.LastWriteTime -lt $daysAgo}
        $filestodelete | Remove-Item
    }
} 
Function Send-OneShellMailMessage
{
[cmdletbinding(DefaultParameterSetName = 'Normal')]
param(
    [parameter(ParameterSetName = 'Test')]
    [switch]$Test
    ,
    [string]$Body
    ,
    [switch]$BodyAsHtml
    ,
    [parameter(ParameterSetName = 'Test')]
    [parameter(ParameterSetName = 'Normal',Mandatory=$true)]
    [string]$Subject
    ,
    [string[]]$Attachments
    ,
    [parameter(ParameterSetName = 'Test')]
    [parameter(ParameterSetName = 'Normal',Mandatory=$true)]
    [validatescript({Test-EmailAddress -EmailAddress $_})]
    [string[]]$To
    ,
    [parameter()]
    [validatescript({Test-EmailAddress -EmailAddress $_})]
    [string[]]$CC
    ,
    [parameter()]
    [validatescript({Test-EmailAddress -EmailAddress $_})]
    [string[]]$BCC
)
    $MailRelayEndpoint = @($script:currentOrgAdminProfileSystems | Where-Object -FilterScript{$_.Identity -eq $script:CurrentAdminUserProfile.General.MailRelayEndpointToUse})
    switch ($MailRelayEndpoint.Count)
    {
        0
        {
            $errorRecord = New-ErrorRecord -Exception 'system.exception' -ErrorId '0' -ErrorCategory InvalidOperation -Message 'Mail Relay Endpoint Missing from OneShell profile configuration' -TargetObject $Script:CurrentAdminUserProfile
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        1
        {
            $SMTPServer=$MailRelayEndpoint.ServiceAddress
        }
        Default
        {
            $errorRecord = New-ErrorRecord -Exception 'system.exception' -ErrorId '0' -ErrorCategory InvalidOperation -Message 'Mail Relay Endpoint is ambiguous from OneShell profile configuration' -TargetObject $Script:CurrentAdminUserProfile
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }
    if ($test)
    {
        $To = $Script:CurrentAdminUserProfile.General.MailFrom
        $Subject = "Test message from OneShell at $(Get-TimeStamp)"
        $Body = $Subject
    }
    $SendMailParams = @{
        SmtpServer = $SMTPServer
        From = $($Script:CurrentAdminUserProfile.General.MailFrom) #need to add this to the admin user profile creations
        To = $To
        Subject = $Subject
    }
    if ($MailRelayEndpoint.AuthenticationRequired) {$SendMailParams.Credential = $MailRelayEndpoint.Credential}
    if ($MailRelayEndpoint.UseTLS) {$SendMailParams.UseSSL = $true}
    if ($BodyAsHtml) {$SendMailParams.BodyAsHtml = $true}
    if ($PSBoundParameters.ContainsKey('CC')) {$SendMailParams.CC = $CC}
    if ($PSBoundParameters.ContainsKey('BCC')) {$SendMailParams.BCC = $BCC}
    if ($PSBoundParameters.ContainsKey('Body')) {$SendMailParams.Body = $Body}
    if ($PSBoundParameters.ContainsKey('BodyAsHtml')) {$SendMailParams.BodyAsHtml = $BodyAsHtml}
    if ($PSBoundParameters.ContainsKey('Attachments')) {$SendMailParams.Attachments = $Attachments}
    Send-MailMessage @SendMailParams
}
function New-Timer {
<#
.Synopsis
Creates a new countdown timer which can show progress and/or issue voice reports of remaining time.
.Description
Creates a new PowerShell Countdown Timer which can show progress using a progress bar and can issue voice reports of progress according to the Units and Frequency specified.  
Additionally, as the timer counts down, alternative voice report units and frequency may be specified using the altReport parameter.  
.Parameter Units
Specify the countdown timer length units.  Valid values are Seconds, Minuts, Hours, or Days.
.Parameter Length
Specify the length of the countdown timer.  Default units for length are Minutes.  Otherwise length uses the Units specified with the Units Parameter.
.Parameter Voice
Turns on voice reporting of countdown progress according to the specified units and frequency.
.Parameter ShowProgress
Shows countdown progress with a progress bar.  The progress bar updates approximately once per second.
.Parameter Frequency
Specifies the frequency of voice reports of countdown progress in Units
.Parameter altReport
Allows specification of additional voice report patterns as a countdown timer progresses.  Accepts an array of hashtable objects which must contain Keys for Units, Frequency, and Countdownpoint (in Units specified in the hashtable)
#>
[cmdletbinding()]
param(
    [parameter()]
    [validateset('Seconds','Minutes','Hours','Days')]
    $units = 'Minutes'
    ,
    [parameter()]
    $length
    ,
    [switch]$voice
    ,
    [switch]$showprogress
    ,
    [double]$Frequency = 1 
    ,
    [hashtable[]]$altReport #Units,Frequency,CountdownPoint
    ,
    [int]$delay
    )

switch ($units) {
    'Seconds' {$timespan = [timespan]::FromSeconds($length)}
    'Minutes' {$timespan = [timespan]::FromMinutes($length)}
    'Hours' {$timespan = [timespan]::FromHours($length)}
    'Days' {$timespan = [timespan]::FromDays($length)}
}

if ($voice) {
    Add-Type -AssemblyName System.speech                                                                                                                                                               
    $speak = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
    $speak.Rate = 3
    $speak.Volume = 100
}

if ($altReport.Count -ge 1) {
    $vrts=@()
    foreach ($vr in $altReport) {
        $vrt = @{}
        switch ($vr.Units) {
            'Seconds' {
                #convert frequency units to seconds
                $vrt.seconds = $vr.frequency
                $vrt.frequency = $vr.frequency
                $vrt.units = $vr.Units
                $vrt.countdownpoint = $vr.countdownpoint 
            }
            'Minutes' {
                #convert frequency units to seconds
                $vrt.seconds = $vr.frequency * 60
                $vrt.frequency = $vrt.seconds * $vr.frequency
                $vrt.units = $vr.units
                $vrt.countdownpoint = $vr.countdownpoint * 60
            }
            'Hours' {
                #convert frequency units to seconds
                $vrt.seconds = $vr.frequency * 60 * 60
                $vrt.frequency = $vrt.seconds * $vr.frequency
                $vrt.units = $vr.units
                $vrt.countdownpoint = $vr.countdownpoint * 60 * 60
            }
            'Days' {
                #convert frequency units to seconds
                $vrt.seconds = $vr.frequency * 24 * 60 * 60
                $vrt.frequency = $vrt.seconds * $vr.frequency
                $vrt.units = $vr.units
                $vrt.countdownpoint = $vr.countdownpoint * 60 * 60 * 24
            }
        }
        $ovrt = $vrt | Convert-HashTableToObject
        $vrts += $ovrt
    }
    $vrts = @($vrts | sort-object -Property countdownpoint -Descending)
}
if($delay) {New-Timer -units Seconds -length $delay -voice -showprogress -Frequency 1}
$starttime = Get-Date
$endtime = $starttime.AddTicks($timespan.Ticks)

if ($showprogress) {
        $writeprogressparams = @{
            Activity = "Starting Timer for $length $units" 
            Status = 'Running'
            PercentComplete = 0
            CurrentOperation = 'Starting'
            SecondsRemaining = $timespan.TotalSeconds
        }
        Write-Progress @writeprogressparams
}

do { 
    if ($nextsecond) {
        $nextsecond = $nextsecond.AddSeconds(1)
    }
    else {$nextsecond = $starttime.AddSeconds(1)}
    $currenttime = Get-Date
    [timespan]$remaining = $endtime - $currenttime
    $secondsremaining = if ($remaining.TotalSeconds -gt 0) {$remaining.TotalSeconds.toUint64($null)} else {0}
    if ($showprogress) {
        $writeprogressparams.CurrentOperation = 'Countdown'
        $writeprogressparams.SecondsRemaining = $secondsremaining
        $writeprogressparams.PercentComplete = ($secondsremaining/$timespan.TotalSeconds)*100
        $writeprogressparams.Activity = "Running Timer for $length $units" 
        Write-Progress @writeprogressparams
    }

    switch ($Units) {
        'Seconds' {
            $seconds = $Frequency
            if ($voice -and ($secondsremaining % $seconds -eq 0)) {
                if ($Frequency -lt 3) {
                    $speak.Rate = 5
                    $speak.SpeakAsync("$secondsremaining")| Out-Null}
                else {
                    $speak.SpeakAsync("$secondsremaining seconds remaining") | Out-Null
                }
            }
        }
        'Minutes' {
            $seconds = $frequency * 60
            if ($voice -and ($secondsremaining % $seconds -eq 0)) {
                $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                if ($minutesremaining -ge 1) {
                    $speak.SpeakAsync("$minutesremaining minutes remaining")| Out-Null
                }
                else {
                    if ($secondsremaining -ge 1) {
                        $speak.SpeakAsync("$secondsremaining seconds remaining")| Out-Null
                    }
                }
            }
        }
        'Hours' {
            $seconds = $frequency * 60 * 60
            if ($voice -and ($secondsremaining % $seconds -eq 0)) {
                $hoursremaining = $remaining.TotalHours.tostring("#.##")
                if ($hoursremaining -ge 1) {
                    $speak.SpeakAsync("$hoursremaining hours remaining")| Out-Null
                }
                else {
                    $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                    if ($minutesremaining -ge 1) {
                        $speak.SpeakAsync("$minutesremaining minutes remaining")| Out-Null
                    }
                    else {
                        if ($secondsremaining -ge 1) {
                            $speak.SpeakAsync("$secondsremaining seconds remaining")| Out-Null
                        }
                    }
                }
            }
        }
        'Days' {
            $seconds = $frequency * 24 * 60 * 60
            if ($voice -and ($secondsremaining % $seconds -eq 0)) {
                $daysremaining = $remaining.TotalDays.tostring("#.##")
                if ($daysremaining -ge 1) {
                    $speak.SpeakAsync("$daysremaining days remaining")| Out-Null
                }
                else {
                    $hoursremaining = $remaining.TotalHours.tostring("#.##")
                    if ($hoursremaining -ge 1) {
                        $speak.SpeakAsync("$hoursremaining hours remaining")| Out-Null
                    }
                    else {
                        $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                        if ($minutesremaining -ge 1) {
                            $speak.SpeakAsync("$minutesremaining minutes remaining")| Out-Null
                        }
                        else {
                            if ($secondsremaining -ge 1) {
                                $speak.SpeakAsync("$secondsremaining seconds remaining")| Out-Null
                            }
                        }
                    }
                        
                }
            }
        }
    }
    $currentvrt = $vrts | ? countdownpoint -ge $($secondsremaining - 1) | Select-Object -First 1
    if ($currentvrt) {
        $Frequency = $currentvrt.frequency
        $Units = $currentvrt.units
        $vrts = $vrts | ? countdownpoint -ne $currentvrt.countdownpoint
    }
    Start-Sleep -Milliseconds $($nextsecond - (get-date)).TotalMilliseconds
}
until ($secondsremaining -eq 0)
if ($showprogress) {
    $writeprogressparams.completed = $true
    $writeprogressparams.Activity = "Completed Timer for $length $units" 
    Write-Progress @writeprogressparams
}
}
#User Input Functions
Function Read-AnyKey {   
    param(
        [string]$prompt
        ,
        [int]$secondsToWait
    )
    Write-Host -NoNewline $prompt
    $secondsCounter = 0
    $subCounter = 0
    While ( (!$host.ui.rawui.KeyAvailable) -and ($count -lt $secondsToWait) ){
        start-sleep -m 10
        $subCounter = $subCounter + 10
        if($subCounter -eq 1000)
        {
            $secondsCounter++
            $subCounter = 0
            Write-Host -NoNewline "."
        }       
        If ($secondsCounter -eq $secondsToWait) { 
            Write-Host "`r`n" #yuck?
            Write-Output $false
        }
    }
    Write-Host "`r`n" #yuck?
    Write-Output $true;
}
function Read-InputBoxDialog { # Show input box popup and return the value entered by the user. 
    param(
        [string]$Message
        , [string]$WindowTitle
        , [string]$DefaultText
    )

    Add-Type -AssemblyName Microsoft.VisualBasic     
    $inputbox = [Microsoft.VisualBasic.Interaction]::InputBox($Message, $WindowTitle, $DefaultText)
    Write-Output $inputbox
} 
function Read-OpenFileDialog {
    param(
        [string]$WindowTitle
        ,
        [string]$InitialDirectory
        ,
        [string]$Filter = "All files (*.*)|*.*"
        ,
    [switch]$AllowMultiSelect)
    Add-Type -AssemblyName System.Windows.Forms
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = $WindowTitle
    if (![string]::IsNullOrWhiteSpace($InitialDirectory)) { $openFileDialog.InitialDirectory = $InitialDirectory }
    $openFileDialog.Filter = $Filter
    if ($AllowMultiSelect) { $openFileDialog.MultiSelect = $true }
    $openFileDialog.ShowHelp = $true
    # Without this line the ShowDialog() function may hang depending on system configuration and running from console vs. ISE.     
    $openFileDialog.ShowDialog() > $null
    if ($AllowMultiSelect) { Write-Output $openFileDialog.Filenames } else { Write-Output $openFileDialog.Filename } 
}  
function Read-Choice {     
    Param(
        [System.String]$Message
        ,       
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]$Choices
        ,         
        [System.Int32]$DefaultChoice = 1
        ,         
        [System.String]$Title = [string]::Empty 
    )   
    $choiceCount = -1     
    [System.Management.Automation.Host.ChoiceDescription[]]$Poss = 
    $Choices | ForEach-Object {
        $choiceCount++
        New-Object System.Management.Automation.Host.ChoiceDescription "&$choiceCount $($_)", "Sets $_ as an answer."      
    }       
    $Host.UI.PromptForChoice( $Title, $Message, $Poss, $DefaultChoice )     
}
function Read-FolderBrowserDialog {# Show an Open Folder Dialog and return the directory selected by the user. 
    Param(
        [string]$Message
        , [string]$InitialDirectory
        , [switch]$NoNewFolderButton
    ) 

    $browseForFolderOptions = 0     
    if ($NoNewFolderButton) { $browseForFolderOptions += 512 }       
    $app = New-Object -ComObject Shell.Application     
    $folder = $app.BrowseForFolder(0, $Message, $browseForFolderOptions, $InitialDirectory)     
    if ($folder) { $selectedDirectory = $folder.Self.Path } else { $selectedDirectory = '' }     
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($app) > $null    
    Write-Output $selectedDirectory
}
##########################################################################################################
#Remote System Connection Functions
##########################################################################################################
Function Import-RequiredModule {
    [cmdletbinding()]
    param
    (
    [parameter(Mandatory=$true)]
    [ValidateSet('ActiveDirectory','MSOnline','AADRM','LyncOnlineConnector','POSH_ADO_SQLServer')]
    [string]$ModuleName
    )
    #Do any custom environment preparation per specific module
    switch ($ModuleName) 
    {
        'ActiveDirectory' 
        {
            #Suppress Creation of the Default AD Drive with current credentials
            $Env:ADPS_LoadDefaultDrive = 0
        }
        Default 
        {}
    }
    #Test if the module required is already loaded:
    $ModuleLoaded = @(Get-Module | Where-Object Name -eq $ModuleName)
    if ($ModuleLoaded.count -eq 0) 
    {
        try 
        {
            $message = "Import the $ModuleName Module"
            Write-Log -message $message -EntryType Attempting
            Import-Module -Name $ModuleName -Global -ErrorAction Stop
            Write-Log -message $message -EntryType Succeeded
            Write-Output $true
        }#try
        catch 
        {
            $myerror = $_
            Write-Log -message $message -Verbose -ErrorLog -EntryType Failed 
            Write-Log -message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror)
        }#catch
    }#if
    else 
    {
        Write-Log -EntryType Notification -Message "$ModuleName Module is already loaded."
        Write-Output $true
    }
}#Import-RequiredModule
Function Connect-Exchange {
    [cmdletbinding(DefaultParameterSetName = 'Organization')]
    Param(
        [parameter(ParameterSetName='OnPremises')]
        [string]$Server
        ,
        [parameter(ParameterSetName='OnPremises')]
        [ValidateSet('Basic','Kerberos','Negotiate','Default','CredSSP','Digest','NegotiateWithImplicitCredential')]
        [string]$AuthMethod
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        $Credential
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [string]$CommandPrefix
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [string]$SessionNamePrefix
        ,
        [parameter(ParameterSetName='Online')]
        [switch]$online
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [boolean]$ProxyEnabled = $False
        ,
        [parameter(ParameterSetName='OnPremises')]
        [string[]]$PreferredDomainControllers
        <#    ,
            [parameter(ParameterSetName='Organization')]
        [switch]$Profile#>
    )
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'ExchangeOrganization'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        $ParameterAttribute.ParameterSetName = 'Organization'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ExchangeOrganizations' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        $AliasSet = @('Org','ExchangeOrg')
        $AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        $AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    Begin {
        switch ($PSCmdlet.ParameterSetName) {
            'Organization' {
                $Org = $PSBoundParameters[$ParameterName]
                $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object {$_.name -eq $org}
                $orgtype = $orgobj.orgtype
                $credential = $orgobj.credential
                $orgName = $orgobj.Name
                $CommandPrefix = $orgobj.CommandPrefix
                $Server =  $orgobj.Server
                $AuthMethod = $orgobj.authmethod
                $ProxyEnabled = $orgobj.ProxyEnabled
                $SessionName = "$orgName-Exchange"
                $PreferredDomainControllers = if (-not [string]::IsNullOrWhiteSpace($orgobj.PreferredDomainControllers)) {@($orgobj.PreferredDomainControllers)} else {$null}
            }
            'Online'{
                $orgtype = $PSCmdlet.ParameterSetName
                $SessionName = "$SessionNamePrefix-Exchange"
                $orgName = $SessionNamePrefix
            }
            'OnPremises'{
                $orgtype = $PSCmdlet.ParameterSetName
                $SessionName = "$SessionNamePrefix-Exchange"
                $orgName = $SessionNamePrefix
            }
        }
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
    }
    Process {
        try {
            $existingsession = Get-PSSession -Name $SessionName -ErrorAction Stop
            #Write-Log -Message "Existing session for $SessionName exists"
            #Write-Log -Message "Checking $SessionName State" 
            if ($existingsession.State -ne 'Opened') {
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'"
                Remove-PSSession -Name $SessionName 
                $UseExistingSession = $False
            }#if
            else {
                #Write-Log -Message "$SessionName State is 'Opened'. Using existing Session." 
                switch ($orgtype){
                    'OnPremises'{
                        try {
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-ExchangeCommand -cmdlet Set-AdServerSettings -ExchangeOrganization $orgName -string '-viewentireforest $true -erroraction Stop -WarningAction SilentlyContinue' -WarningAction SilentlyContinue
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#OnPremises
                    'Online' {
                        try {
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-ExchangeCommand -cmdlet Get-AddressBookPolicy -ExchangeOrganization $orgName -string '-erroraction Stop'
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#Online
                }#switch $orgtype
            }#else
        }#try
        catch {
            Write-Log -Message "No existing session for $SessionName exists" 
            $UseExistingSession = $false
        }#catch
        switch ($UseExistingSession) {
            $true {}#$true
            $false {
                $sessionParams = @{
                    ConfigurationName = 'Microsoft.Exchange'
                    Credential = $Credential
                    Name = $SessionName
                }
                switch ($orgtype) {
                    'Online' {
                        $sessionParams.ConnectionURI = 'https://outlook.office365.com/powershell-liveid/'
                        $sessionParams.Authentication = 'Basic'
                        $sessionParams.AllowRedirection = $true
                        If ($ProxyEnabled) {
                            $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                            Write-Log -message 'Using Proxy Configuration'
                        }
                    }
                    'OnPremises' {
                        #add option for https + Basic Auth    
                        $sessionParams.ConnectionURI = "http://" + $Server + "/PowerShell/"
                        $sessionParams.Authentication = $AuthMethod
                        if ($ProxyEnabled) {
                            $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                            Write-Log -message 'Using Proxy Configuration'
                        }
                    }
                }
                try {
                    Write-Log -Message "Attempting: Creation of Remote Session $SessionName to Exchange System $orgName"
                    $sessionobj = New-PSSession @sessionParams -ErrorAction Stop
                    Write-Log -Message "Succeeded: Creation of Remote Session to Exchange System $orgName"
                    Write-Log -Message "Attempting: Import Exchange Session $SessionName and Module" 
                    $ImportPSSessionParams = @{
                        AllowClobber = $true
                        DisableNameChecking = $true
                        ErrorAction = 'Stop'
                        Session = Get-PSSession -Name $SessionName
                    }
                    $ImportModuleParams = @{
                        DisableNameChecking = $true
                        ErrorAction = 'Stop'
                        Global = $true
                    }
                    if (-not [string]::IsNullOrWhiteSpace($CommandPrefix)) {
                        $ImportPSSessionParams.Prefix = $CommandPrefix
                        $ImportModuleParams.Prefix = $CommandPrefix
                    }
                    Import-Module (Import-PSSession @ImportPSSessionParams) @ImportModuleParams
                    Write-Log -Message "Succeeded: Import Exchange Session $SessionName and Module" 
                    if ($orgtype -eq 'OnPremises') {
                        if ($PreferredDomainControllers.Count -ge 1) {
                            $splat=@{ViewEntireForest=$true;SetPreferredDomainControllers=$PreferredDomainControllers;ErrorAction='Stop'}
                        }#if
                        else {
                            $splat=@{ViewEntireForest=$true;ErrorAction='Stop'}
                        }#else    
                        Invoke-ExchangeCommand -cmdlet Set-ADServerSettings -ExchangeOrganization $orgName -splat $splat
                    }#if
                    Write-Output $true
                    Write-Log -Message "Succeeded: Connect to Exchange System $orgName"
                }#try
                catch {
                    Write-Log -Message "Failed: Connect to Exchange System $orgName" -Verbose -ErrorLog
                    Write-Log -Message $_.tostring() -ErrorLog
                    Write-Output $False
                    $_
                }#catch
            }#$false
        }#switch
    }#process
}#function Connect-Exchange
Function Connect-Skype {
    [cmdletbinding(DefaultParameterSetName = 'Organization')]
    Param(
        [parameter(ParameterSetName='OnPremises')]
        [string]$Server
        ,
        [parameter(ParameterSetName='OnPremises')]
        [ValidateSet('Basic','Kerberos','Negotiate','Default','CredSSP','Digest','NegotiateWithImplicitCredential')]
        [string]$AuthMethod
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        $Credential
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [string]$CommandPrefix
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [string]$SessionNamePrefix
        ,
        [parameter(ParameterSetName='Online')]
        [switch]$online
        ,
        [parameter(ParameterSetName='OnPremises')]
        [parameter(ParameterSetName='Online')]
        [boolean]$ProxyEnabled = $False
        ,
        [parameter(ParameterSetName='OnPremises')]
        [string[]]$PreferredDomainControllers
        <#    ,
            [parameter(ParameterSetName='Organization')]
        [switch]$Profile#>
    )
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'SkypeOrganization'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        $ParameterAttribute.ParameterSetName = 'Organization'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SkypeOrganizations' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        $AliasSet = @('Org','SkypeOrg')
        $AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        $AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    Begin {
        switch ($PSCmdlet.ParameterSetName) {
            'Organization' {
                $Org = $PSBoundParameters[$ParameterName]
                $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'SkypeOrganizations' | Where-Object {$_.name -eq $org}
                $orgtype = $orgobj.orgtype
                $credential = $orgobj.credential
                $orgName = $orgobj.Name
                $CommandPrefix = $orgobj.CommandPrefix
                $Server =  $orgobj.Server
                $AuthMethod = $orgobj.authmethod
                $ProxyEnabled = $orgobj.ProxyEnabled
                $SessionName = "$orgName-Skype"
                $PreferredDomainControllers = if (-not [string]::IsNullOrWhiteSpace($orgobj.PreferredDomainControllers)) {@($orgobj.PreferredDomainControllers)} else {$null}
            }
            'Online'{
                $orgtype = $PSCmdlet.ParameterSetName
                $SessionName = "$SessionNamePrefix-Skype"
                $orgName = $SessionNamePrefix
            }
            'OnPremises'{
                $orgtype = $PSCmdlet.ParameterSetName
                $SessionName = "$SessionNamePrefix-Skype"
                $orgName = $SessionNamePrefix
            }
        }
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
    }
    Process {
        try
        {
            $existingsession = Get-PSSession -Name $SessionName -ErrorAction Stop
            Write-Log -Message "Existing session for $SessionName exists"
            Write-Log -Message "Checking $SessionName State" 
            if ($existingsession.State -ne 'Opened')
            {
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'"
                Remove-PSSession -Name $SessionName 
                $UseExistingSession = $False
            }#if
            else
            {
                #Write-Log -Message "$SessionName State is 'Opened'. Using existing Session." 
                switch ($orgtype)
                {
                    'OnPremises'
                    {
                        try
                        {
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-SkypeCommand -cmdlet 'Get-CsTenantFederationConfiguration' -SkypeOrganization $orgName -string '-erroraction Stop' -WarningAction SilentlyContinue
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch
                        {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#OnPremises
                    'Online'
                    {
                        try
                        {
                            try
                            {Import-RequiredModule -ModuleName LyncOnlineConnector -ErrorAction Stop}
                            catch
                            {
                                Write-Log -Message 'Unable to load LyncOnlineConnector Module' -EntryType Failed -ErrorLog -Verbose
                                Write-Log -Message $_.tostring() -ErrorLog 
                                Write-Output $false
                            }
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-SkypeCommand -cmdlet 'Get-CsTenantFederationConfiguration' -SkypeOrganization $orgName -string '-erroraction Stop'
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch
                        {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#Online
                }#switch $orgtype
            }#else
        }#try
        catch
        {
            Write-Log -Message "No existing session for $SessionName exists" 
            $UseExistingSession = $false
        }#catch
        switch ($UseExistingSession) {
            $true {}#$true
            $false {
                $sessionParams = @{
                    Credential = $Credential
                    Name = $SessionName
                }
                switch ($orgtype) {
                    'Online' {
                        <#If ($ProxyEnabled) {
                            $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                            Write-Log -message 'Using Proxy Configuration'
                        }
                        #>
                    }
                    'OnPremises' {
                        #add option for https + Basic Auth    
                        <#
                        $sessionParams.ConnectionURI = "http://" + $Server + "/PowerShell/"
                        $sessionParams.Authentication = $AuthMethod
                        if ($ProxyEnabled) {
                            $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                            Write-Log -message 'Using Proxy Configuration'
                        }
                        #>
                    }
                }
                try {
                    $message = "Creation of Remote Session $SessionName to Skype System $orgName"
                    Write-Log -Message $message -entryType Attempting
                    $sessionobj = New-cSonlineSession @sessionParams -ErrorAction Stop
                    Write-Log -Message $message -EntryType Succeeded
                    Write-Log -Message "Attempting: Import Skype Session $SessionName and Module" 
                    $ImportPSSessionParams = @{
                        AllowClobber = $true
                        DisableNameChecking = $true
                        ErrorAction = 'Stop'
                        Session = Get-PSSession -Name $SessionName
                    }
                    $ImportModuleParams = @{
                        DisableNameChecking = $true
                        ErrorAction = 'Stop'
                        Global = $true
                    }
                    if (-not [string]::IsNullOrWhiteSpace($CommandPrefix)) {
                        $ImportPSSessionParams.Prefix = $CommandPrefix
                        $ImportModuleParams.Prefix = $CommandPrefix
                    }
                    Import-Module (Import-PSSession @ImportPSSessionParams) @ImportModuleParams
                    Write-Log -Message "Succeeded: Import Skype Session $SessionName and Module" 
                    Write-Output $true
                    Write-Log -Message "Succeeded: Connect to Skype System $orgName"
                }#try
                catch {
                    Write-Log -Message "Failed: Connect to Skype System $orgName" -Verbose -ErrorLog
                    Write-Log -Message $_.tostring() -ErrorLog
                    Write-Output $False
                    $_
                }#catch
            }#$false
        }#switch
    }#process
}#function Connect-Skype
Function Connect-AADSync {
    [cmdletbinding(DefaultParameterSetName = 'Profile')]
    Param(
        [parameter(ParameterSetName='Manual',Mandatory=$true)]
        $Server
        ,[parameter(ParameterSetName='Manual',Mandatory=$true)]
        $Credential
        ,
        [Parameter(ParameterSetName='Manual',Mandatory=$true)]
        [ValidateLength(1,3)]
        [string]$CommandPrefix
        ,
        [switch]$usePrefix
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'AADSyncServer'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 3
        $ParameterAttribute.ParameterSetName = 'Profile'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AADSyncServers' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        #$AliasSet = @('')
        #$AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        #$AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    #Connect to Directory Synchronization
    #Server has to have been enabled for PS Remoting (enable-psremoting)
    #Credential has to be a member of ADSyncAdmins on the AADSync Server
    begin{
        switch ($PSCmdlet.ParameterSetName) {
            'Profile' {
                $SelectedProfile = $PSBoundParameters[$ParameterName]
                $Profile = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'AADSyncServers' | Where-Object {$_.name -eq $selectedProfile}
                $CommandPrefix = $Profile.Name
                $SessionName = "$commandPrefix-AADSync"
                $Server = $Profile.Server
                $Credential = $Profile.Credential
            }#Profile
            'Manual' {
                $SessionName = "$CommandPrefix-AADync"
            }#manual
        }#switch
    }
    Process{
        try {
            $existingsession = Get-PSSession -Name $SessionName -ErrorAction Stop
            #Write-Log -Message "Existing session for $SessionName exists"
            #Write-Log -Message "Checking $SessionName State" 
            if ($existingsession.State -ne 'Opened') {
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'"
                Remove-PSSession -Name $SessionName 
                $UseExistingSession = $False
            }#if
            else {
                #Write-Log -Message "$SessionName State is 'Opened'. Using existing Session." 
                $UseExistingSession = $true
            }#else
        }#try
        catch {
            Write-Log -Message "No existing session for $SessionName exists" 
            $UseExistingSession = $false
        }#catch
        if ($UseExistingSession -eq $False) {
            Write-Log -Message "Connecting to Directory Synchronization Server $server as User $($credential.username)."
            Try {
                $Session = New-PsSession -ComputerName $Server -Credential $Credential -Name $SessionName -ErrorAction Stop
                Write-Log -Message "Attempting: Import AADSync Session $SessionName and Module" 
                if ($usePrefix) {
                    Invoke-Command -Session $Session -ScriptBlock {Import-Module ADSync -DisableNameChecking} -ErrorAction Stop
                    Import-Module (Import-PSSession -Session $Session -Module ADSync -DisableNameChecking -ErrorAction Stop -Prefix $CommandPrefix) -Global -DisableNameChecking -ErrorAction Stop -Prefix $CommandPrefix
                }
                else {
                    Invoke-Command -Session $Session -ScriptBlock {Import-Module ADSync -DisableNameChecking} -ErrorAction Stop
                    Import-Module (Import-PSSession -Session $Session -Module ADSync -DisableNameChecking -ErrorAction Stop) -Global -DisableNameChecking -ErrorAction Stop 
                }
                Write-Log -Message "Succeeded: Import AADSync Session $SessionName and Module" 
                if ((Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock {Get-Command -Module ADSync | select -ExpandProperty Name}) -contains 'Get-ADSyncScheduler') 
                {
                if ($usePrefix) {$functionstring = "Function Global:Start-$($CommandPrefix)DirectorySynchronization {"}
                else {$functionstring = 'Function Global:Start-DirectorySynchronization {'}
                $functionstring += 
                @"
    param([switch]`$full)
    Write-Warning -Message 'Start-DirectorySynchronization is deprecated. Please replace with Start-ADSyncSyncCycle.'
    if (`$full) {
        `$scriptblock = [ScriptBlock]::Create('Start-ADSyncSyncCycle -PolicyType Initial')
        Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock `$scriptblock | Write-Verbose -verbose
    }#if
    else {
        `$scriptblock = [ScriptBlock]::Create('Start-ADSyncSyncCycle -PolicyType Delta')
        Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock `$scriptblock | Write-Verbose -verbose
    }#else
}#Function Global:Start-DirectorySynchronization
"@
                }
                else 
                {
                if ($usePrefix) {$functionstring = "Function Global:Start-$($CommandPrefix)DirectorySynchronization {"}
                else {$functionstring = 'Function Global:Start-DirectorySynchronization {'}
                $functionstring += 
                @"
    param([switch]`$full)
    if (`$full) {
        `$scriptblock = [ScriptBlock]::Create('SCHTASKS /run /TN "Azure AD Sync Scheduler Full"')
        Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock `$scriptblock | Write-Verbose -verbose
    }#if
    else {
        `$scriptblock = [ScriptBlock]::Create('SCHTASKS /run /TN "Azure AD Sync Scheduler"')
        Invoke-Command -Session (Get-PSSession -Name $SessionName) -ScriptBlock `$scriptblock | Write-Verbose -verbose
    }#else
}#Function Global:Start-DirectorySynchronization
"@
                }
                $function = [scriptblock]::Create($functionstring)
                &$function
                Write-Output $true
            }#Try
            Catch {
                Write-Log -Verbose -Message "ERROR: Connection to $server failed." -ErrorLog
                Write-Log -Verbose -Message $_.tostring() -ErrorLog
                Write-Output $false
            }#catch
        }#if
    }#process 
}#Function Connect-AADSync
Function Connect-ADInstance {
    [cmdletbinding(DefaultParameterSetName = 'Instance')]
    param(
        [parameter(Mandatory=$True,ParameterSetName='Manual')]
        [string]$Name
        ,
        [parameter(Mandatory = $true,ParameterSetName='Manual')]
        [string]$server
        ,
        [parameter(Mandatory = $true,ParameterSetName='Manual')]
        $Credential
        ,
        [parameter(Mandatory = $true,ParameterSetName='Manual')]
        [string]$description
        ,
        [parameter(Mandatory = $true,ParameterSetName='Manual')]
        [boolean]$GlobalCatalog = $true
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'ActiveDirectoryInstance'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        $ParameterAttribute.ParameterSetName = 'Instance'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        $AliasSet = @('AD','Instance')
        $AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        $AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    Begin {
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }#$ProcessStatus
        Switch ($PSCmdlet.ParameterSetName) {
            'Instance' {
                $ADI = $PSBoundParameters[$ParameterName]
                $ADIobj = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Where-Object {$_.name -eq $ADI}
                $name = $ADIobj.Name
                $server = $ADIobj.Server
                $Credential = $ADIobj.credential
                $Description = $ADIobj.description
                $GlobalCatalog = $ADIobj.GlobalCatalog
            }#instance
            'Manual' {
            }#manual
        }#switch
    }#begin
    Process {
        try {
            $existingdrive = Get-PSDrive -Name $Name -ErrorAction Stop
            #Write-Log -Message "Existing drive  for $name exists"
            #Write-Log -Message "Checking $SessionName State" 
            if ($existingdrive) {
                Write-Log -Message "Existing Drive for $Name exists." 
                Write-Log -Message "Attempting: Validate Operational Status of Drive $name." 
                try {
                    $result = @(Get-ChildItem -Path "$name`:\" -ErrorAction Stop)
                    If ($result.Count -ge 1) {
                        Write-Log -Message "Succeeded: Validate Operational Status of Drive $name."
                        $UseExistingDrive = $True
                    }
                    else {
                        Remove-PSDrive -Name $name -ErrorAction Stop
                        throw "No Results for Get-ChildItem for Path $name`:\"
                    }
                }
                Catch {
                    Write-Log -Message "Failed: Validate Operational Status of Drive $name." -ErrorLog
                    $UseExistingDrive = $False
                }
            }#if
            else {
                $UseExistingDrive = $false
            }#else
        }#try
        catch {
            Write-Log -Message "No existing PSDrive for $Name exists" 
            $UseExistingDrive = $false
        }#catch
        if ($UseExistingDrive -eq $False) {
            if ($GlobalCatalog) {$server = $server + ':3268'}
            $NewPSDriveParams = @{
                Name = $name
                Server = $server
                Root = '//RootDSE/'
                Scope = 'Global'
                PSProvider = 'ActiveDirectory'
                ErrorAction = 'Stop'
            }#newpsdriveparams
            if ($Description) {$NewPSDriveParams.Description = $Description}
            if ($credential) {$NewPSDriveParams.Credential = $Credential}
            try {
                Write-Log -Message "Attempting: Connect PS Drive $name`: to $Description"
                if (Import-RequiredModule -ModuleName ActiveDirectory -ErrorAction Stop) {
                    New-PSDrive @NewPSDriveParams | Out-Null
                }#if
                Write-Log -Message "Succeeded: Connect PS Drive $name`: to $Description"
                Write-Output $true
            }#try
            catch {
                Write-Log -Message "FAILED: Connect PS Drive $name`: to $Description" -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                $_
                $false
            }#catch
        } #if
    }#process  
}#Connect-ADForest
Function Connect-AzureAD {
    [cmdletbinding(DefaultParameterSetName = 'Tenant')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'Tenant'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        $ParameterAttribute.ParameterSetName = 'Tenant'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        #$AliasSet = @('Org','ExchangeOrg')
        #$AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        #$AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    #Connect to Windows Azure Active Directory
    begin{
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Tenant' 
            {
                $Identity = $PSBoundParameters[$ParameterName]
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' 
            {
            }#manual
        }#switch
    }#begin
    process 
    {
            try 
            {
                $ModuleStatus = Import-RequiredModule -ModuleName MSOnline -ErrorAction Stop
                Write-Log -Message "Attempting: Connect to Windows Azure AD Administration with User $($Credential.username)."
                Connect-MsolService -Credential $Credential -ErrorAction Stop
                Write-Log -Message "Succeeded: Connect to Windows Azure AD Administration with User $($Credential.username)."
                Write-Output $true
            }
            Catch 
            {
                Write-Log -Message "FAILED: Connect to Windows Azure AD Administration with User $($Credential.username)." -Verbose -ErrorLog
                Write-Log -Message $_.tostring()
                Write-Output $false 
            }
    } #process
    <#Proxy for connect-msolservice
        netsh winhttp import proxy source=ie
        [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    #>
}#function Connect-AzureAD
Function Connect-AADRM {
    [cmdletbinding(DefaultParameterSetName = 'Tenant')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'Tenant'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        $ParameterAttribute.ParameterSetName = 'Tenant'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        #$AliasSet = @('Org','ExchangeOrg')
        #$AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        #$AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    #Connect to Windows Azure Active Directory Rights Management
    begin{
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Tenant' {
                $Identity = $PSBoundParameters[$ParameterName]
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' {
            }#manual
        }#switch
    }#begin
    process 
    {
        try 
        {
            $ModuleStatus = Import-RequiredModule -ModuleName AADRM -ErrorAction Stop
            Write-Log -Message "Attempting: Connect to Azure AD RMS Administration with User $($Credential.username)."
            Connect-AadrmService -Credential $Credential -errorAction Stop | Out-Null
            Write-Log -Message "Succeeded: Connect to Azure AD RMS Administration with User $($Credential.username)."
            Write-Output $true
        }
        catch 
        {
            Write-Log -Message "FAILED: Connect to Azure AD RMS Administration with User $($Credential.username)." -Verbose -ErrorLog
            Write-Log -Message $_.tostring() -ErrorLog
            Write-Output $false 
        }
    }#process
}#function Connect-AADRM 
Function Connect-SQLDatabase {
    [cmdletbinding(DefaultParameterSetName = 'SQLDatabase')]
    Param(
        [parameter(ParameterSetName='Manual')]
        $Credential
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'SQLDatabase'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        $ParameterAttribute.ParameterSetName = 'SQLDatabase'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        #$AliasSet = @('Org','ExchangeOrg')
        #$AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        #$AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    #Connect to Windows Azure Active Directory Rights Management
    begin{
        $ProcessStatus = @{
            Command = $MyInvocation.MyCommand.Name
            BoundParameters = $MyInvocation.BoundParameters
            Outcome = $null
        }
        switch ($PSCmdlet.ParameterSetName) {
            'SQLDatabase' {
                $Identity = $PSBoundParameters[$ParameterName]
                $SQLDatabaseObj = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Where-Object {$_.name -eq $Identity}
                $name = $SQLDatabaseObj.Name
                $SQLServer = $SQLDatabaseObj.Server
                $Instance = $SQLDatabaseObj.Instance
                $Database = $SQLDatabaseObj.Database
                $Credential = $SQLDatabaseObj.credential
                $Description = $SQLDatabaseObj.description
                $Credential = $Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' {
            }#manual
        }#switch
    }#begin
    process 
    {
        try 
        {
            $message = "Import required module POSH_ADO_SQLServer"
            Write-Log -Message $message -EntryType Attempting
            $ModuleStatus = Import-RequiredModule -ModuleName POSH_ADO_SQLServer -ErrorAction Stop
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $myerror = $_
            Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror)
        }
        try
        {
            $message = "Connect to $Description on $SQLServer as User $($Credential.username)."
            Write-Log -Message $message -EntryType Attempting
            Write-Warning -Message "Connect-SQLDatabase currently uses Windows Integrated Authentication to connect to SQL Servers and ignores supplied credentials"
            $SQLConnection = New-SQLServerConnection -server $SQLServer -database $Database -ErrorAction Stop #-user $credential.username -password $($Credential.password | Convert-SecureStringToString)
            $SQLConnectionString = New-SQLServerConnectionString -server $SQLServer -database $Database -ErrorAction Stop
            Write-Log -Message $message -EntryType Succeeded
            $SQLConnection | Add-Member -Name 'Name' -Value $name -MemberType NoteProperty
            Update-SQLConnections -ConnectionName $Name -SQLConnection $SQLConnection
            Update-SQLConnectionStrings -ConnectionName $name -SQLConnectionString $SQLConnectionString
            Write-Output $true
        }
        catch 
        {
            $myerror = $_
            Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
            Write-Log -Message $myerror.tostring() -ErrorLog
            $PSCmdlet.ThrowTerminatingError($myerror) 
        }
    }#process
}#function Connect-SQLDatabase 
Function Connect-PowerShellSystem {
    [cmdletbinding(DefaultParameterSetName = 'Profile')]
    Param(
        [parameter(ParameterSetName='Manual',Mandatory=$true)]
        $ComputerName
        ,[parameter(ParameterSetName='Manual',Mandatory=$true)]
        $Credential
        ,
        [Parameter(ParameterSetName='Manual',Mandatory=$true)]
        [ValidateLength(1,3)]
        [string]$CommandPrefix
        ,
        [switch]$usePrefix
        ,
        [string[]]$ManagementGroups
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'PowerShellSystem'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 3
        $ParameterAttribute.ParameterSetName = 'Profile'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'PowerShellSystems' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        #$AliasSet = @('')
        #$AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        #$AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    #Connect to Directory Synchronization
    #Server has to have been enabled for PS Remoting (enable-psremoting)
    #Credential has to be a member of ADSyncAdmins on the AADSync Server
    begin{
        switch ($PSCmdlet.ParameterSetName) {
            'Profile' {
                $SelectedProfile = $PSBoundParameters[$ParameterName]
                $Profile = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'PowerShellSystems' | Where-Object {$_.name -eq $selectedProfile}
                $SessionName = "$($Profile.Name)"
                $System = $Profile.System
                $Credential = $Profile.Credential
                $ManagementGroups = $Profile.SessionManagementGroups
            }#Profile
            'Manual' {
                $SessionName = $ComputerName
                $System = $ComputerName
            }#manual
        }#switch
    }#begin
    Process{
        try {
            $existingsession = Get-PSSession -Name $SessionName -ErrorAction Stop
            #Write-Log -Message "Existing session for $SessionName exists"
            #Write-Log -Message "Checking $SessionName State" 
            if ($existingsession.State -ne 'Opened') {
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'" -EntryType Notification
                Remove-PSSession -Name $SessionName 
                $UseExistingSession = $False
            }#if
            else {
                #Write-Log -Message "$SessionName State is 'Opened'. Using existing Session." 
                $UseExistingSession = $true
            }#else
        }#try
        catch {
            Write-Log -Message "No existing session for $SessionName exists" -EntryType Notification
            $UseExistingSession = $false
        }#catch
        if ($UseExistingSession -eq $False) {
            $message = "Connecting to System $system as User $($credential.username)."
            Try {
                Write-Log -Message $message -EntryType Attempting
                $Session = New-PsSession -ComputerName $System -Credential $Credential -Name $SessionName -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
                Update-SessionManagementGroups -ManagementGroups $ManagementGroups -Session $SessionName -ErrorAction Stop
                $true
            }#Try
            Catch {
                Write-Log -Verbose -Message $message -ErrorLog -EntryType Failed
                Write-Log -Verbose -Message $_.tostring() -ErrorLog
                $false
            }#catch
        }#if
    }#process 
}#Function Connect-PowerShellSystem
Function Update-SessionManagementGroups {
[cmdletbinding(DefaultParameterSetName = 'Profile')]
Param(
    [parameter(Mandatory=$true)]
    $SessionName
    ,[parameter(Mandatory=$true)]
    [string[]]$ManagementGroups
)#param
foreach ($MG in $ManagementGroups)
{
    $SessionGroup = $MG + '_Sessions'
    #Check if the Session Group already exists
    if (Test-Path -Path "variable:\$SessionGroup") 
    {
    #since the session group already exists, add the session to it if it is not already present
        $existingSessions = Get-Variable -Name $SessionGroup -Scope Global -ValueOnly
        $existingSessionNames = $existingSessions | Select-Object -ExpandProperty Name
        $existingSessionIDs = $existingSessions | Select-Object -ExpandProperty ID
        if ($SessionName -in $existingSessionNames) 
        {
            $NewSession = Get-PSSession -Name $SessionName
            $newvalue = @($existingSessions | Where-Object -FilterScript {$_.Name -ne $SessionName})
            $newvalue += $NewSession
            Set-Variable -Name $SessionGroup -Value $newvalue -Scope Global
        } else {
            $NewSession = Get-PSSession -Name $SessionName
            $newvalue = @(Get-PSSession -Name $existingSessionNames)
            $newvalue += $NewSession
            Set-Variable -Name $SessionGroup -Value $newvalue -Scope Global
        }
    } else {
    #since the session group does not exist, create it and add the session to it
        New-Variable -Name $SessionGroup -Value @($(Get-PSSession -Name $SessionName)) -Scope Global
    }#else
}#foreach
}#function Update-SessionManagementGroups
Function Update-SQLConnections {
[cmdletbinding()]
Param(
    [parameter(Mandatory=$true)]
    $ConnectionName
    ,[parameter(Mandatory=$true)]
    $SQLConnection
)#param
#Check if the Session Group already exists
if (Test-Path -Path 'variable:\SQLConnections') 
{
    #since the connection group already exists, add the connection to it if it is not already present or update it if it is
    $existingConnections = Get-Variable -Name 'SQLConnections' -Scope Global -ValueOnly
    $existingConnectionNames = $existingConnections | Select-Object -ExpandProperty Name
    #$existingSessionIDs = $existingSessions | Select-Object -ExpandProperty ID
    if ($ConnectionName -in $existingConnectionNames) 
    {
        $newvalue = @($existingConnections | Where-Object -FilterScript {$_.Name -ne $ConnectionName})
        $newvalue += $SQLConnection
        Set-Variable -Name 'SQLConnections' -Value $newvalue -Scope Global
    } else {
        $newvalue = @($existingConnections)
        $newvalue += $SQLConnection
        Set-Variable -Name 'SQLConnections' -Value $newvalue -Scope Global
    }

} else {
#since the session group does not exist, create it and add the session to it
    New-Variable -Name 'SQLConnections' -Value @(,$SQLConnection) -Scope Global
}#else
}#function Update-SQLConnections
Function Update-SQLConnectionStrings {
[cmdletbinding()]
Param(
    [parameter(Mandatory=$true)]
    $ConnectionName
    ,[parameter(Mandatory=$true)]
    $SQLConnectionString
)#param
#Check if the Session Group already exists
if (Test-Path -Path 'variable:\SQLConnectionStrings') 
{
    $Global:SQLConnectionStrings.$($ConnectionName)=$SQLConnectionString
} else {
#since the session group does not exist, create it and add the session to it
    New-Variable -Name 'SQLConnectionStrings' -Value @{$ConnectionName = $SQLConnectionString} -Scope Global
}#else
}#function Update-SQLConnectionStrings
Function Connect-RemoteSystems
{
    [CmdletBinding()]
    param ()
    $ProcessStatus = @{
        Command = $MyInvocation.MyCommand.Name
        BoundParameters = $MyInvocation.BoundParameters
        Outcome = $null
        Connections = @()
    }
    try {
        # Connect To Exchange Systems
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                Write-Log -Message "Attempting: Connect to $sys-Exchange."
                $Status = Connect-Exchange -ExchangeOrganization $sys -ErrorAction Stop
                Write-Log -Message "Succeeded: Connect to $sys-Exchange."
                $ProcessStatus.Connections += [pscustomobject]@{Type='Exchange';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                Write-Log -Message "Failed: Connect to $sys-Exchange." -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='Exchange';Name=$sys;ConnectionStatus=$Status}
            }#catch
        }
        # Connect to Azure AD Sync
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AADSyncServers' | Where-Object AutoConnect -EQ $true | Select-Object -ExpandProperty Name)) 
        {
            $ConnectAADSyncParams = @{AADSyncServer = $sys; ErrorAction = 'Stop'}
            if (($Script:AADSyncServers | Where-Object AutoConnect -EQ $true).count -gt 1) {$ConnectAADSyncParams.UsePrefix = $true}
            try {
                Write-Log -Message "Attempting: Connect to $sys-AADSync."
                $Status = Connect-AADSync @ConnectAADSyncParams
                Write-Log -Message "Succeeded: Connect to $sys-AADSync."
                $ProcessStatus.Connections += [pscustomobject]@{Type='AADSync';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                Write-Log -Message "Failed: Connect to $sys-AADSync." -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='AADSync';Name=$sys;ConnectionStatus=$Status}
            }#catch    
        }
        # Connect to Active Directory Forests
        if (Import-RequiredModule -ModuleName ActiveDirectory -ErrorAction Stop) 
        {
            foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Where-Object AutoConnect -EQ $true | Select-Object -ExpandProperty Name)) {
                try {
                    Write-Log -Message "Attempting: Connect to AD Instance $sys."
                    $Status = Connect-ADInstance -ActiveDirectoryInstance $sys -ErrorAction Stop
                    Write-Log -Message "Succeeded: Connect to AD Instance $sys."
                    $ProcessStatus.Connections += [pscustomobject]@{Type='AD Instance';Name=$sys;ConnectionStatus=$Status}
                }
                catch {
                    Write-Log -Message "FAILED: Connect to AD Instance $sys." -Verbose -ErrorLog
                    Write-Log -Message $_.tostring() -ErrorLog
                    $Status = $false
                    $ProcessStatus.Connections += [pscustomobject]@{Type='AD Instance';Name=$sys;ConnectionStatus=$Status}
                }
            }
        }
        # Connect to default Azure AD
        $DefaultTenant = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.autoconnect -eq $true} | Select-Object -First 1)
        if ($DefaultTenant.Count -eq 1) 
        {
            try
            {
                $message = "Connect to Azure AD Tenant $sys"
                $Status = Connect-AzureAD -Tenant $DefaultTenant.Name -ErrorAction Stop
                $ProcessStatus.Connections += [pscustomobject]@{Type='Azure AD';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
            catch
            {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='Azure AD';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
            try
            {
                $message = "Connect to Azure AD RMS Tenant $sys"
                $Status = Connect-AADRM -Tenant $DefaultTenant.Name -ErrorAction Stop
                $ProcessStatus.Connections += [pscustomobject]@{Type='Azure AD RMS';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
            catch
            {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='Azure AD RMS';Name=$DefaultTenant.Name;ConnectionStatus=$Status}
            }
        }
        # Connect To PowerShell Systems
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'PowershellSystems' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to PowerShell on System $sys"
                Write-Log -Message $message -EntryType Attempting
                $Status = Connect-PowerShellSystem -PowerShellSystem $sys -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
                $ProcessStatus.Connections += [pscustomobject]@{Type='PowerShell';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='PowerShell';Name=$sys;ConnectionStatus=$Status}
            }#catch
        }
        # Connect To SQL Database Systems
        foreach ($sys in ($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SQLDatabases' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to SQL Database $sys"
                Write-Log -Message $message -EntryType Attempting
                $Status = Connect-SQLDatabase -SQLDatabase $sys -ErrorAction Stop
                Write-Log -Message $message -EntryType Succeeded
                $ProcessStatus.Connections += [pscustomobject]@{Type='SQL Database';Name=$sys;ConnectionStatus=$Status}
            }#try
            catch {
                $myerror = $_
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $myerror.tostring() -ErrorLog
                $Status = $false
                $ProcessStatus.Connections += [pscustomobject]@{Type='SQL Database';Name=$sys;ConnectionStatus=$Status}
            }#catch
        }
        $ProcessStatus.Outcome = $true
        $PSO = $ProcessStatus | Convert-HashTableToObject
        $ProcessStatus.Connections
    }
    catch {
        $ProcessStatus.Outcome = $false
        $PSO = $ProcessStatus | Convert-HashTableToObject
    }
}
function Invoke-ExchangeCommand {
    [cmdletbinding(DefaultParameterSetName = 'String')]
    param(
        [parameter(Mandatory = $true,Position = 1)]
        [ValidateScript({$_ -like '*-*'})]
        [string]$cmdlet
        ,
        [parameter(Position = 3,ParameterSetName='Splat')]
        [hashtable]$splat
        ,
        [parameter(Position = 3,ParameterSetName = 'String')]
        [string]$string = ''
        ,
        [string]$CommandPrefix
    )#Param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'ExchangeOrganization'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        #$ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        #$ParameterAttribute.ParameterSetName = 'Organization'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ExchangeOrganizations' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        $AliasSet = @('Org','ExchangeOrg')
        $AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        $AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam

    begin {
        # Bind the dynamic parameter to a friendly variable
        if ([string]::IsNullOrWhiteSpace($CommandPrefix)) {
            $Org = $PsBoundParameters[$ParameterName]
            if (-not [string]::IsNullOrWhiteSpace($Org)) {
                $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object {$_.name -eq $org}
                $CommandPrefix = $orgobj.CommandPrefix
            }
            else {$CommandPrefix = ''}
        }
    }

    Process {

        #Build the Command String and convert to Scriptblock
        switch ($PSCmdlet.ParameterSetName) {
            'splat' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) @splat")}#splat
            'string' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) $string")}#string
        }
        #Execute the command String
        &$commandstring

    }#Process

}#Function Invoke-ExchangeCommand
function Invoke-SkypeCommand {
    [cmdletbinding(DefaultParameterSetName = 'String')]
    param(
        [parameter(Mandatory = $true,Position = 1)]
        [ValidateScript({$_ -like '*-*'})]
        [string]$cmdlet
        ,
        [parameter(Position = 3,ParameterSetName='Splat')]
        [hashtable]$splat
        ,
        [parameter(Position = 3,ParameterSetName = 'String')]
        [string]$string = ''
        ,
        [string]$CommandPrefix
    )#Param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'SkypeOrganization'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        #$ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 2
        #$ParameterAttribute.ParameterSetName = 'Organization'

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SkypeOrganizations' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        $AliasSet = @('Org','SkypeOrg')
        $AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        $AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam

    begin {
        # Bind the dynamic parameter to a friendly variable
        if ([string]::IsNullOrWhiteSpace($CommandPrefix)) {
            $Org = $PsBoundParameters[$ParameterName]
            if (-not [string]::IsNullOrWhiteSpace($Org)) {
                $orgobj = $Script:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'SkypeOrganizations' | Where-Object {$_.name -eq $org}
                $CommandPrefix = $orgobj.CommandPrefix
            }
            else {$CommandPrefix = ''}
        }
    }

    Process {

        #Build the Command String and convert to Scriptblock
        switch ($PSCmdlet.ParameterSetName) {
            'splat' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) @splat")}#splat
            'string' {$commandstring = [scriptblock]::Create("$($cmdlet.split('-')[0])-$CommandPrefix$($cmdlet.split('-')[1]) $string")}#string
        }
        #Execute the command String
        &$commandstring

    }#Process

}#Function Invoke-SkypeCommand
##########################################################################################################
#Invoke-ExchangeCommand Dependent Functions
##########################################################################################################
function Get-RecipientCmdlet {
[cmdletbinding()]
param
(
[parameter(ParameterSetName='RecipientObject')]
[psobject]$Recipient
,
[parameter(ParametersetName='IdentityString')]
[string]$Identity
,
[parameter(Mandatory=$true)]
[ValidateSet('Set','Get','Remove','Disable')]
$verb
,
[parameter(ParameterSetName = 'IdentityString')]
$ExchangeOrganization
)
switch ($PSCmdlet.ParameterSetName)
{
    'RecipientObject'
    {
        #add some code to validate the object
    }
    'IdentityString'
    {
        #get the recipient object
        $Recipient = Invoke-ExchangeCommand -cmdlet 'Get-Recipient' -string "-Identity $Identity" -ExchangeOrganization $ExchangeOrganization
    }
}#switch ParameterSetName
#Return the cmdlet based on recipient type and requested verb
switch ($verb)
{
    'Get'
    {
        switch ($Recipient.recipienttypedetails)
        {
            'LinkedMailbox' {$cmdlet = 'Get-Mailbox'}
            'RemoteRoomMailbox'{$cmdlet = 'Get-RemoteMailbox'}
            'RemoteSharedMailbox' {$cmdlet = 'Get-RemoteMailbox'}
            'RemoteUserMailbox' {$cmdlet = 'Get-RemoteMailbox'}
            'RemoteEquipmentMailbox' {$cmdlet = 'Get-RemoteMailbox'}
            'RoomMailbox' {$cmdlet = 'Get-Mailbox'}
            'SharedMailbox' {$cmdlet = 'Get-Mailbox'}
            'DiscoveryMailbox' {$cmdlet = 'Get-Mailbox'}
            'ArbitrationMailbox' {$cmdlet = 'Get-Mailbox'}
            'UserMailbox' {$cmdlet = 'Get-Mailbox'}
            'LegacyMailbox' {$cmdlet = 'Get-Mailbox'}
            'EquipmentMailbox' {$cmdlet = 'Get-Mailbox'}
            'MailContact' {$cmdlet = 'Get-MailContact'}
            'MailForestContact' {$cmdlet = 'Get-MailContact'}
            'MailUser' {$cmdlet = 'Get-MailUser'}
            'MailUniversalDistributionGroup' {$cmdlet = 'Get-DistributionGroup'}
            'MailUniversalSecurityGroup' {$cmdlet = 'Get-DistributionGroup'}
            'DynamicDistributionGroup' {$cmdlet = 'Get-DynamicDistributionGroup'}
            'PublicFolder' {$cmdlet = 'Get-MailPublicFolder'}
        }#switch RecipientTypeDetails
    }#Get
    'Set'
    {
        switch ($Recipient.recipienttypedetails) 
        {
            'LinkedMailbox' {$cmdlet = 'Set-Mailbox'}
            'RemoteRoomMailbox'{$cmdlet = 'Set-RemoteMailbox'}
            'RemoteSharedMailbox' {$cmdlet = 'Set-RemoteMailbox'}
            'RemoteUserMailbox' {$cmdlet = 'Set-RemoteMailbox'}
            'RemoteEquipmentMailbox' {$cmdlet = 'Set-RemoteMailbox'}
            'RoomMailbox' {$cmdlet = 'Set-Mailbox'}
            'SharedMailbox' {$cmdlet = 'Set-Mailbox'}
            'DiscoveryMailbox' {$cmdlet = 'Set-Mailbox'}
            'ArbitrationMailbox' {$cmdlet = 'Set-Mailbox'}
            'UserMailbox' {$cmdlet = 'Set-Mailbox'}
            'LegacyMailbox' {$cmdlet = 'Set-Mailbox'}
            'EquipmentMailbox' {$cmdlet = 'Set-Mailbox'}
            'MailContact' {$cmdlet = 'Set-MailContact'}
            'MailForestContact' {$cmdlet = 'Set-MailContact'}
            'MailUser' {$cmdlet = 'Set-MailUser'}
            'MailUniversalDistributionGroup' {$cmdlet = 'Set-DistributionGroup'}
            'MailUniversalSecurityGroup' {$cmdlet = 'Set-DistributionGroup'}
            'DynamicDistributionGroup' {$cmdlet = 'Set-DynamicDistributionGroup'}
            'PublicFolder' {$cmdlet = 'Set-MailPublicFolder'}
        }#switch RecipientTypeDetails
    }
    'Remove'
    {
        switch ($Recipient.recipienttypedetails) 
        {
            'LinkedMailbox' {$cmdlet = 'Remove-Mailbox'}
            'RemoteRoomMailbox'{$cmdlet = 'Remove-RemoteMailbox'}
            'RemoteSharedMailbox' {$cmdlet = 'Remove-RemoteMailbox'}
            'RemoteUserMailbox' {$cmdlet = 'Remove-RemoteMailbox'}
            'RemoteEquipmentMailbox' {$cmdlet = 'Remove-RemoteMailbox'}
            'RoomMailbox' {$cmdlet = 'Remove-Mailbox'}
            'SharedMailbox' {$cmdlet = 'Remove-Mailbox'}
            'DiscoveryMailbox' {$cmdlet = 'Remove-Mailbox'}
            'ArbitrationMailbox' {$cmdlet = 'Remove-Mailbox'}
            'UserMailbox' {$cmdlet = 'Remove-Mailbox'}
            'LegacyMailbox' {$cmdlet = 'Remove-Mailbox'}
            'EquipmentMailbox' {$cmdlet = 'Remove-Mailbox'}
            'MailContact' {$cmdlet = 'Remove-MailContact'}
            'MailForestContact' {$cmdlet = 'Remove-MailContact'}
            'MailUser' {$cmdlet = 'Remove-MailUser'}
            'MailUniversalDistributionGroup' {$cmdlet = 'Remove-DistributionGroup'}
            'MailUniversalSecurityGroup' {$cmdlet = 'Remove-DistributionGroup'}
            'DynamicDistributionGroup' {throw 'No Remove Cmdlet for DynamicDistributionGroup. Use Disable instead.'}
            'PublicFolder' {throw 'No Remove Cmdlet for MailPublicFolder. Use Disable instead.'}
        }#switch RecipientTypeDetails
    }
    'Disable'
    {
        switch ($Recipient.recipienttypedetails) 
        {
            'LinkedMailbox' {$cmdlet = 'Disable-Mailbox'}
            'RemoteRoomMailbox'{$cmdlet = 'Disable-RemoteMailbox'}
            'RemoteSharedMailbox' {$cmdlet = 'Disable-RemoteMailbox'}
            'RemoteUserMailbox' {$cmdlet = 'Disable-RemoteMailbox'}
            'RemoteEquipmentMailbox' {$cmdlet = 'Disable-RemoteMailbox'}
            'RoomMailbox' {$cmdlet = 'Disable-Mailbox'}
            'SharedMailbox' {$cmdlet = 'Disable-Mailbox'}
            'DiscoveryMailbox' {$cmdlet = 'Disable-Mailbox'}
            'ArbitrationMailbox' {$cmdlet = 'Disable-Mailbox'}
            'UserMailbox' {$cmdlet = 'Disable-Mailbox'}
            'LegacyMailbox' {$cmdlet = 'Disable-Mailbox'}
            'EquipmentMailbox' {$cmdlet = 'Disable-Mailbox'}
            'MailContact' {$cmdlet = 'Disable-MailContact'}
            'MailForestContact' {$cmdlet = 'Disable-MailContact'}
            'MailUser' {$cmdlet = 'Disable-MailUser'}
            'MailUniversalDistributionGroup' {$cmdlet = 'Disable-DistributionGroup'}
            'MailUniversalSecurityGroup' {$cmdlet = 'Disable-DistributionGroup'}
            'DynamicDistributionGroup' {$cmdlet = 'Disable-DynamicDistributionGroup'}
            'PublicFolder' {$cmdlet = 'Disable-MailPublicFolder'}
        }#switch RecipientTypeDetails
    }
}#switch Verb
$cmdlet
}
##########################################################################################################
#AD/Azure AD Helper Functions
##########################################################################################################
function Find-ADUser {
    [cmdletbinding(DefaultParameterSetName = 'Default')]
    param(
        [parameter(Mandatory = $true,valuefrompipeline = $true, valuefrompipelinebypropertyname = $true, ParameterSetName='Default')]
        [parameter(ParameterSetName='FirstLast')]
        [string]$Identity
        ,
        [parameter(Mandatory = $true)]
        [validateset('SAMAccountName','UserPrincipalName','ProxyAddress','Mail','mailNickname','employeeNumber','employeeID','extensionattribute5','extensionattribute11','extensionattribute13','DistinguishedName','CanonicalName','ObjectGUID','mS-DS-ConsistencyGuid','SID','GivenNameSurname')]
        $IdentityType
        ,
        [switch]$DoNotPreserveLocation #use this switch when you are already running the commands from the correct AD Drive
        ,
        $properties = $AllADAttributesToRetrieve
        ,
        [parameter(ParameterSetName='FirstLast',Mandatory = $true)]
        [string]$GivenName
        ,
        [parameter(ParameterSetName='FirstLast',Mandatory = $true)]
        [string]$SurName
        ,
        [switch]$AmbiguousAllowed
        ,
        [switch]$ReportExceptions
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'ActiveDirectoryInstance'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 3

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        $AliasSet = @('AD','ADInstance')
        $AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        $AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    Begin {
        $ADInstance = $PSBoundParameters[$ParameterName]
        if ($DoNotPreserveLocation -ne $true) {Push-Location -StackName 'Lookup-ADUser'}
        #validate AD Instance
        try {
            #Write-Log -Message "Attempting: Set Location to AD Drive $("$ADInstance`:")"
            Set-Location $("$ADInstance`:\") -ErrorAction Stop
            #Write-Log -Message "Succeeded: Set Location to AD Drive $("$ADInstance`:")" 
        }#try
        catch {
            Write-Log -Message "Failed: Set Location to AD Drive $("$ADInstance`:")" -Verbose -ErrorLog
            Write-Log -Message $_.tostring() -ErrorLog
            $ErrorRecord = New-ErrorRecord -Exception 'System.Exception' -ErrorId ADDriveNotAvailable -ErrorCategory NotSpecified -TargetObject $ADInstance -Message "Required AD Drive not available"
            $PSCmdlet.ThrowTerminatingError($ErrorRecord)
        }
        #Setup GetADUserParams
        $GetADUserParams = @{ErrorAction = 'Stop'}
        if ($properties.count -ge 1) {
            #Write-Log -Message "Using Property List: $($properties -join ",") with Get-ADUser"
            $GetADUserParams.Properties = $Properties
        }
        #Setup exception reporting
        if ($ReportExceptions) {
            $Script:LookupADUserNotFound = @()
            $Script:LookupADUserAmbiguous = @()
        }
    }#Begin

    Process {
        switch ($IdentityType) {
            'mS-DS-ConsistencyGuid' {
                $Identity = $Identity -join ' '
            }
            'GivenNameSurname' {
                $SurName = $SurName.Trim()
                $GivenName = $GivenName.Trim()                
                $Identity = "$SurName, $GivenName"
            }
            Default {}
        }
        foreach ($ID in $Identity) {
            try {
                Write-Log -Message "Attempting: Get-ADUser with identifier $ID for Attribute $IdentityType" 
                switch ($IdentityType) {
                    'SAMAccountName' {
                        $ADUser = @(Get-ADUser -filter {SAMAccountName -eq $ID} @GetADUserParams)
                    }
                    'UserPrincipalName' {
                        $AdUser = @(Get-ADUser -filter {UserPrincipalName -eq $ID} @GetADUserParams)
                    }
                    'ProxyAddress' {
                        #$wildcardID = "*$ID*"
                        $AdUser = @(Get-ADUser -filter {proxyaddresses -like $ID} @GetADUserParams)
                    }
                    'Mail' {
                        $AdUser = @(Get-ADUser -filter {Mail -eq $ID}  @GetADUserParams)
                    }
                    'mailNickname'{
                        $AdUser = @(Get-ADUser -filter {mailNickname -eq $ID}  @GetADUserParams)
                    }
                    'extensionattribute5' {
                        $AdUser = @(Get-ADUser -filter {extensionattribute5 -eq $ID} @GetADUserParams)
                    }
                    'extensionattribute11' {
                        $AdUser = @(Get-ADUser -filter {extensionattribute11 -eq $ID} @GetADUserParams)
                    }
                    'extensionattribute13' {
                        $AdUser = @(Get-ADUser -filter {extensionattribute13 -eq $ID} @GetADUserParams)
                    }
                    'DistinguishedName' {
                        $AdUser = @(Get-ADUser -filter {DistinguishedName -eq $ID} @GetADUserParams)
                    }
                    'CanonicalName' {
                        $AdUser = @(Get-ADUser -filter {CanonicalName -eq $ID} @GetADUserParams)
                    }
                    'ObjectGUID' {
                        $AdUser = @(Get-ADUser -filter {ObjectGUID -eq $ID} @GetADUserParams)
                    }
                    'SID' {
                        $AdUser = @(Get-ADUser -filter {SID -eq $ID} @GetADUserParams)
                    }
                    'mS-DS-ConsistencyGuid' {
                        $ID = [byte[]]$ID.split(' ')
                        $AdUser = @(Get-ADUser -filter {mS-DS-ConsistencyGuid -eq $ID} @GetADUserParams)
                    }
                    'GivenNameSurName' {
                        $ADUser = @(Get-ADUser -Filter {GivenName -eq $GivenName -and Surname -eq $SurName} @GetADUserParams)
                    }
                    'employeeNumber' {
                        $AdUser = @(Get-ADUser -filter {employeeNumber -eq $ID}  @GetADUserParams)
                    }
                    'employeeID'{
                        $AdUser = @(Get-ADUser -filter {employeeID -eq $ID}  @GetADUserParams)
                    }
                }#switch
                Write-Log -Message "Succeeded: Get-ADUser with identifier $ID for Attribute $IdentityType" 
            }#try
            catch {
                Write-Log -Message "FAILED: Get-ADUser with identifier $ID for Attribute $IdentityType" -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                if ($ReportExceptions) {$Script:LookupADUserNotFound += $ID}
            }
            switch ($aduser.Count) {
                1 {
                    $TrimmedADUser = $ADUser | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                    Write-Output $TrimmedADUser
                }#1
                0 {
                    if ($ReportExceptions) {$Script:LookupADUserNotFound += $ID}
                }#0
                Default {
                    if ($AmbiguousAllowed) {
                        $TrimmedADUser = $ADUser | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                        Write-Output $TrimmedADUser    
                    }
                    else {
                        if ($ReportExceptions) {$Script:LookupADUserAmbiguous += $ID}
                    }
                }#Default
            }#switch
        }#foreach
    }#Process

    end {
        if ($ReportExceptions) {
            if ($Script:LookupADUserNotFound.count -ge 1) {
                Write-Log -Message 'Review logs or OneShell variable $LookupADUserNotFound for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Script:LookupADUserNotFound -join "`n`t")" -ErrorLog
            }#if
            if ($Script:LookupADUserAmbiguous.count -ge 1) {
                Write-Log -Message 'Review logs or OneShell variable $LookupADUserAmbiguous for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Script:LookupADUserAmbiguous -join "`n`t")" -ErrorLog
            }#if
        }#if
        if ($DoNotPreserveLocation -ne $true) {Pop-Location -StackName 'Lookup-ADUser'}#if
    }#end

}#Find-ADUser
function Find-ADContact {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true,valuefrompipeline = $true, valuefrompipelinebypropertyname = $true)]
        [string]$Identity
        ,
        [parameter(Mandatory  =$true)]
        [validateset('ProxyAddress','Mail','Name','extensionattribute5','extensionattribute11','extensionattribute13','DistinguishedName','CanonicalName','ObjectGUID','mS-DS-ConsistencyGuid')]
        $IdentityType
        ,

        [switch]$DoNotPreserveLocation #use this switch when you are already running the commands from the correct AD Drive
        ,
        $properties = $AllADContactAttributesToRetrieve
        ,
        [switch]$AmbiguousAllowed
        ,
        [switch]$ReportExceptions
    )#param
    DynamicParam {
        #inspiration:  http://blogs.technet.com/b/pstips/archive/2014/06/10/dynamic-validateset-in-a-dynamic-parameter.aspx
        # Set the dynamic parameters' name
        $ParameterName = 'ActiveDirectoryInstance'
            
        # Create the dictionary 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Create the collection of attributes
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            
        # Create and set the parameters' attributes
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 3

        # Add the attributes to the attributes collection
        $AttributeCollection.Add($ParameterAttribute)

        # Generate and set the ValidateSet 
        $ValidateSet = @($Script:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Select-Object -ExpandProperty Name)
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($ValidateSet)

        # Add the ValidateSet to the attributes collection
        $AttributeCollection.Add($ValidateSetAttribute)

        # Add an Alias 
        $AliasSet = @('AD','ADInstance')
        $AliasAttribute = New-Object System.Management.Automation.AliasAttribute($AliasSet)
        $AttributeCollection.Add($AliasAttribute)

        # Create and return the dynamic parameter
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        Write-Output $RuntimeParameterDictionary
    }#DynamicParam
    Begin {
        $ADInstance = $PSBoundParameters[$ParameterName]
        if ($DoNotPreserveLocation -ne $true) {Push-Location -StackName 'Find-ADContact'}
        try {
            #Write-Log -Message "Attempting: Set Location to AD Drive $("$ADInstance`:")" -Verbose
            Set-Location $("$ADInstance`:") -ErrorAction Stop
            #Write-Log -Message "Succeeded: Set Location to AD Drive $("$ADInstance`:")" -Verbose
        }#try
        catch {
            Write-Log -Message "Succeeded: Set Location to AD Drive $("$ADInstance`:")" -ErrorLog
            Write-Log -Message $_.tostring() -ErrorLog
            $ErrorRecord = New-ErrorRecord -Exception 'System.Exception' -ErrorId ADDriveNotAvailable -ErrorCategory NotSpecified -TargetObject $ADInstance -Message "Required AD Drive not available"
            $PSCmdlet.ThrowTerminatingError($ErrorRecord)
        }
        $GetADObjectParams = @{ErrorAction = 'Stop'}
        if ($properties.count -ge 1) {
            #Write-Log -Message "Using Property List: $($properties -join ",") with Get-ADObject"
            $GetADObjectParams.Properties = $Properties
        }
        if ($ReportExceptions) {
            $Script:LookupADContactNotFound = @()
            $Script:LookupADContactAmbiguous = @()
        }
    }#Begin

    Process {
        if ($IdentityType -eq 'mS-DS-ConsistencyGuid') {
            $Identity = $Identity -join ' '
        }
        foreach ($ID in $Identity) {
            try {
                Write-Log -Message "Attempting: Get-ADObject with identifier $ID for Attribute $IdentityType" 
                switch ($IdentityType) {
                    'ProxyAddress' {
                        #$wildcardID = "*$ID*"
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and proxyaddresses -like $ID} @GetADObjectParams)
                    }
                    'Mail' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and Mail -eq $ID}  @GetADObjectParams)
                    }
                    'extensionattribute5' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and extensionattribute5 -eq $ID} @GetADObjectParams)
                    }
                    'extensionattribute11' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and extensionattribute11 -eq $ID} @GetADObjectParams)
                    }
                    'extensionattribute13' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and extensionattribute13 -eq $ID} @GetADObjectParams)
                    }
                    'DistinguishedName' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and DistinguishedName -eq $ID} @GetADObjectParams)
                    }
                    'CanonicalName' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and CanonicalName -eq $ID} @GetADObjectParams)
                    }
                    'ObjectGUID' {
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and ObjectGUID -eq $ID} @GetADObjectParams)
                    }
                    'mS-DS-ConsistencyGuid' {
                        $ID = [byte[]]$ID.split(' ')
                        $ADContact = @(Get-ADObject -filter {objectclass -eq 'contact' -and mS-DS-ConsistencyGuid -eq $ID} @GetADObjectParams)
                    }
                }#switch
                Write-Log -Message "Succeeded: Get-ADObject with identifier $ID for Attribute $IdentityType" 
            }#try
            catch {
                Write-Log -Message "FAILED: Get-ADObject with identifier $ID for Attribute $IdentityType" -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                if ($ReportExceptions) {$Script:LookupADContactNotFound += $ID}
            }
            switch ($ADContact.Count) {
                1 {
                    $TrimmedADObject = $ADContact | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                    Write-Output $TrimmedADObject
                }#1
                0 {
                    if ($ReportExceptions) {$Script:LookupADContactNotFound += $ID}
                }#0
                Default {
                    if ($AmbiguousAllowed) {
                        $TrimmedADObject = $ADContact | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                        Write-Output $TrimmedADObject    
                    }
                    else {
                        if ($ReportExceptions) {$Script:LookupADContactAmbiguous += $ID}
                    }
                }#Default
            }#switch
        }#foreach
    }#Process

    end {
        if ($ReportExceptions) {
            if ($Script:LookupADContactNotFound.count -ge 1) {
                Write-Log -Message 'Review logs or OneShell variable $LookupADObjectNotFound for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Script:LookupADContactNotFound -join "`n`t")" -ErrorLog
            }#if
            if ($Script:LookupADContactAmbiguous.count -ge 1) {
                Write-Log -Message 'Review logs or OneShell variable $LookupADObjectAmbiguous for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Script:LookupADContactAmbiguous -join "`n`t")" -ErrorLog
            }#if
        }#if
        if ($DoNotPreserveLocation -ne $true) {Pop-Location -StackName 'Find-ADContact'}#if
    }#end
}#Find-ADContact
function Find-PrimarySMTPAddress {
    [cmdletbinding()]
    Param(
        [parameter(mandatory = $true)]
        $ProxyAddresses
        ,
        [parameter(mandatory = $false)]
        [string]$Identity
    )
    $message = "Find Primary SMTP Address"
    if (-not [string]::IsNullOrWhiteSpace($Identity)) 
    {
        $message = $message + " for $Identity"
    }
    Write-Log -EntryType Attempting -Message $message
    $PrimaryAddresses = @($ProxyAddresses | Where-Object {$_ -clike 'SMTP:*'} | ForEach-Object {($_ -split ':')[1]})
    switch ($PrimaryAddresses.count) 
    {
        1 
        {
            $PrimarySMTPAddress = $PrimaryAddresses[0]
            Write-Log -EntryType Succeeded -Message $message
            $PrimarySMTPAddress
        }#1
        0 
        {
            $message = $message + ": 0 Found"
            Write-Log -message $message -Verbose -EntryType Failed
            Throw "$message"
        }#0
        Default 
        {
            $message = $message + ": Multiple Found"
            Write-Log -message $message -Verbose -EntryType Failed
            Throw "$message"
        }#Default
    }#switch 
}
function Get-AdObjectDomain {
    param(
        [parameter()]
        $adobject
    )
    [string]$domain=$adobject.canonicalname.split('/')[0]
    Write-Output $domain
}
Function Get-ADAttributeSchema {
    param(
        [parameter(Mandatory=$true)]
        $attribute
        ,
        [parameter(Mandatory=$true)]
        $ADForest
        ,
        [string[]]$properties
    )
    if (-not $properties) {$properties = '*'}
    try {
        $forest = Get-ADForest -Identity $ADForest -ErrorAction Stop
    }
    catch {
        $_
        throw "Could not find AD Forest $ADForest"
    }
    $schemalocation = "CN=Schema,$($forest.PartitionsContainer.split(',',2)[1])"
    $attributelocation = "cn=$attribute,$schemalocation"
    try {
        Get-ADObject $attributelocation -Properties $properties -ErrorAction Stop
    }
    catch {
        $_
        throw "Could not find AD Object for $attribute in $attributelocation"
    }
}
function Get-MsolUserLicenseDetail {
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true, ParameterSetName='UserPrincipalName')]
        [string[]]$UserPrincipalName
        ,
        [parameter(ValueFromPipeline=$true,ParameterSetName='MSOLUserObject')]
        [Microsoft.Online.Administration.User[]]$msoluser
    )
    begin {
        function getresult {
            param($user)
            $result += [pscustomobject]@{
                UserPrincipalName = $user.UserPrincipalName
                LicenseAssigned = $user.Licenses.AccountSKUID
                EnabledServices = @($user.Licenses.servicestatus | Select-Object @{n='Service';e={$_.serviceplan.servicename}},@{n='Status';e={$_.provisioningstatus}} | where-object Status -ne 'Disabled' | Select-Object -ExpandProperty Service)
                DisabledServices = @($user.Licenses.servicestatus | Select-Object @{n='Service';e={$_.serviceplan.servicename}},@{n='Status';e={$_.provisioningstatus}} | where-object Status -eq 'Disabled' | Select-Object -ExpandProperty Service)
                UsageLocation = $user.UsageLocation
                LicenseReconciliationNeeded = $user.LicenseReconciliationNeeded
            }#result
            Write-Output $result
        }
    }#begin
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'UserPrincipalName' {
                foreach ($UPN in $UserPrincipalName) {
                    try {
                        Write-Log -Message "Attempting: Get-MsolUser for UserPrincipalName $UPN" 
                        $user = Get-MsolUser -UserPrincipalName $UPN -ErrorAction Stop
                        Write-Log -Message "Succeeded: Get-MsolUser for UserPrincipalName $UPN" 
                        getresult $user 
                    }#try
                    catch{
                        Write-Log -message "Unable to locate MSOL User with UserPrincipalName $UPN" -ErrorLog
                        Write-Log -message $_.tostring() -ErrorLog
                    }#catch

                }#foreach
            }#UserPrincipalName
            'MSOLUserObject' {
                foreach ($user in $msoluser) {
                    getresult $user 
                }#foreach
            }#MSOLUserObject
        }#switch
    }#process
    end {
    }#end
}
function Get-XADUserPasswordExpirationDate() {

    Param ([Parameter(Mandatory=$true,  Position=0,  ValueFromPipeline=$true, HelpMessage="Identity of the Account")]

    [Object] $accountIdentity)

    PROCESS {

        $accountObj = Get-ADUser $accountIdentity -properties PasswordExpired, PasswordNeverExpires, PasswordLastSet

        if ($accountObj.PasswordExpired) {

            echo ("Password of account: " + $accountObj.Name + " already expired!")

        } else { 

            if ($accountObj.PasswordNeverExpires) {

                echo ("Password of account: " + $accountObj.Name + " is set to never expires!")

            } else {

                $passwordSetDate = $accountObj.PasswordLastSet

                if ($passwordSetDate -eq $null) {

                    echo ("Password of account: " + $accountObj.Name + " has never been set!")

                }  else {

                    $maxPasswordAgeTimeSpan = $null

                    $dfl = (get-addomain).DomainMode

                    if ($dfl -ge 3) { 

                        ## Greater than Windows2008 domain functional level

                        $accountFGPP = Get-ADUserResultantPasswordPolicy $accountObj

                        if ($accountFGPP -ne $null) {

                            $maxPasswordAgeTimeSpan = $accountFGPP.MaxPasswordAge

                        } else {

                            $maxPasswordAgeTimeSpan = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge

                        }

                    } else {

                        $maxPasswordAgeTimeSpan = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge

                    }

                    if ($maxPasswordAgeTimeSpan -eq $null -or $maxPasswordAgeTimeSpan.TotalMilliseconds -eq 0) {

                        echo ("MaxPasswordAge is not set for the domain or is set to zero!")

                    } else {

                        echo ("Password of account: " + $accountObj.Name + " expires on: " + ($passwordSetDate + $maxPasswordAgeTimeSpan))

                    }

                }

            }

        }

    }

}
function Get-AllADRecipientObjects {
[cmdletbinding()]
param
(
[int]$ResultSetSize = 10000
,
[switch]$Passthrough
,
[switch]$ExportData
,
[parameter(Mandatory=$true)]
$ADInstance
)
    cd "$($ADInstance):\"
    $AllGroups = Get-ADGroup -ResultSetSize $ResultSetSize -Properties @($AllADAttributesToRetrieve + 'Members') -Filter * | Select-Object -Property * -ExcludeProperty Property*,Item
    $AllMailEnabledGroups = $AllGroups | Where-Object -FilterScript {$_.legacyExchangeDN -ne $NULL -or $_.mailNickname -ne $NULL -or $_.proxyAddresses -ne $NULL}
    $AllContacts = Get-ADObject -Filter {objectclass -eq 'contact'} -Properties $AllADContactAttributesToRetrieve -ResultSetSize $ResultSetSize | Select-Object -Property * -ExcludeProperty Property*,Item
    $AllMailEnabledContacts = $AllContacts | Where-Object -FilterScript {$_.legacyExchangeDN -ne $NULL -or $_.mailNickname -ne $NULL -or $_.proxyAddresses -ne $NULL}
    $AllUsers = Get-ADUser -ResultSetSize $ResultSetSize -Filter * -Properties $AllADAttributesToRetrieve | Select-Object -Property * -ExcludeProperty Property*,Item
    $AllMailEnabledUsers = $AllUsers  | Where-Object -FilterScript {$_.legacyExchangeDN -ne $NULL -or $_.mailNickname -ne $NULL -or $_.proxyAddresses -ne $NULL}
    $AllPublicFolders = Get-ADObject -Filter {objectclass -eq 'publicFolder'} -ResultSetSize $ResultSetSize -Properties $AllADAttributesToRetrieve | Select-Object -Property * -ExcludeProperty Property*,Item
    $AllMailEnabledPublicFolders = $AllPublicFolders  | Where-Object -FilterScript {$_.legacyExchangeDN -ne $NULL -or $_.mailNickname -ne $NULL -or $_.proxyAddresses -ne $NULL}
    $AllMailEnabledADObjects = $AllMailEnabledGroups + $AllMailEnabledContacts + $AllMailEnabledUsers + $AllMailEnabledPublicFolders
    if ($Passthrough) {$AllMailEnabledADObjects}
    if ($ExportData) {Export-Data -DataToExport $AllMailEnabledADObjects -DataToExportTitle 'AllADRecipientObjects' -Depth 3 -DataType xml}
}
##########################################################################################################
#Profile and Environment Initialization Functions
##########################################################################################################
Function Export-OrgProfile
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [hashtable]$profile
        ,
        [parameter(Mandatory=$true)]
        [validateset('New','Update')]
        $operation
    )
    $profileobject = $profile | Convert-HashTableToObject
    $name = $profileobject.Identity
    $path = "$($Script:OneShellModuleFolderPath)\$name.json"
    $JSONparams =@{
        InputObject = $profileobject
        ErrorAction = 'Stop'
        Depth = 3
    }
    switch ($operation){
        'Update' {$params.Force = $true}
        'New' {$params.NoClobber = $true}
    }#switch

    try {
        ConvertTo-Json @JSONparams | Out-File -FilePath $path -Encoding ascii -ErrorAction Stop
        Write-Output $true
    }#try
    catch {
        $_
        throw "FAILED: Could not write Org Profile data to $path"
    }#catch

}#Function Export-OrgProfile
Function Get-OrgProfile
{
[cmdletbinding(DefaultParameterSetName = 'All')]
param(
    [parameter(ParameterSetName = 'All')]
    [parameter(ParameterSetName = 'Identity')]
    [parameter(ParameterSetName = 'OrgName')]
    #add locations validation with Test-Path
    [string[]]$Location = @("$env:ALLUSERSPROFILE\OneShell")
    ,
    [parameter(ParameterSetName = 'All')]
    [parameter(ParameterSetName = 'Identity')]
    [parameter(ParameterSetName = 'OrgName')]
    $OrgProfileType = 'OneShellOrgProfile'
    ,
    [parameter(ParameterSetName = 'All')]
    [parameter(ParameterSetName = 'Identity')]
    [parameter(ParameterSetName = 'OrgName')]
    [switch]$raw
    ,
    [parameter(ParameterSetName = 'Identity')]
    $Identity
    , 
    [parameter(ParameterSetName = 'OrgName')]
    $OrgName
    ,
    [parameter(ParameterSetName = 'Imported')]
    [switch]$Imported
)
if ($PSCmdlet.ParameterSetName -eq 'Imported')
{$OrgProfiles}
else
{
foreach ($loc in $Location)
{
    $JSONProfiles = @(Get-ChildItem -Path $loc -Filter *.json)
    if ($JSONProfiles.Count -ge 1) {
        $PotentialOrgProfiles = @(foreach ($file in $JSONProfiles) {Get-Content -Path $file.fullname -Raw | ConvertFrom-Json})
        $FoundOrgProfiles = @($PotentialOrgProfiles | Where-Object {$_.ProfileType -eq $OrgProfileType})
        switch ($PSCmdlet.ParameterSetName)
        {
            'Identity'
            {
                $OrgProfiles = @($FoundOrgProfiles | Where-Object -FilterScript {$_.Identity -eq $Identity})
            }
            'OrgName'
            {
                $OrgProfiles = @($FoundOrgProfiles | Where-Object -FilterScript {$_.General.Name -eq $OrgName})
            }
            'All'
            {$OrgProfiles = @($FoundOrgProfiles)}
        }
        if ($OrgProfiles.Count -ge 1) {
            if ($raw)
            {
                $OrgProfiles
            }
            else
            {
                $OrgProfiles | Select-Object -Property @{n='Identity';e={$_.Identity}},@{n='Name';e={$_.General.Name}},@{n='Default';e={$_.General.Default}}
            }
        }
        else {
            Write-Log -message "No valid Organization Profiles Were Found in $loc" -EntryType Notification -Verbose
        }
    }
}
}#else
}#Function Get-OrgProfile
Function Import-OrgProfile
{
[cmdletbinding()]
param
(
#Add validation for the path
[string[]]$Location
,
[string]$OrgProfileType
)
$GetOrgProfileParams=@{
    ErrorAction = 'Stop'
    Raw = $true
}
if ($PSBoundParameters.ContainsKey('Location'))
{$GetOrgProfileParams.Location = $Location}
if ($PSBoundParameters.ContainsKey('OrgProfileType'))
{$GetOrgProfileParams.OrgProfileType = $OrgProfileType}
Try
{
    $OrgProfilesToImport = @(Get-OrgProfile @GetOrgProfileParams) 
    Set-OneShellVariable -Name OrgProfiles -Value $OrgProfilesToImport
    Write-Output $True
}
catch
{
    Write-Output $false
}
}#function Import-OrgProfile
Function Use-OrgProfile
{
param
(
    [parameter(ParameterSetName = 'Object')]
    $profile 
    ,
    [parameter(ParameterSetName = 'Identity')]
    $Identity
    ,
    [parameter(ParameterSetName = 'OrgName')]
    $OrgName
)
begin
{
    switch ($PSCmdlet.ParameterSetName)
    {
        'Object'
        {}
        'Identity'
        {
            $profile = $script:OrgProfiles | Where-Object -FilterScript {$_.Identity -eq $Identity} | Select-Object -First 1
        }
        'OrgName'
        {
            $profile = $script:OrgProfiles | Where-Object -FilterScript {$_.General.Name -eq $OrgName} | Select-Object -First 1
        }
    }
}#begin
    process
    {
        if ($script:CurrentOrgProfile -and $profile.Identity -ne $script:CurrentOrgProfile.Identity)
        {
            $script:CurrentOrgProfile = $profile
            Write-Log -message "Org Profile has been changed to $($script:CurrentOrgProfile.Identity), $($script:CurrentOrgProfile.general.name).  Remove PSSessions and select an Admin Profile to load." -EntryType Notification -Verbose
        }
        else
        {
            $script:CurrentOrgProfile = $profile
            Write-Log -Message "Org Profile has been set to $($script:CurrentOrgProfile.Identity), $($script:CurrentOrgProfile.general.name)." -EntryType Notification -Verbose
        }
        $Script:CurrentOrgAdminProfileSystems = @()
        Write-Output $true
    }#process
}
Function Select-OrgProfile
{
param(
    [parameter(Mandatory=$true)]
    [validateset('Use','Edit')]
    $purpose
)
$MenuDefinition = 
[pscustomobject]@{
    GUID = [guid]::NewGuid()
    Title = "Select Organization Profile to $purpose"
    Initialization = ''
    ParentGUID = $null
    Choices = @()
}
foreach ($profile in Get-OrgProfile)
{
    $MenuDefinition.choices += 
    [pscustomobject]@{
        choice=$profile.general.Name
        command=switch ($purpose)
        {
            'Edit'
            {
                "Set-OrgProfile -Identity $($Profile.Identity)"
            }
            'Use'
            {
                "Use-OrgProfile -Identity $($profile.identity)"
            }
        }#switch
        exit = $true
    }
}
    Invoke-Menu -menudefinition $MenuDefinition 
}
function Get-OrgProfileSystem
{
param(
    $OrganizationIdentity
)
$targetOrgProfile = @(Get-OrgProfile -Identity $OrganizationIdentity -raw)
switch ($targetOrgProfile.Count)
{
    1
    {}
    0
    {throw "No matching Organization Profile was found for identity $OrganizationIdentity"}
    Default 
    {throw "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"}
}
$systemtypes = $targetOrgProfile | Select-Object -Property * -ExcludeProperty Identity,General,ProfileType | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
$systems = @()
foreach ($systemtype in $systemtypes)
{
    foreach ($sys in $targetorgprofile.$systemtype)
    {
        $system = $sys.psobject.copy()
        $system | Add-Member -MemberType NoteProperty -Name SystemType -Value $systemtype
        $systems += $system
    }
}
$systems
}
Function Use-AdminUserProfile
{
[cmdletbinding()]
param(
    [parameter(ParameterSetName = 'Object',ValueFromPipeline=$true)]
    $profile 
    ,
    [parameter(ParameterSetName = 'Identity',ValueFromPipelineByPropertyname = $true, Mandatory = $true)]
    [string]$Identity
    ,
    [parameter(ParameterSetName = 'Identity',ValueFromPipelineByPropertyname = $true)]
    [ValidateScript({Test-DirectoryPath -Path $_})]
    [string[]]$Path
)
begin
{
    switch ($PSCmdlet.ParameterSetName)
    {
        'Object'
        {}
        'Identity'
        {
            $GetAdminUserProfileParams = @{
                Identity = $Identity
                Raw = $true
            }
            if ($PSBoundParameters.ContainsKey('Path'))
            {
                $GetAdminUserProfileParams.Path = $Path
            }
            $profile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
        }
    }
}#begin
process{
    #check if there is already a "Current" admin profile and if it is different from the one being used/applied by this run of the function
    #need to add some clean-up functionality for sessions when there is a change, or make it always optional to reset all sessions with this function
    if ($script:CurrentAdminUserProfile -and $profile.Identity -ne $script:CurrentAdminUserProfile.Identity) 
    {
        $script:CurrentAdminUserProfile = $profile
        Write-Warning "Admin User Profile has been changed to $($script:CurrentAdminUserProfile.Identity). Remove PSSessions and then re-establish connectivity using Connect-RemoteSystems."
    }
    else {
        $script:CurrentAdminUserProfile = $profile
        Write-Verbose "Admin User Profile has been set to $($script:CurrentAdminUserProfile.Identity), $($script:CurrentAdminUserProfile.general.name)."
    }
    #Retrieve the systems from the current org profile
    $systems = Get-OrgProfileSystem -OrganizationIdentity $script:CurrentAdminUserProfile.general.OrganizationIdentity
    #Build the autoconnect property and the mapped credentials for each system and store in the CurrentOrgAdminProfileSystems Script variable
    $Script:CurrentOrgAdminProfileSystems = 
    @(
        foreach ($sys in $systems) {
            $sys | Add-Member -MemberType NoteProperty -Name Autoconnect -Value $null
            [boolean]$autoconnect = $script:CurrentAdminUserProfile.systems | Where-Object -FilterScript {$sys.Identity -eq $_.Identity} | foreach-Object {$_.autoconnect}
            $sys.AutoConnect = $autoconnect
            if (! $sys.Autoconnect) {$sys.Autoconnect = $false}
            $sysPreCredential = $script:CurrentAdminUserProfile.Credentials | Where-Object -FilterScript {$_.systems -contains $sys.Identity} 
            if (! $sysPreCredential) {$Credential = $null}
            else {
                $SSPassword = $sysPreCredential.password | ConvertTo-SecureString
                $Credential = if ($sysPreCredential -and $SSPassword) {New-Object System.Management.Automation.PSCredential($sysPreCredential.Username,$SSPassword)} else {$null}
            }
            $sys | Add-Member -MemberType NoteProperty -Name Credential -value $Credential
            $sys
        }
    )
    #set folder paths
    $script:OneShellAdminUserProfileFolder = $script:CurrentAdminUserProfile.general.ProfileFolder
    #need to update the following to Script (Module) scoped variables . . . 
    $Script:LogFolderPath = "$script:OneShellAdminUserProfileFolder\Logs\"
    $Script:ReferenceFolder = "$script:OneShellAdminUserProfileFolder\Reference\"
    $Script:LogPath = "$script:OneShellAdminUserProfileFolder\Logs\$Script:Stamp" + '-AdminOperations.log'
    $Script:ErrorLogPath = "$script:OneShellAdminUserProfileFolder\Logs\$Script:Stamp" + '-AdminOperations-Errors.log'
    $Script:ExportDataPath = "$script:OneShellAdminUserProfileFolder\Export\"
    Return $true
}#process
}
Function Get-AdminUserProfile
{
[cmdletbinding(DefaultParameterSetName='All')]
param(
    #Add Location Validation to Parameter validation script
    [parameter(ParameterSetName = 'All')]
    [parameter(ParameterSetName = 'Identity')]
    [parameter(ParameterSetName = 'Name')]
    [ValidateScript({Test-DirectoryPath -Path $_})]
    [string[]]$Path = "$env:UserProfile\OneShell\"
    ,
    [parameter(ParameterSetName = 'All')]
    [parameter(ParameterSetName = 'Identity')]
    [parameter(ParameterSetName = 'Name')]
    $ProfileType = 'OneShellAdminUserProfile'
    ,
    [parameter(ParameterSetName = 'All')]
    [parameter(ParameterSetName = 'Identity')]
    [parameter(ParameterSetName = 'Name')]
    $OrgIdentity
    ,
    [parameter(ParameterSetName = 'Identity')]
    $Identity
    , 
    [parameter(ParameterSetName = 'Name')]
    $Name
    ,
    [parameter(ParameterSetName='Imported')]
    [switch]$Imported
    ,
    [parameter(ParameterSetName = 'All')]
    [parameter(ParameterSetName = 'Identity')]
    [parameter(ParameterSetName = 'Name')]
    [switch]$raw
)
if ($PSCmdlet.ParameterSetName -eq 'Imported')
{$outputprofiles = $AdminUserProfiles}
else
{
$outputprofiles = @(
    foreach ($loc in $Path)
    {
        $JSONProfiles = @(Get-ChildItem -Path $Loc -Filter *.JSON)
        if ($JSONProfiles.Count -ge 1) {
            $PotentialAdminUserProfiles = foreach ($file in $JSONProfiles) {Get-Content -Path $file.fullname -Raw | ConvertFrom-Json}
            $FoundAdminUserProfiles = @($PotentialAdminUserProfiles | Where-Object {$_.ProfileType -eq $ProfileType})
            if ($FoundAdminUserProfiles.Count -ge 1) {
                switch ($PSCmdlet.ParameterSetName) {
                    'All'
                    {
                        $FoundAdminUserProfiles
                    }
                    'Identity'
                    {
                        $FoundAdminUserProfiles | Where-Object -FilterScript {$_.Identity -eq $Identity}
                    }
                    'Name'
                    {
                        $FoundAdminUserProfiles | Where-Object -FilterScript {$_.General.Name -eq $Name}
                    }
                }
            }
        }
    }#foreach
)#outputprofiles
#filter the found profiles for OrgIdentity if specified
if (-not [string]::IsNullOrWhiteSpace($OrgIdentity))
{
    if ($OrgIdentity -eq 'CurrentOrg')
    {$OrgIdentity = $script:CurrentOrgProfile.Identity}
    $outputprofiles = $outputprofiles | Where-Object -FilterScript {$_.general.organizationidentity -eq $OrgIdentity}
}
#output the found profiles
if ($raw)
{
    $outputprofiles
}#if Raw
else
{
    $outputprofiles | Select-Object -Property @{n='Identity';e={$_.Identity}},@{n='Name';e={$_.General.Name}},@{n='Default';e={$_.General.Default}},@{n='OrgIdentity';e={$_.general.organizationidentity}}
}#else when not "Raw"
}#else when not "Imported"
}#function Get-AdminUserProfile
Function Import-AdminUserProfile
{
[cmdletbinding()]
param
(
[parameter()]
[ValidateScript({Test-DirectoryPath -Path $_})]
[string[]]$Path
,
$ProfileType
,
$OrgIdentity
,
$Identity
,
$Name
)
$getAdminUserProfileParams=
@{
    raw = $true
    ErrorAction = 'stop'
}
if ($PSBoundParameters.ContainsKey('Path'))
{
    $getAdminUserProfileParams.Location = $Path
}
if ($PSBoundParameters.ContainsKey('ProfileType'))
{
    $getAdminUserProfileParams.ProfileType = $ProfileType
}
if ($PSBoundParameters.ContainsKey('Identity'))
{
    $getAdminUserProfileParams.Identity = $Identity
}
if ($PSBoundParameters.ContainsKey('Name'))
{
    $getAdminUserProfileParams.Name = $Name
}
if ($PSBoundParameters.ContainsKey('OrgIdentity'))
{
    $getAdminUserProfileParams.OrgIdentity = $OrgIdentity
}
try
{
    $Script:AdminUserProfiles = @(Get-AdminUserProfile @getAdminUserProfileParams)
    Write-Output $True
}
catch
{
    Write-Output $false
}
}
Function Select-AdminUserProfile {
    param(
        [parameter()]
        [validateset('Use','Edit')]
        $purpose 
    )
    $MenuDefinition = [pscustomobject]@{
        GUID = [guid]::NewGuid()
        Title = "Select Admin User Profile to $purpose"
        Initialization = ''
        ParentGUID = $null
        Choices = @()
    }
    foreach ($profile in $Script:AdminUserProfiles) {
        $MenuDefinition.choices += [pscustomobject]@{
            choice = $profile.general.Name
            command = switch ($purpose) {
                'Edit' {"Set-AdminUserProfile -Identity $($Profile.Identity)"} 
                'Use' {"Use-AdminUserProfile -Identity $($profile.identity)"}
            }#switch
            exit = $true
        }

    }
    Invoke-Menu -menudefinition $MenuDefinition 
}
function New-AdminUserProfile
{
[cmdletbinding()]
param
(
    [parameter(Mandatory)]
    [string]$OrganizationIdentity
    ,
    [string]$name
)
    $targetOrgProfile = @(Get-OrgProfile -Identity $OrganizationIdentity -raw)
    switch ($targetOrgProfile.Count)
    {
        1 {}
        0
        {
            $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $OrganizationIdentity -Message "No matching Organization Profile was found for identity $OrganizationIdentity"
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        Default
        {
            $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $OrganizationIdentity -Message "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }
    Write-Verbose -Message 'NOTICE: This function uses interactive windows/dialogs which may sometimes appear underneath the active window.  If things seem to be locked up, check for a hidden window.' -Verbose
    #Build the basic Admin profile object
    $newAdminUserProfile = [ordered]@{
        Identity = [guid]::NewGuid()
        ProfileType = 'OneShellAdminUserProfile'
        General = [ordered]@{
            Name = if ($name) {"$name-" + $targetOrgProfile.general.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME} else {$targetOrgProfile.general.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME}
            Host = $env:COMPUTERNAME
            OrganizationIdentity = $targetOrgProfile.identity
            ProfileFolder = GetAdminUserProfileFolder
            Default = if ((Read-Choice -Message "Should this be the default profile for Organization Profile $($targetorgprofile.general.name)?" -Choices 'Yes','No' -DefaultChoice 1 -Title 'Default Profile?') -eq 0) {$true} else {$false}
        }
        Systems = @()
        Credentials = @()
    }
    #Get the Admin user's email address
    $newAdminUserProfile.General.MailFrom = GetAdminUserProfileEmailAddress
    #Get Org Profile Defined Systems
    $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
    #Select the mail relay endpoint for the profile to use
    $MailRelayEndpoints = @($systems | where-object -FilterScript {$_.SystemType -eq 'MailRelayEndpoints'})
    if ($MailRelayEndpoints.Count -gt 1)
    {
        $Message = "Organization Profile $($targetorgprofile.general.name) defines more than one mail relay endpoint.  Which one would you like to use for this Admin profile?"
        $choices = $MailRelayEndpoints | Select-Object -Property @{n='choice';e={$_.Name + '(' + $_.ServiceAddress + ')'}} | Select-Object -ExpandProperty Choice
        $choice = Read-Choice -Message $Message -Choices $choices -DefaultChoice 1 -Title "Select Mail Relay Endpoint"
        $MailRelayEndpointToUse = $MailRelayEndpoints[$choice] | Select-Object -ExpandProperty Identity
    }
    else
    {
        $MailRelayEndpointToUse = $MailRelayEndpoints[0] | Select-Object -ExpandProperty Identity
    }
    $newAdminUserProfile.General.MailRelayEndpointToUse = $MailRelayEndpointToUse
    #Get the admin User's Credentials
    $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems)
    #Prepare Stored Credentials to associate with one or more systems
    :SysCredAssociation foreach ($sys in $systems) #using the label just to make the use of Continue explicit in the code below
    {
        if ($sys.AuthenticationRequired -eq $false) {Continue SysCredAssociation}
        if ($sys.SystemType -eq 'MailRelayEndpoints')
        {
            if ($sys.Identity -eq $MailRelayEndpointToUse) {$autoConnectChoice = 1}
            else {Continue SysCredAssociation}
        }
        else
        {
            $label = $sys | Select-Object @{n='name';e={$_.SystemType + ': ' + $_.Name}} | Select-Object -ExpandProperty Name
            $prompt = "Do you want to Auto Connect to this system with this admin profile: `n`n$label"
            $autoConnectChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -DefaultChoice 0 -Title 'Auto Connect?'
        }
        switch ($autoConnectChoice) {
            0 {
                $SystemEntry = [ordered]@{'Identity' = $sys.Identity;'Autoconnect' = $true}
                $newAdminUserProfile.Systems += $SystemEntry
                #associate a credential with the autoconnect system
                $prompt = "Which Credential do you want to associate with this system: `n`n$label"
                $choice = Read-Choice -Message $prompt -Choices $exportcredentials.Username -Title "Associate Credential:$label" -DefaultChoice 0
                [array]$currentAssociatedSystems = @($exportcredentials[$choice].Systems)
                $currentAssociatedSystems += $sys.Identity
                $exportcredentials[$choice].Systems = $currentAssociatedSystems
            }
            1 {
                $SystemEntry = [ordered]@{'Identity' = $sys.Identity;'Autoconnect' = $false}
                $newAdminUserProfile.Systems += $SystemEntry
                #ask if user still wants to associate a credential
                $prompt = "Do you want to associate a credential for on demand connections to this system: `n`n$label"
                $AssociateOnDemandCredentialChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -Title "Associate Credential:$label" -DefaultChoice 1
                switch ($AssociateOnDemandCredentialChoice) {
                    0 {
                        #associate a credential with the non-autoconnect system for on demand connections via profile
                        $prompt = "Which Credential do you want to associate with this system: `n`n$label"
                        $choice = Read-Choice -Message $prompt -Choices $exportcredentials.Username -Title "Associate Credential:$label" -DefaultChoice 0
                        [array]$currentAssociatedSystems = @($exportcredentials[$choice].Systems)
                        $currentAssociatedSystems += $sys.Identity
                        $exportcredentials[$choice].Systems = $currentAssociatedSystems
                    }
                    1 {}
                }
            }
        }
        Remove-Variable -Name SystemEntry
    }
    #add the stored and system associated credentials to the profile
    $newAdminUserProfile.Credentials = @($exportcredentials)
    #if necessary, create the Admin Profile File System Folders and export the JSON profile file
    try
    {
        if (Add-AdminUserProfileFolders -AdminUserProfile $newAdminUserProfile -path $newAdminUserProfile.General.profileFolder -ErrorAction Stop)
        {
            if (Export-AdminUserProfile -profile $newAdminUserProfile -ErrorAction Stop -path $newAdminUserProfile.General.profileFolder)
            {
                if (Get-AdminUserProfile -Identity $newAdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $newAdminUserProfile.General.profileFolder)
                {
                    Write-Log -Message "New Admin Profile with Name: $($newAdminUserProfile.General.Name) and Identity: $($newAdminUserProfile.Identity) was successfully configured, exported, and imported." -Verbose -ErrorAction SilentlyContinue -EntryType Notification
                    Write-Log -Message "To initialize the new profile for immediate use, run 'Use-AdminUserProfile -Identity $($newAdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue -EntryType Notification
                }
            }
        }
    }
    catch
    {
        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($newAdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
    }
    #return the admin profile raw object to the pipeline
    Write-Output $newAdminUserProfile
}# New-AdminUserProfile
function Set-AdminUserProfile
{
    [cmdletbinding()]
    param(
        [parameter(ParameterSetName = 'Object')]
        [psobject]$profile 
        ,
        [parameter(ParameterSetName = 'Identity',Mandatory = $true)]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript({Test-DirectoryPath -Path $_})]
        [string[]]$Path 
    )
    switch ($PSCmdlet.ParameterSetName) {
        'Object' {$editAdminUserProfile = $profile}
        'Identity'
        {
            $GetAdminUserProfileParams = @{
                Identity = $Identity
                Raw = $true
            }
            if ($PSBoundParameters.ContainsKey('Path'))
            {
                $GetAdminUserProfileParams.Path = $Path
            }
            $editAdminUserProfile = $(Get-AdminUserProfile @GetAdminUserProfileParams)
        }
    }
    $OrganizationIdentity = $editAdminUserProfile.General.OrganizationIdentity
    $targetOrgProfile = @(Get-OrgProfile -Identity $OrganizationIdentity -raw)
    switch ($targetOrgProfile.Count)
    {
        1 {}
        0
        {
            $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $OrganizationIdentity -Message "No matching Organization Profile was found for identity $OrganizationIdentity"
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        Default
        {
            $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $OrganizationIdentity -Message "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
    }
    Write-Verbose -Message 'NOTICE: This function uses interactive windows/dialogs which may sometimes appear underneath the active window.  If things seem to be locked up, check for a hidden window.' -Verbose
    #Set Admin Profile to Default or Not Default
    if ($editAdminUserProfile.General.Default) {
        $prompt = "This admin profile is currently the Default Admin Profile.`n`nShould this be the default profile for Organization Profile $($targetorgprofile.general.name)?"
        $defaultChoiceDefault = 0
    }
    else {
        $prompt = "This admin profile is currently NOT the Default Admin Profile.`n`nShould this be the default profile for Organization Profile $($targetorgprofile.general.name)?"
        $defaultChoiceDefault = 1
    }
    $editAdminUserProfile.General.Default = if ((Read-Choice -Message $prompt -Choices 'Yes','No' -DefaultChoice $defaultChoiceDefault -Title 'Default Profile?') -eq 0) {$true} else {$false}
    #Get the Admin user's email address
    if (Test-Member -InputObject $editAdminUserProfile.General -Name MailFrom)
    {
        $currentEmailAddress = $editAdminUserProfile.General.MailFrom
    }
    else
    {
        $editAdminUserProfile.General | Add-Member -MemberType NoteProperty -Name MailFrom -Value $null
    }
    $editAdminUserProfile.General.MailFrom = GetAdminUserProfileEmailAddress -CurrentEmailAddress $currentEmailAddress
    #Get Org Profile Defined Systems
    $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
    $MailRelayEndpoints = @($systems | where-object -FilterScript {$_.SystemType -eq 'MailRelayEndpoints'})
    if ($MailRelayEndpoints.Count -gt 1)
    {
        $Message = "Organization Profile $($targetorgprofile.general.name) defines more than one mail relay endpoint.  Which one would you like to use for this Admin profile?"
        $choices = $MailRelayEndpoints | Select-Object -Property @{n='choice';e={$_.Name + '(' + $_.ServiceAddress + ')'}} | Select-Object -ExpandProperty Choice
        $choice = Read-Choice -Message $Message -Choices $choices -DefaultChoice 1 -Title "Select Mail Relay Endpoint"
        $MailRelayEndpointToUse = $MailRelayEndpoints[$choice] | Select-Object -ExpandProperty Identity
    }
    else
    {
        $MailRelayEndpointToUse = $MailRelayEndpoints[0] | Select-Object -ExpandProperty Identity
    }
    if (-not (Test-Member -InputObject $editAdminUserProfile.General -Name MailRelayEndpointToUse))
    {
        $editAdminUserProfile.General | Add-Member -MemberType NoteProperty -Name MailRelayEndpointToUse -Value $MailRelayEndpointToUse
    }
    $editAdminUserProfile.General.MailRelayEndpointToUse = $MailRelayEndpointToUse
    #Get User's Credentials
    $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems -credentials $editAdminUserProfile.Credentials -edit)
    #Prepare Stored Credentials to associate with one or more systems
    $exportcredentials | foreach {$_.systems=@()}
    #Prepare Edited System Entries variable:
    $EditedSystemEntries = @()
    :SysCredAssociation foreach ($sys in $systems) {
        if ($sys.AuthenticationRequired -eq $false) {Continue SysCredAssociation}
        if ($sys.SystemType -eq 'MailRelayEndpoints')
        {
            if ($sys.Identity -eq $MailRelayEndpointToUse) {$autoConnectChoice = 1}
        }
        else
        {
            $label = $sys | Select-Object @{n='name';e={$_.SystemType + ': ' + $_.Name}} | Select-Object -ExpandProperty Name
            $currentAutoConnect = $editAdminUserProfile.Systems | Where-Object -FilterScript {$_.Identity -eq $Sys.Identity} | Foreach-Object {$_.Autoconnect}
            [string]$currentCredential = $editAdminUserProfile.Credentials | Where-Object -FilterScript {$_.systems-contains $sys.Identity} | Foreach-Object {$_.UserName}
            switch ($currentAutoConnect) {
                $true {
                    $prompt = "This system currently is set to Auto Connect in this profile.`n`nDo you want to Auto Connect to this system with this admin profile? `n`n$label"
                    $DefaultChoiceAC = 0
                }
                $false {
                    $prompt = "This system currently is NOT set to Auto Connect in this profile.`n`nDo you want to Auto Connect to this system with this admin profile? `n`n$label"
                    $DefaultChoiceAC = 1
                }
                Default {
                    $prompt = "Do you want to Auto Connect to this system with this admin profile? `n`n$label"
                    $DefaultChoiceAC = -1
                }
            }
            $autoConnectChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -DefaultChoice $DefaultChoiceAC -Title 'Auto Connect?'
        }
        switch ($autoConnectChoice) {
            0 {
                $SystemEntry = [ordered]@{'Identity' = $sys.Identity;'Autoconnect' = $true}
                $EditedSystemEntries += $SystemEntry
                #associate a credential with the autoconnect system
                if (-not [string]::IsNullOrWhiteSpace($currentCredential)) {
                    $prompt = "This system is currently configured to use Credential: $currentCredential`n`nWhich Credential do you want to associate with this system: `n`n$label"
                    $defaultchoicecred = Get-ArrayIndexForValue -array $exportcredentials -value $currentCredential -property UserName
                }#if
                else {
                    $defaultchoicecred = -1
                    $prompt = "Which Credential do you want to associate with this system: `n`n$label"
                }
                $choice = Read-Choice -Message $prompt -Choices $exportcredentials.Username -Title "Associate Credential:$label" -DefaultChoice $defaultchoicecred
                [array]$currentAssociatedSystems = @($exportcredentials[$choice].Systems)
                $currentAssociatedSystems += $sys.Identity
                $exportcredentials[$choice].Systems = $currentAssociatedSystems
            }
            1 {
                $SystemEntry = [ordered]@{'Identity' = $sys.Identity;'Autoconnect' = $false}
                $EditedSystemEntries += $SystemEntry
                #ask if user still wants to associate a credential
                $prompt = "Do you want to associate a credential for on demand connections to this system: `n`n$label"
                $AssociateOnDemandCredentialChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -Title "Associate Credential:$label" -DefaultChoice 1
                switch ($AssociateOnDemandCredentialChoice) {
                    0 {
                        #associate a credential with the autoconnect system
                        if (-not [string]::IsNullOrWhiteSpace($currentCredential)) {
                            $prompt = "This system is currently configured to use Credential: $currentCredential`n`nWhich Credential do you want to associate with this system: `n`n$label"                
                            $defaultchoicecred = Get-ArrayIndexForValue -array $exportcredentials -value $currentCredential -property UserName
                        }#if
                        else {
                            $defaultchoicecred = -1                
                            $prompt = "Which Credential do you want to associate with this system: `n`n$label"
                        }
                        $choice = Read-Choice -Message $prompt -Choices $exportcredentials.Username -Title "Associate Credential:$label" -DefaultChoice $defaultchoicecred
                        [string[]]$currentAssociatedSystems = @($exportcredentials[$choice].Systems)
                        $currentAssociatedSystems += $sys.Identity
                        $exportcredentials[$choice].Systems = $currentAssociatedSystems
                    }
                    1 {}
                }
            }
        }
        Remove-Variable -Name SystemEntry
    }
    $editAdminUserProfile.Credentials = @($exportcredentials)
    $editAdminUserProfile.Systems = $EditedSystemEntries
    #<#
    try {
        if (Add-AdminUserProfileFolders -AdminUserProfile $editAdminUserProfile -ErrorAction Stop -path $editAdminUserProfile.General.ProfileFolder) {
            if (Export-AdminUserProfile -profile $editAdminUserProfile -ErrorAction Stop -path $editAdminUserProfile.General.ProfileFolder) {
                if (Get-AdminUserProfile -Identity $editAdminUserProfile.Identity.tostring() -ErrorAction Stop -Path $editAdminUserProfile.General.ProfileFolder) {
                    Write-Log -Message "Edited Admin Profile with Name: $($editAdminUserProfile.General.Name) and Identity: $($editAdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                    Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($editAdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                }
            }
        }
        $editAdminUserProfile    
    }
    catch {
        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($editAdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
    }
    ##>
}# Set-AdminUserProfile
#supporting functions for AdminUserProfile Editing
function GetAdminUserProfileFolder
{
    $message = "Select a location for your admin user profile directory. A sub-directory named 'OneShell' will be created in the selected directory if one does not already exist. The user profile $($env:UserProfile) is the recommended location.  Additionally, under the OneShell directory, sub-directories for Logs, Input, and Export files will be created."
    Do
    {
        $UserChosenPath = Read-FolderBrowserDialog -Message $message  -InitialDirectory 'MyComputer' 
        if (Test-IsWriteableDirectory -Path $UserChosenPath)
        {
            $ProfileFolderToCreate = Join-Path $UserChosenPath 'OneShell'
            $IsWriteableFilesystemDirectory = $true
        }
    }
    Until
    (
        $IsWriteableFilesystemDirectory
    )
    $ProfileFolderToCreate
}#function GetAdminUserProfileFolder
function GetAdminUserProfileEmailAddress
{
[cmdletbinding()]
param(
    $CurrentEmailAddress
)
$ReadInputBoxDialogParams = @{
    Message = 'Specify a valid E-mail address to be associated with this Admin profile for the sending/receiving of email messages.'
    WindowTitle =  'OneShell Admin Profile E-mail Address'
}
if ($PSBoundParameters.ContainsKey('CurrentEmailAddress'))
{
    $ReadInputBoxDialogParams.DefaultText = $CurrentEmailAddress
} 
do
{
    $address = Read-InputBoxDialog @ReadInputBoxDialogParams
}
until
(Test-EmailAddress -EmailAddress $address)
$address
}
function Add-AdminUserProfileFolders {
    [cmdletbinding()]
    param(
        $AdminUserProfile
        ,
        $path = $env:USERPROFILE + '\OneShell'
    )
    $AdminUserJSONProfileFolder = $path
    if (-not (Test-Path -Path $AdminUserJSONProfileFolder)) {
        New-Item -Path $AdminUserJSONProfileFolder -ItemType Directory -ErrorAction Stop
    }
    $profilefolder = $AdminUserProfile.General.ProfileFolder 
    $profilefolders =  $($profilefolder + '\Logs'), $($profilefolder + '\Export'),$($profilefolder + '\InputFiles')
    foreach ($folder in $profilefolders) {
        if (-not (Test-Path $folder)) {
            New-Item -Path $folder -ItemType Directory -ErrorAction Stop
        }
    }
    $true
}
function Set-AdminUserProfileCredentials {
    [cmdletbinding(DefaultParameterSetName='New')]
    param(
        [parameter(ParameterSetName='New',Mandatory = $true)]
        [parameter(ParameterSetName='Edit',Mandatory = $true)]
        $systems
        ,
        [parameter(ParameterSetName='Edit')]
        [switch]$edit
        ,
        [parameter(ParameterSetName='Edit',Mandatory = $true)]
        [psobject[]]$Credentials
    )
    switch ($PSCmdlet.ParameterSetName) {
        'Edit' {
            $editableCredentials = @($Credentials | Select-Object @{n='UserName';e={$_.UserName}},@{n='Password';e={$_.Password | ConvertTo-SecureString}})
        }
        'New' {$editableCredentials = @()}
    }
    $systems = $systems | Where-Object -FilterScript {$_.AuthenticationRequired -eq $null -or $_.AuthenticationRequired -eq $true} #null is for backwards compatibility if the AuthenticationRequired property is missing.
    $labels = $systems | Select-Object @{n='name';e={$_.SystemType + ': ' + $_.Name}}
    do {
        $prompt = @"
You may associate a credential with each of the following systems for auto connection or on demand connections/usage:

$($labels.name -join "`n")

You have created the following credentials so far:
$($editableCredentials.UserName -join "`n")

In the next step, you may modify the association of these credentials with the systems above.

Would you like to add, edit, or remove a credential?"
"@
        $response = Read-Choice -Message $prompt -Choices 'Add','Edit','Remove','Done' -DefaultChoice 0 -Title 'Add/Remove Credential?'
        switch ($response) {
            0 {#Add
                $editableCredentials += $host.ui.PromptForCredential('Add Credential','Specify the Username and Password for your credential','','')
            }
            1 {#Edit
                if ($editableCredentials.Count -lt 1) {Write-Error -Message 'There are no credentials to edit'}
                else {
                    $CredChoices = @($editableCredentials.UserName)
                    $whichcred = Read-Choice -Message 'Select a credential to edit' -Choices $CredChoices -DefaultChoice 0 -Title 'Select Credential to Edit'
                    $editableCredentials[$whichcred] = $host.ui.PromptForCredential('Edit Credential','Specify the Username and Password for your credential',$editableCredentials[$whichcred].UserName,'')
                }
                
            }
            2 {#Remove
                if ($editableCredentials.Count -lt 1) {Write-Error -Message 'There are no credentials to remove'}
                else {
                    $CredChoices = @($editableCredentials.UserName)
                    $whichcred = Read-Choice -Message 'Select a credential to remove' -Choices $CredChoices -DefaultChoice 0 -Title 'Select Credential to Remove'
                    $editableCredentials = @($editableCredentials | Where-Object -FilterScript {$editableCredentials[$whichcred] -ne $_})
                }
                
            }
            3 {$noMoreCreds = $true} #Done
        }
    }
    until ($noMoreCreds -eq $true)
    $exportcredentials = $editableCredentials | Select-Object @{n='UserName';e={$_.UserName}},@{n='Password';e={$_.Password | ConvertFrom-SecureString}},@{n='Systems';e={[string[]]@()}}
    Write-Output $exportcredentials
}
Function Export-AdminUserProfile
{
[cmdletbinding()]
param(
    [parameter(Mandatory=$true)]
    $profile
    ,
    $path = "$($Env:USERPROFILE)\OneShell\"
)
    if ($profile.Identity -is 'GUID')
    {$name = $($profile.Identity.Guid) + '.JSON'} 
    else
    {$name = $($profile.Identity) + '.JSON'}
    $fullpath = Join-Path $path $name
    $ConvertToJsonParams =@{
        InputObject = $profile
        ErrorAction = 'Stop'
        Depth = 4
    }
    try
    {
        ConvertTo-Json @ConvertToJsonParams | Out-File -FilePath $fullpath -Encoding ascii -ErrorAction Stop -Force 
        Write-Output $true
    }#try
    catch
    {
        $_
        throw "FAILED: Could not write Admin User Profile data to $path"
    }#catch
}
Function Initialize-AdminEnvironment
{
[cmdletbinding(defaultparametersetname = 'AutoConnect')]
param(
    [parameter(ParameterSetName = 'AutoConnect')]
    [switch]$AutoConnect
    ,
    [parameter(ParameterSetName = 'ShowMenu')]
    [switch]$ShowMenu
    ,
    [parameter(ParameterSetName = 'SpecifiedProfile')]
    $OrgProfile
    ,
    [parameter(ParameterSetName = 'SpecifiedProfile')]
    $AdminProfile
)
Process
{
Switch ($PSCmdlet.ParameterSetName)
{
    'AutoConnect'
    {
        if (Import-OrgProfile)
        {
            $DefaultOrgProfile = @($script:OrgProfiles | Where-Object {$_.General.Default -eq $true})
            switch ($DefaultOrgProfile.Count)
            {
                {$_ -eq 1}
                {
                    [boolean]$OrgProfileLoaded = Use-OrgProfile -Profile $DefaultOrgProfile
                }
                {$_ -gt 1}
                {
                    Write-Error "FAILED: Multiple Org Profiles Are Set as Default: $($DefaultOrgProfile.Identity -join ',')"
                }
                {$_ -lt 1}
                {
                    Write-Error 'FAILED: No Org Profiles Are Set as Default'
                }
            }#Switch $DefaultOrgProfile.Count
        }#If Get-OrgProfile
        if ($OrgProfileLoaded)
        {
            if (Import-AdminUserProfile -OrgIdentity CurrentOrg)
            {
                $DefaultAdminUserProfile = @($script:AdminUserProfiles | Where-Object -FilterScript {$_.General.Default -eq $true})
            }
            switch ($DefaultAdminUserProfile.Count) 
            {
                {$_ -eq 1}
                {
                    $message = "Admin user profile has been set to Name:$($DefaultAdminUserProfile.General.Name), Identity:$($DefaultAdminUserProfile.Identity)."
                    Write-Log -Message $message -Verbose -ErrorAction SilentlyContinue -EntryType Notification
                    [boolean]$AdminUserProfileLoaded = Use-AdminUserProfile -Profile $DefaultAdminUserProfile
                    if ($AdminUserProfileLoaded)
                    {
                        Write-Log -Message "Running Connect-RemoteSystems" -EntryType Notification
                        Connect-RemoteSystems
                    }#if
                }
                {$_ -gt 1}
                {
                    Write-Error "FAILED: Multiple Admin User Profiles Are Set as Default for $($CurrentOrgProfile.Identity): $($DefaultAdminUserProfile.Identity -join ',')"
                    Use-AdminUserProfile -Identity (Select-AdminUserProfile -purpose Use)
                }
                {$_ -lt 1}
                {
                    Write-Warning "No Admin User Profiles Are Set as Default for $($CurrentOrgProfile.Identity)"
                    switch ($Script:AdminUserProfiles.count)
                    {
                        {$_ -ge 1}
                        {
                            Use-AdminUserProfile -Identity (Select-AdminUserProfile -purpose Use)
                        }
                        {$_ -lt 1}
                        {
                            $newAdminUserProfile = New-AdminUserProfile -OrganizationIdentity $CurrentOrgProfile.Identity
                        }
                    }
                }
            }#Switch
        }#If $OrgProfileLoaded
    }#AutoConnect
    'ShowMenu'
    {
        Start-Sleep -Seconds 2
        $menudefinition = [pscustomobject]@{
            GUID = 'ac4ce63e-8b76-4381-a1d5-ad19510f47c7'
            Title = 'OneShell Module Startup Menu'
            Initialization = $Null
            Choices = @(
                #[pscustomobject]@{choice='Connect to Autoconnect Remote Systems from Initialized Profile (Runs command Connect-RemoteSystems)';command='Connect-RemoteSystems';exit=$true}
                [pscustomobject]@{choice='Manage Organization and/or Admin User Profiles';command='Invoke-Menu -menuGUID 9e7ff8e1-afbb-418d-a31f-9c07bce3ab33'}
                [pscustomobject]@{choice='Exit to Command Line';command='';exit=$true}
            )
            ParentGUID = $Null
        }
        Invoke-Menu -menudefinition $menudefinition
    }#ShowMenu
}#Switch
}#Process
}
##########################################################################################################
#Module Variables and Variable Functions
##########################################################################################################
#Import-Module PsMenu -Global #moved to module manifest - remove comment later
function Get-OneShellVariable 
{
param
(
[string]$Name
)
    Get-Variable -Scope Script -Name $name 
}
function Get-OneShellVariableValue 
{
param
(
[string]$Name
)
    Get-Variable -Scope Script -Name $name -ValueOnly
}
function Set-OneShellVariable 
{
param
(
[string]$Name
,
$Value
)
    Set-Variable -Scope Script -Name $Name -Value $value  
}
function New-OneShellVariable 
{
param 
(
[string]$Name
,
$Value
)
    New-Variable -Scope Script -Name $name -Value $Value
}
function Remove-OneShellVariable
{
param
(
[string]$Name
)
    Remove-Variable -Scope Script -Name $name
}
#Global Variables to be replaced with Module/Script Level Variables in a coming release
function Set-OneShellVariables
{
    #Write-Log -message 'Setting OneShell Module Variables'
    $Script:OneShellModuleFolderPath = $PSScriptRoot #Split-Path $((Get-Module -ListAvailable -Name OneShell).Path)
    [string]$Script:E4_SkuPartNumber = 'ENTERPRISEWITHSCAL' 
    [string]$Script:E3_SkuPartNumber = 'ENTERPRISEPACK' 
    [string]$Script:E2_SkuPartNumber = 'STANDARDWOFFPACK' #Non-Profit SKU
    [string]$Script:E1_SkuPartNumber = 'STANDARDPACK'
    [string]$Script:K1_SkuPartNumber = 'DESKLESSPACK' 
    $Script:LogPreference = $True
    #AdvancedOneShell needs updated for the following:
    $Script:ScalarADAttributesToRetrieve = @(
        'altRecipient'
        'forwardingAddress'
        'msExchGenericForwardingAddress'
        'cn'
        'userPrincipalName'
        'sAMAccountName'
        'CanonicalName'
        'GivenName'
        'SurName'
        'DistinguishedName'
        'ObjectGUID'
        'mS-DS-ConsistencyGuid'
        'displayName'
        'employeeNumber'
        'employeeID'
        'Mail'
        'mailNickname'
        'homeMDB'
        'homeMTA'
        'msExchHomeServerName'
        'legacyExchangeDN'
        'msExchArchiveGUID'
        'msExchArchiveName'
        'msExchMailboxGUID'
        'msExchMasterAccountSID'
        'msExchUserCulture'
        'targetAddress'
        'msExchRecipientDisplayType'
        'msExchRecipientTypeDetails'
        'msExchRemoteRecipientType'
        'msExchVersion'
        'extensionattribute1'
        'extensionattribute2'
        'extensionattribute3'
        'extensionattribute4'
        'extensionattribute5'
        'extensionattribute6'
        'extensionattribute7'
        'extensionattribute8'
        'extensionattribute9'
        'extensionattribute10'
        'extensionattribute11'
        'extensionattribute12'
        'extensionattribute13'
        'extensionattribute14'
        'extensionattribute15'
        'canonicalname'
        'department'
        'deliverandRedirect'
        'distinguishedName'
        'msExchHideFromAddressLists'
        'msExchPoliciesExcluded'
        'msExchUsageLocation'
        'c'
        'co'
        'country'
        'physicalDeliveryOfficeName'
    )#Scalar Attributes to Retrieve
    $Script:MultiValuedADAttributesToRetrieve = @(
        'proxyAddresses'
        'msexchextensioncustomattribute1'
        'msexchextensioncustomattribute2'
        'msexchextensioncustomattribute3'
        'msexchextensioncustomattribute4'
        'msexchextensioncustomattribute5'
        'memberof'
        'msExchPoliciesExcluded'
    )#MultiValuedADAttributesToRetrieve
    $Script:AllADAttributesToRetrieve = @($ScalarADAttributesToRetrieve + $MultiValuedADAttributesToRetrieve)
    $Script:AllADContactAttributesToRetrieve = $script:AllADAttributesToRetrieve | Where-Object {$_ -notin ('surName','country','homeMDB','homeMTA','msExchHomeServer')}
    $Script:Stamp = Get-TimeStamp
    #Module Menu Definitions
    $menudefinition = [pscustomobject]@{
        GUID = '14aee7c9-6e2a-48bd-bdff-93be72bfc65a'
        Title = 'OneShell Profile Maintenance'
        Initialization = $null
        Choices = @(
        )
        ParentGUID = $null
    }
    Add-MenuDefinition -MenuDefinition $menudefinition

    $menudefinition = [pscustomobject]@{
        GUID = '9e7ff8e1-afbb-418d-a31f-9c07bce3ab33'
        Title = 'OneShell Admin User Profile Maintenance'
        Initialization = $Null
        Choices = @(
            [pscustomobject]@{choice='View Existing Admin User Profiles';command='Get-AdminUserProfile -OrgIdentity CurrentOrg; Read-Host -Prompt "Press enter to Continue"'}
            [pscustomobject]@{choice='Edit an existing Admin User Profile';command='Select-AdminUserProfile -purpose Edit'}
            [pscustomobject]@{choice='Use an existing Admin User Profile';command='Select-AdminUserProfile -purpose Use';exit = $true}
            [pscustomobject]@{choice='Create a new Admin User Profile';command='$prompt = "Enter a short descriptive name for this profile";New-AdminUserProfile -OrganizationIdentity $($CurrentOrgProfile.Identity) -name (read-host -Prompt $prompt)'}
        )
        ParentGUID = '14aee7c9-6e2a-48bd-bdff-93be72bfc65a'
    }
    Add-MenuDefinition -MenuDefinition $menudefinition

    $menudefinition = [pscustomobject]@{
    GUID = 'bfbcf228-1e2e-4289-a7cd-eae003cc3740'
    Title = 'OneShell Organization Profile Maintenance'
    Initialization = $Null
    Choices = @(
        [pscustomobject]@{choice='View Existing Organization Profiles';command='Get-OrgProfile; Read-Host -Prompt "Press enter to Continue"'}
        #[pscustomobject]@{choice='Edit an existing Organization Profile';command='Select-AdminUserProfile -purpose Edit'}
        [pscustomobject]@{choice='Use an existing Organization Profile';command='Select-OrgProfile -purpose Use'; exit = $true}
        #[pscustomobject]@{choice='Create a new Organization Profile';command='$prompt = "Enter a short descriptive name for this profile";New-AdminUserProfile -OrganizationIdentity $($CurrentOrgProfile.Identity) -name (read-host -Prompt $prompt)'}
    )
    ParentGUID = '14aee7c9-6e2a-48bd-bdff-93be72bfc65a'
    }
    Add-MenuDefinition -MenuDefinition $menudefinition
}
##########################################################################################################
#Initialization
##########################################################################################################
Set-OneShellVariables
#Do one of the following in your profile or run script:
#Initialize-AdminEnvironment
# OR
#Get-OrgProfile
#Select-OrgProfile -purpose Use
#Get-AdminUserProfile -OrgIdentity CurrentOrg
#Use-AdminUserProfile -Identity [GUID]