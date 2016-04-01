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
function Get-AvailableExceptionsList {
    [CmdletBinding()]
    param()
    end {
        $irregulars = 'Dispose|OperationAborted|Unhandled|ThreadAbort|ThreadStart|TypeInitialization'
        [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object {
            $_.GetExportedTypes() -match 'Exception' -notmatch $irregulars |
            Where-Object {
                $_.GetConstructors() -and $(
                    $_exception = New-Object $_.FullName
                    New-Object Management.Automation.ErrorRecord $_exception, ErrorID, OpenError, Target
                )
            } | Select-Object -ExpandProperty FullName
        } 2> $null
    }

    <#  .Synopsis      Retrieves all available Exceptions to construct ErrorRecord objects.  .Description      Retrieves all available Exceptions in the current session to construct ErrorRecord objects.  .Example      $availableExceptions = Get-AvailableExceptionsList      Description      ===========      Stores all available Exception objects in the variable 'availableExceptions'.  .Example      Get-AvailableExceptionsList | Set-Content $env:TEMP\AvailableExceptionsList.txt      Description      ===========      Writes all available Exception objects to the 'AvailableExceptionsList.txt' file in the user's Temp directory.  .Inputs     None  .Outputs     System.String  .Link      New-ErrorRecord  .Notes      Name:      Get-AvailableExceptionsList      Author:    Robert Robelo      LastEdit:  08/24/2011 12:35  #>
}
function New-ErrorRecord {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]
        $Exception,
        [Parameter(Mandatory = $true, Position = 1)]
        [Alias('ID')]
        [System.String]
        $ErrorId,
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
        $ErrorCategory,
        [Parameter(Mandatory = $true, Position = 3)]
        [System.Object]
        $TargetObject,
        [Parameter()]
        [System.String]
        $Message,
        [Parameter()]
        [System.Exception]
        $InnerException
    )
    begin {
        # check for required function, if not defined...
        if (-not (Test-Path function:Get-AvailableExceptionsList)) {
            $message1 = "The required function Get-AvailableExceptionsList is not defined. " +
            "Please define it in the same scope as this function's and try again."
            $exception1 = New-Object System.OperationCanceledException $message1
            $errorID1 = 'RequiredFunctionNotDefined'
            $errorCategory1 = 'OperationStopped'
            $targetObject1 = 'Get-AvailableExceptionsList'
            $errorRecord1 = New-Object Management.Automation.ErrorRecord $exception1, $errorID1,
            $errorCategory1, $targetObject1
            # ...report a terminating error to the user
            $PSCmdlet.ThrowTerminatingError($errorRecord1)
        }
        # required function is defined, get "available" exceptions
        $exceptions = Get-AvailableExceptionsList
        $exceptionsList = $exceptions -join "`r`n"
    }
    process {
        # trap for any of the "exceptional" Exception objects that made through the filter
        trap [Microsoft.PowerShell.Commands.NewObjectCommand] {
            $PSCmdlet.ThrowTerminatingError($_)
        }
        # verify input exception is "available". if so...
        if ($exceptions -match "^(System\.)?$Exception$") {
            # ...build and save the new Exception depending on present arguments, if it...
            $_exception = if ($Message -and $InnerException) {
                # ...includes a custom message and an inner exception
                New-Object $Exception $Message, $InnerException
            } elseif ($Message) {
                # ...includes a custom message only
                New-Object $Exception $Message
            } else {
                # ...is just the exception full name
                New-Object $Exception
            }
            # now build and output the new ErrorRecord
            New-Object Management.Automation.ErrorRecord $_exception, $ErrorID,
            $ErrorCategory, $TargetObject
        } else {
            # Exception argument is not "available";
            # warn the user, provide a list of "available" exceptions and...
            Write-Warning "Available exceptions are:`r`n$exceptionsList" 
            $message2 = "Exception '$Exception' is not available."
            $exception2 = New-Object System.InvalidOperationExceptionn $message2
            $errorID2 = 'BadException'
            $errorCategory2 = 'InvalidOperation'
            $targetObject2 = 'Get-AvailableExceptionsList'
            $errorRecord2 = New-Object Management.Automation.ErrorRecord $exception2, $errorID2,
            $errorCategory2, $targetObject2
            # ...report a terminating error to the user
            $PSCmdlet.ThrowTerminatingError($errorRecord2)
        }
    }

    <#  .Synopsis      Creates an custom ErrorRecord that can be used to report a terminating or non-terminating error.  .Description      Creates an custom ErrorRecord that can be used to report a terminating or non-terminating error.  .Parameter Exception      The Exception that will be associated with the ErrorRecord.  .Parameter ErrorID      A scripter-defined identifier of the error.      This identifier must be a non-localized string for a specific error type.  .Parameter ErrorCategory      An ErrorCategory enumeration that defines the category of the error.  .Parameter TargetObject      The object that was being processed when the error took place.  .Parameter Message      Describes the Exception to the user.  .Parameter InnerException      The Exception instance that caused the Exception association with the ErrorRecord.  .Example      # advanced functions for testing function Test-1 {  [CmdletBinding()]  param(  [Parameter(Mandatory = $true, ValueFromPipeline = $true)]  [String]  $Path  )  process {   foreach ($_path in $Path) {    $content = Get-Content -LiteralPath $_path -ErrorAction SilentlyContinue    if (-not $content) {     $errorRecord = New-ErrorRecord InvalidOperationException FileIsEmpty InvalidOperation $_path -Message "File '$_path' is empty."     $PSCmdlet.ThrowTerminatingError($errorRecord)    }   }  } } function Test-2 {  [CmdletBinding()]  param(  [Parameter(Mandatory = $true, ValueFromPipeline = $true)]  [String]  $Path  )  process {   foreach ($_path in $Path) {    $content = Get-Content -LiteralPath $_path -ErrorAction SilentlyContinue    if (-not $content) {     $errorRecord = New-ErrorRecord InvalidOperationException FileIsEmptyAgain InvalidOperation $_path -Message "File '$_path' is empty again." -InnerException $Error[0].Exception     $PSCmdlet.ThrowTerminatingError($errorRecord)    }   }  } } # code to test the custom terminating error reports Clear-Host $null = New-Item -Path .\MyEmptyFile.bak -ItemType File -Force -Verbose Get-ChildItem *.bak | Where-Object {-not $_.PSIsContainer} | Test-1 Write-Host System.Management.Automation.ErrorRecord -ForegroundColor Green $Error[0] | Format-List * -Force Write-Host Exception -ForegroundColor Green $Error[0].Exception | Format-List * -Force Get-ChildItem *.bak | Where-Object {-not $_.PSIsContainer} | Test-2 Write-Host System.Management.Automation.ErrorRecord -ForegroundColor Green $Error[0] | Format-List * -Force Write-Host Exception -ForegroundColor Green $Error[0].Exception | Format-List * -Force Remove-Item .\MyEmptyFile.bak -Verbose      Description      ===========      Both advanced functions throw a custom terminating error when an empty file is being processed.          -Function Test-2's custom ErrorRecord includes an inner exception, which is the ErrorRecord reported by function Test-1.      The test code demonstrates this by creating an empty file in the curent directory -which is deleted at the end- and passing its path to both test functions.      The custom ErrorRecord is reported and execution stops for function Test-1, then the ErrorRecord and its Exception are displayed for quick analysis.      Same process with function Test-2; after analyzing the information, compare both ErrorRecord objects and their corresponding Exception objects.          -In the ErrorRecord note the different Exception, CategoryInfo and FullyQualifiedErrorId data.          -In the Exception note the different Message and InnerException data.  .Example      $errorRecord = New-ErrorRecord System.InvalidOperationException FileIsEmpty InvalidOperation $Path -Message "File '$Path' is empty." $PSCmdlet.ThrowTerminatingError($errorRecord)      Description      ===========      A custom terminating ErrorRecord is stored in variable 'errorRecord' and then it is reported through $PSCmdlet's ThrowTerminatingError method.      The $PSCmdlet object is only available within advanced functions.  .Example      $errorRecord = New-ErrorRecord System.InvalidOperationException FileIsEmpty InvalidOperation $Path -Message "File '$Path' is empty." Write-Error -ErrorRecord $errorRecord      Description      ===========      A custom non-terminating ErrorRecord is stored in variable 'errorRecord' and then it is reported through the Write-Error Cmdlet's ErrorRecord parameter.  .Inputs      System.String  .Outputs      System.Management.Automation.ErrorRecord  .Link      Write-Error      Get-AvailableExceptionsList  .Notes      Name:      New-ErrorRecord      Author:    Robert Robelo      LastEdit:  08/24/2011 12:35  #>
}
#Useful Functions
function Get-CustomRange {
    #Start http://www.vistax64.com/powershell/15525-range-operator.html
    param([string] $first, [string] $second, [string] $type)

    $rangeStart = [int] ($first -as $type)
    $rangeEnd = [int] ($second -as $type)

    $rangeStart..$rangeEnd | ForEach-Object { $_ -as $type }
}
function Compare-ComplexObject {
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
    foreach ($prop in $ComparisonProperties) {
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
        $results += $ComparisonObject | Select-Object -Property Property,CompareResult,ReferenceObjectValue,DifferenceObjectValue #,ComparisonType
    }#foreach
    switch ($show) {
        'All' {$results}#All
        'EqualOnly' {$results | Where-Object {$_.CompareResult}}#EqualOnly
        'DifferentOnly' {$results |Where-Object {-not $_.CompareResult}}#DifferentOnly
    }#switch $show
}#function Compare-ComplexObject
function Start-ComplexJob {
    <#.SYNOPSIS
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
    param(
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

    $StartJobParams = @{}
    $StartJobParams.Name = $name
    #$startjobparams.initializationscript = $initializationscript
    $StartJobParams.ArgumentList = $Arguments
    $StartJobParams.ScriptBlock = $ScriptBlock

    Start-Job @StartJobParams
}#Function Start-ComplexJob
function Get-CSVExportPropertySet {
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
    param(
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
function Start-WindowsSecurity {
#useful in RDP sessions especially on Windows 2012
(New-Object -COM Shell.Application).WindowsSecurity()
}
function New-GUID {[GUID]::NewGuid()}
#Conversion and Testing Functions
function Merge-Hashtables {
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
function Convert-HashtableToObject {
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
Function Convert-ObjectToHashTable {

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
function ConvertTo-String {
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
function Get-GuidFromByteArray {
    param(
        [byte[]]$GuidByteArray
    )
    New-Object -TypeName guid -ArgumentList (,$GuidByteArray)   
}
function Get-ImmutableIDFromGUID {
    param(
        [guid]$Guid
    )
    [System.Convert]::ToBase64String($Guid.ToByteArray())
}
function Get-GUIDFromImmutableID {
    param(
        $ImmutableID
    )
    [GUID][system.convert]::frombase64string($ImmutableID) 
}
function Get-Checksum {
    Param (
        [string]$File=$(throw("You must specify a filename to get the checksum of."))
        ,
        [ValidateSet("sha1","md5")]
        [string]$Algorithm="sha1"
    )
    $fs = new-object System.IO.FileStream $File, "Open"
    $algo = [type]"System.Security.Cryptography.$Algorithm"
    $crypto = $algo::Create()
    $hash = [BitConverter]::ToString($crypto.ComputeHash($fs)).Replace("-", "")
    $fs.Close()
    $hash
}
function Test-Member { 
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
function Test-IP {
#https://gallery.technet.microsoft.com/scriptcenter/A-short-tip-to-validate-IP-4f039260
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -match [IPAddress]$_ })]
        [String]$ip    
    )
    $ip
}
function Test-CurrentPrincipalIsAdmin {
    $currentPrincipal = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
}
Function Test-ForLocalModule {
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
Function Test-ExchangeAlias {
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
#Function to populate the Global TestExchangeAlias Hash Table
function RefreshData {
    $Global:TestExchangeAlias =@{}
    Connect-Exchange -ExchangeOrganization $ExchangeOrganization
    $AllRecipients = Invoke-ExchangeCommand -ExchangeOrganization $exchangeOrganization -cmdlet Get-Recipient -string '-ResultSize Unlimited'
    foreach ($r in $AllRecipients) {
        $alias = $r.alias
        if ($Global:TestExchangeAlias.ContainsKey($alias)) {
            $Global:TestExchangeAlias.$alias += $r.guid.tostring()
        }
        else {
            $Global:TestExchangeAlias.$alias = @()
            $Global:TestExchangeAlias.$alias += $r.guid.tostring()
        }
    }
}
#Populate the Global TestExchangeAlias Hash Table if needed
if (Test-Path -Path variable:\TestExchangeAlias) {
    if ($RefreshAliasData) {
        Write-Log -message "RefreshData to run" -Verbose
        RefreshData
    }
}
else {
    Write-Log -message "RefreshData to run" -Verbose
    RefreshData
}
#Test the Alias
if ($global:TestExchangeAlias.ContainsKey($Alias)) {
    $ConflictingGUIDs = @($global:TestExchangeAlias.$Alias | Where-Object {$_ -notin $ExemptObjectGUIDs})
    if ($ConflictingGUIDs.count -gt 0) {
        if ($ReturnConflicts) {
            Return $ConflictingGUIDs
        }
        else {
            Return $false
        }
    }
    else {
        Return $true
    }
}
else {
    Return $true
}
}
Function Add-ExchangeAliasToTestExchangeAlias 
{
[cmdletbinding()]
param(
    [string]$Alias
    ,
    [guid]$ObjectGUID #should be the AD ObjectGuid
)
    if ($Global:TestExchangeAlias.ContainsKey($alias))
    {
        Write-Log -Message "Alias already exists in the TestExchangeAlias Table" -EntryType Failed
        Return $false
    }
    else
    {
        $Global:TestExchangeAlias.$alias = @()
        $Global:TestExchangeAlias.$alias += $r.guid.tostring()
    }
}
Function Test-ExchangeProxyAddress {
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
#Function to populate the Global TestExchangeProxyAddress Hash Table
function RefreshData {
    $Global:TestExchangeProxyAddress =@{}
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
            if ($Global:TestExchangeProxyAddress.ContainsKey($ProxyAddress)) {
                $Global:TestExchangeProxyAddress.$ProxyAddress += $r.guid.tostring()
            }
            else {
                $Global:TestExchangeProxyAddress.$ProxyAddress = @()
                $Global:TestExchangeProxyAddress.$ProxyAddress += $r.guid.tostring()
            }
        }
    }
    Write-Progress @writeProgressParams -Completed
}
#Populate the Global TestExchangeProxyAddress Hash Table if needed
if (Test-Path -Path variable:\TestExchangeProxyAddress) {
    if ($RefreshProxyAddressData) {
        Write-Log -message "RefreshData to run" -Verbose
        RefreshData
    }
}
else {
    Write-Log -message "RefreshData to run" -Verbose
    RefreshData
}

#Test the Alias
if ($ProxyAddress -notlike "{$proxyaddresstype}:*") {
    $ProxyAddress = "${proxyaddresstype}:$ProxyAddress"
}
if ($global:TestExchangeProxyAddress.ContainsKey($ProxyAddress)) {
    $ConflictingGUIDs = @($global:TestExchangeProxyAddress.$ProxyAddress | Where-Object {$_ -notin $ExemptObjectGUIDs})
    if ($ConflictingGUIDs.count -gt 0) {
        if ($ReturnConflicts) {
            Return $ConflictingGUIDs
        }
        else {
            Return $false
        }
    }
    else {
        Return $true
    }
}
else {
    Return $true
}
}
Function Test-DirectorySynchronization {
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
    #Read-Choice -Message "Waiting for Directory Synchronization for $identity.  Please allow the script to complete." -Choices "OK" -DefaultChoice 0 -Title "Converting Mailbox" | Out-Null
    Connect-Exchange -ExchangeOrganization $ExchangeOrganization
    $Recipient = Invoke-ExchangeCommand -cmdlet Get-Recipient -ExchangeOrganization $ExchangeOrganization -string "-Identity $Identity -ErrorAction SilentlyContinue" -ErrorAction SilentlyContinue
    if ($Recipient.$RecipientAttributeToCheck -eq $RecipientAttributeValue) {
        Write-Log -Message "Checking $identity for value $RecipientAttributeValue in attribute $RecipientAttributeToCheck." -EntryType Succeeded -verbose    
        Return $true
    }
    elseif ($InitiateSynchronization) {
        Write-Log -Message "Initiating Directory Synchronization and Checking/Waiting for a maximum of $MaxSyncWaitMinutes minutes." -EntryType Notification -Verbose
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $minutes = 0
        Start-DirectorySynchronization
        do {
            Start-Sleep -Seconds $SyncCheckInterval
            Connect-Exchange -ExchangeOrganization $ExchangeOrganization
            Write-Log -Message "Checking $identity for value $RecipientAttributeValue in attribute $RecipientAttributeToCheck." -EntryType Attempting -verbose
            $Recipient = Invoke-ExchangeCommand -cmdlet Get-Recipient -ExchangeOrganization $ExchangeOrganization -string "-Identity $Identity -ErrorAction SilentlyContinue" -ErrorAction SilentlyContinue
            #check if we have already waited the DeltaSyncExpectedMinutes.  If so, request a new directory synchronization
            if (($stopwatch.Elapsed.Minutes % $DeltaSyncExpectedMinutes -eq 0) -and ($stopwatch.Elapsed.Minutes -ne $minutes)) {
                $minutes = $stopwatch.Elapsed.Minutes
                Write-Log -Message "$minutes minutes of a maximum $MaxSyncWaitMinutes minutes elapsed. Initiating additional Directory Synchronization attempt." -EntryType Notification -Verbose
                Start-DirectorySynchronization
            }
        }
        until ($Recipient.$RecipientAttributeToCheck -eq $RecipientAttributeValue -or $stopwatch.Elapsed.Minutes -ge $MaxSyncWaitMinutes)
        $stopwatch.Stop()
        if ($stopwatch.Elapsed.Minutes -ge $MaxSyncWaitMinutes) {
            Write-Log -Message "Maximum Synchronization Wait Time Met or Exceeded" -EntryType Notification -ErrorLog -Verbose
        }
        if ($Recipient.$RecipientAttributeToCheck -eq $RecipientAttributeValue) {
            Write-Log -Message "Checking $identity for value $RecipientAttributeValue in attribute $RecipientAttributeToCheck." -EntryType Succeeded -verbose            
            Return $true
        }
        else {Return $false}
    }
    else {Return $false}
}#Process
End {}
}
#Logging and Data Export Functions
function Get-FirstNonNullEmptyStringVariableValueFromScopeHierarchy {
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
Return $value
}
Function Write-Log {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
        ,
        [Parameter(Mandatory=$false,Position=1)]
        [ValidateScript({if (-not [string]::IsNullOrWhiteSpace($Global:LogPath)) {if ([string]::IsNullOrWhiteSpace($_)){$false} else {$true}}})]
        [string]$LogPath
        ,
        [Parameter(Position=2)]
        [switch]$ErrorLog
        ,
        [Parameter(Mandatory=$false,Position=3)]
        [ValidateScript({if (-not [string]::IsNullOrWhiteSpace($Global:ErrorLogPath)) {if ([string]::IsNullOrWhiteSpace($_)){$false} else {$true}}})]
        [string]$ErrorLogPath
        ,
        [Parameter(Mandatory=$false,Position=4)]
        [ValidateSet('Attempting','Succeeded','Failed','Notification')]
        [string]$EntryType
    )
    #Add the Entry Type to the message or add nothing to the message if there is not EntryType specified - preserves legacy functionality and adds new EntryType capability
    if (-not [string]::IsNullOrWhiteSpace($EntryType)) {$Message = $EntryType + ':' + $Message}
    #check the Log Preference to see if the message should be logged or not
    if ($Global:LogPreference -eq $null -or $Global:LogPreference -eq $true) {
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
                if (Test-Path -Path variable:\UnwrittenLogEntries) {
                    $Global:UnwrittenLogEntries += Write-Output -InputObject "$(Get-Date) $Message" 
                }
                else {
                    $Global:UnwrittenLogEntries = @()
                    $Global:UnwrittenLogEntries += Write-Output -InputObject "$(Get-Date) $Message" 
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
                        $Global:UnwrittenErrorLogEntries += Write-Output -InputObject "$(Get-Date) $Message" 
                    }
                    else {
                        $Global:UnwrittenErrorLogEntries = @()
                        $Global:UnwrittenErrorLogEntries += Write-Output -InputObject "$(Get-Date) $Message" 
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
        $ExportFolderPath = $global:ExportDataPath
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
    switch ($DataType) {
        'xml' {
            $ExportFilePath = $exportFolderPath +  $Stamp  + $DataToExportTitle + '.xml'
        }#xml
        'json' {
            $ExportFilePath = $exportFolderPath +  $Stamp  + $DataToExportTitle + '.json'
        }#json
        'csv' {
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
    Write-Log -Message "Attempting: Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath" -Verbose
    Try {
        switch ($DataType) {
            'xml' {
                $DataToExport | Export-Clixml -Depth $Depth -Path $ExportFilePath -ErrorAction Stop -Encoding Unicode
            }#xml
            'json' {
                $DataToExport | ConvertTo-Json -Depth $Depth -ErrorAction Stop  | Out-File -FilePath $ExportFilePath -Encoding unicode -ErrorAction Stop
            }#json
            'csv' {
                if ($append) {$DataToExport | Export-csv -Path $ExportFilePath -NoTypeInformation -ErrorAction Stop -Append}#if
                else {$DataToExport | Export-csv -Path $ExportFilePath -NoTypeInformation -ErrorAction Stop}#else
            }#csv
        }
        if ($ReturnExportFilePath) {Write-Output $ExportFilePath}
        Write-Log -Message "Succeeded: Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath" -Verbose
    }#try
    Catch {
        Write-Log -Message "FAILED: Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath" -Verbose -ErrorLog
        Write-Log -Message $_.tostring() -ErrorLog
    }#catch
}#Export-Data
function Export-Credential {
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
    return $exportCredential
}
Function Update-ProcessStatus {
    param(
        $ProcessStatus
        ,
        [switch]$Failed
    )
    if ($Failed) {
        $ProcessStatus.Outcome = $false
        $Global:DGPProceed = $false
    }
    else {
        $ProcessStatus.Outcome = $true
    }

    $PSO = $ProcessStatus | Convert-HashTableToObject
    $Global:DGPProcessStatus += $PSO

}
Function Remove-AgedFiles {
    param(
        [int]$days
        ,
        [string[]]$directoriesToClean
    )
    $now = Get-Date
    $daysAgo = $now.AddDays(-$days)
    $DirectoriesToClean = $Global:DGPDirectoriesToClean
    foreach ($directory in $DirectoriesToClean) {
        $files = Get-ChildItem -Path $directory
        $files | Where-Object {$_.CreationTime -lt $daysAgo -and $_.LastWriteTime -lt $daysAgo} | Remove-Item 
    }
} 
Function Send-MonitoringMessage {
    [cmdletbinding()]
    param(
        [switch]$Test
        ,
        $Body 
        ,
        $Subject 
        ,
        $Attachments 
        ,
        $ToRecipientList
    )
    if ($test) {$ToRecipientList = $Global:mailnotificationsender}
    $SendMailParams = @{
        Attachments =$Attachments
        From = $Global:MailNotificationSender
        To = $ToRecipientList
        #CC = ''
        SmtpServer = $Global:MailRelayServer
        BodyAsHtml = $true
        Body = $Body
        Subject = $Subject
    }
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
            Write-Host "`r`n"
            return $false;
        }
    }
    Write-Host "`r`n"
    return $true;
}
function Read-InputBoxDialog { # Show input box popup and return the value entered by the user. 
    param(
        [string]$Message
        , [string]$WindowTitle
        , [string]$DefaultText
    )

    Add-Type -AssemblyName Microsoft.VisualBasic     
    $inputbox = [Microsoft.VisualBasic.Interaction]::InputBox($Message, $WindowTitle, $DefaultText)
    $inputbox
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
    if ($AllowMultiSelect) { return $openFileDialog.Filenames } else { return $openFileDialog.Filename } 
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
    [System.Management.Automation.Host.ChoiceDescription[]]$Poss = $Choices | ForEach-Object {            
        New-Object System.Management.Automation.Host.ChoiceDescription "&$($_)", "Sets $_ as an answer."      
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
    return $selectedDirectory
}
##########################################################################################################
#Remote System Connection Functions
##########################################################################################################
Function Import-RequiredModule {
    [cmdletbinding()]
    param
    (
    [parameter(Mandatory=$true)]
    [ValidateSet('ActiveDirectory','MSOnline','AADRM','LyncOnlineConnector')]
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
            Write-Log -message $message -Verbose -EntryType Attempting
            Import-Module -Name $ModuleName -Global -ErrorAction Stop
            Write-Log -message $message -Verbose -EntryType Succeeded
            Return $true
        }#try
        catch 
        {
            Write-Log -message $message -Verbose -ErrorLog -EntryType Failed 
            Write-Log -message $_.tostring() -ErrorLog
            Return $false
        }#catch
    }#if
    else 
    {
        Write-Log -EntryType Notification -Message "$ModuleName Module is already loaded."
        Return $true
    }
}#Import-RequiredModule
Function Connect-Exchange {
    [cmdletbinding(DefaultParameterSetName = 'Organization')]
    Param(
        [parameter(ParameterSetName='OnPremises')]
        [string]$Server
        ,
        [parameter(ParameterSetName='OnPremises')]
        [string]$AuthMethod = $Global:OnPremAuthMethod
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ExchangeOrganizations' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
    }#DynamicParam
    Begin {
        switch ($PSCmdlet.ParameterSetName) {
            'Organization' {
                $Org = $PSBoundParameters[$ParameterName]
                $orgobj = $Global:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object {$_.name -eq $org}
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
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'" -Verbose
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
                    Write-Log -Message "Attempting: Creation of Remote Session $SessionName to Exchange System $orgName" -Verbose
                    $sessionobj = New-PSSession @sessionParams -ErrorAction Stop
                    Write-Log -Message "Succeeded: Creation of Remote Session to Exchange System $orgName" -Verbose
                    Write-Log -Message "Attempting: Import Exchange Session $SessionName and Module" -Verbose 
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
                    Write-Log -Message "Succeeded: Import Exchange Session $SessionName and Module" -Verbose 
                    if ($orgtype -eq 'OnPremises') {
                        if ($PreferredDomainControllers.Count -ge 1) {
                            $splat=@{ViewEntireForest=$true;SetPreferredDomainControllers=$PreferredDomainControllers;ErrorAction='Stop'}
                        }#if
                        else {
                            $splat=@{ViewEntireForest=$true;ErrorAction='Stop'}
                        }#else    
                        Invoke-ExchangeCommand -cmdlet Set-ADServerSettings -ExchangeOrganization $orgName -splat $splat
                    }#if
                    Return $true
                    Write-Log -Message "Succeeded: Connect to Exchange System $orgName" -Verbose
                }#try
                catch {
                    Write-Log -Message "Failed: Connect to Exchange System $orgName" -Verbose -ErrorLog
                    Write-Log -Message $_.tostring() -ErrorLog
                    Return $False
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
        [string]$AuthMethod = $Global:OnPremAuthMethod
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SkypeOrganizations' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
    }#DynamicParam
    Begin {
        switch ($PSCmdlet.ParameterSetName) {
            'Organization' {
                $Org = $PSBoundParameters[$ParameterName]
                $orgobj = $Global:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'SkypeOrganizations' | Where-Object {$_.name -eq $org}
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
        try {
            Import-RequiredModule -ModuleName LyncOnlineConnector -ErrorAction Stop
            $existingsession = Get-PSSession -Name $SessionName -ErrorAction Stop
            Write-Log -Message "Existing session for $SessionName exists"
            Write-Log -Message "Checking $SessionName State" 
            if ($existingsession.State -ne 'Opened') {
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'" -Verbose
                Remove-PSSession -Name $SessionName 
                $UseExistingSession = $False
            }#if
            else {
                #Write-Log -Message "$SessionName State is 'Opened'. Using existing Session." 
                switch ($orgtype){
                    'OnPremises'{
                        try {
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-SkypeCommand -cmdlet 'Get-CsTenantFederationConfiguration' -SkypeOrganization $orgName -string '-erroraction Stop' -WarningAction SilentlyContinue
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
                            Invoke-SkypeCommand -cmdlet 'Get-CsTenantFederationConfiguration' -SkypeOrganization $orgName -string '-erroraction Stop'
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
                    Write-Log -Message $message -Verbose -entryType Attempting
                    $sessionobj = New-cSonlineSession @sessionParams -ErrorAction Stop
                    Write-Log -Message $message -Verbose -EntryType Succeeded
                    Write-Log -Message "Attempting: Import Skype Session $SessionName and Module" -Verbose 
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
                    Write-Log -Message "Succeeded: Import Skype Session $SessionName and Module" -Verbose 
                    Return $true
                    Write-Log -Message "Succeeded: Connect to Skype System $orgName" -Verbose
                }#try
                catch {
                    Write-Log -Message "Failed: Connect to Skype System $orgName" -Verbose -ErrorLog
                    Write-Log -Message $_.tostring() -ErrorLog
                    Return $False
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AADSyncServers' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
    }#DynamicParam
    #Connect to Directory Synchronization
    #Server has to have been enabled for PS Remoting (enable-psremoting)
    #Credential has to be a member of ADSyncAdmins on the AADSync Server
    begin{
        switch ($PSCmdlet.ParameterSetName) {
            'Profile' {
                $SelectedProfile = $PSBoundParameters[$ParameterName]
                $Profile = $Global:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'AADSyncServers' | Where-Object {$_.name -eq $selectedProfile}
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
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'" -Verbose
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
            Write-Log -Verbose -Message "Connecting to Directory Synchronization Server $server as User $($credential.username)."
            Try {
                $Session = New-PsSession -ComputerName $Server -Verbose -Credential $Credential -Name $SessionName -ErrorAction Stop
                Write-Log -Message "Attempting: Import AADSync Session $SessionName and Module" -Verbose 
                if ($usePrefix) {
                    Invoke-Command -Session $Session -ScriptBlock {Import-Module ADSync -DisableNameChecking} -ErrorAction Stop
                    Import-Module (Import-PSSession -Session $Session -Module ADSync -DisableNameChecking -ErrorAction Stop -Prefix $CommandPrefix) -Global -DisableNameChecking -ErrorAction Stop -Prefix $CommandPrefix
                }
                else {
                    Invoke-Command -Session $Session -ScriptBlock {Import-Module ADSync -DisableNameChecking} -ErrorAction Stop
                    Import-Module (Import-PSSession -Session $Session -Module ADSync -DisableNameChecking -ErrorAction Stop) -Global -DisableNameChecking -ErrorAction Stop 
                }
                Write-Log -Message "Succeeded: Import AADSync Session $SessionName and Module" -Verbose 
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
                Return $true
            }#Try
            Catch {
                Write-Log -Verbose -Message "ERROR: Connection to $server failed." -ErrorLog
                Write-Log -Verbose -Message $_.tostring() -ErrorLog
                Return $false
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
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
                $ADIobj = $Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Where-Object {$_.name -eq $ADI}
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
                Write-Log -Message "Attempting: Connect PS Drive $name`: to $Description" -Verbose
                if (Import-RequiredModule -ModuleName ActiveDirectory -ErrorAction Stop) {
                    New-PSDrive @NewPSDriveParams | Out-Null
                }#if
                Write-Log -Message "Succeeded: Connect PS Drive $name`: to $Description" -Verbose
                Return $true
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
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
                $Credential = $Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
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
                Import-RequiredModule -ModuleName MSOnline -ErrorAction Stop
                Write-Log -Message "Attempting: Connect to Windows Azure AD Administration with User $($Credential.username)." -Verbose
                Connect-MsolService -Credential $Credential -ErrorAction Stop
                Write-Log -Message "Succeeded: Connect to Windows Azure AD Administration with User $($Credential.username)." -Verbose
                Return $true
            }
            Catch 
            {
                Write-Log -Message "FAILED: Connect to Windows Azure AD Administration with User $($Credential.username)." -Verbose -ErrorLog
                Write-Log -Message $_.tostring()
                Return $false 
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
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
                $Credential = $Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.Name -eq $Identity} | Select-Object -ExpandProperty Credential
            }#tenant
            'Manual' {
            }#manual
        }#switch
    }#begin
    process 
    {
        try 
        {
            Import-RequiredModule -ModuleName AADRM -ErrorAction Stop
            Write-Log -Message "Attempting: Connect to Azure AD RMS Administration with User $($Credential.username)." -Verbose
            Connect-AadrmService -Credential $Credential -errorAction Stop | Out-Null
            Write-Log -Message "Succeeded: Connect to Azure AD RMS Administration with User $($Credential.username)." -Verbose
            Return $true
        }
        catch 
        {
            Write-Log -Message "FAILED: Connect to Azure AD RMS Administration with User $($Credential.username)." -Verbose -ErrorLog
            Write-Log -Message $_.tostring() -ErrorLog
            Return $false 
        }
    }#process
}#function Connect-AADRM 
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'PowerShellSystems' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
    }#DynamicParam
    #Connect to Directory Synchronization
    #Server has to have been enabled for PS Remoting (enable-psremoting)
    #Credential has to be a member of ADSyncAdmins on the AADSync Server
    begin{
        switch ($PSCmdlet.ParameterSetName) {
            'Profile' {
                $SelectedProfile = $PSBoundParameters[$ParameterName]
                $Profile = $Global:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'PowerShellSystems' | Where-Object {$_.name -eq $selectedProfile}
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
                Write-Log -Message "Existing session for $SessionName exists but is not in state 'Opened'" -Verbose -EntryType Notification
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
                Write-Log -Verbose -Message $message -EntryType Attempting
                $Session = New-PsSession -ComputerName $System -Verbose -Credential $Credential -Name $SessionName -ErrorAction Stop
                Write-Log -Verbose -Message $message -EntryType Succeeded
                Update-SessionManagementGroups -ManagementGroups $ManagementGroups -Session $SessionName -ErrorAction Stop
                Return $true
            }#Try
            Catch {
                Write-Log -Verbose -Message $message -ErrorLog -EntryType Failed
                Write-Log -Verbose -Message $_.tostring() -ErrorLog
                Return $false
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
    foreach ($MG in $ManagementGroups) {
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
            }
            else 
            {
                $NewSession = Get-PSSession -Name $SessionName
                $newvalue = @(Get-PSSession -Name $existingSessionNames)
                $newvalue += $NewSession
                Set-Variable -Name $SessionGroup -Value $newvalue -Scope Global
            }
        }
        else 
        {
        #since the session group does not exist, create it and add the session to it
            New-Variable -Name $SessionGroup -Value @($(Get-PSSession -Name $SessionName)) -Scope Global
        }#else
    }#foreach
}#function Update-SessionManagementGroups
Function Connect-RemoteSystems {
    [CmdletBinding()]
    param ()
    $ProcessStatus = @{
        Command = $MyInvocation.MyCommand.Name
        BoundParameters = $MyInvocation.BoundParameters
        Outcome = $null
    }
    try {
        # Connect To Exchange Systems
        foreach ($sys in ($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                Write-Log -Message "Attempting: Connect to $sys-Exchange." -Verbose
                Connect-Exchange -ExchangeOrganization $sys -ErrorAction Stop
                Write-Log -Message "Succeeded: Connect to $sys-Exchange." -Verbose
            }#try
            catch {
                Write-Log -Message "Failed: Connect to $sys-Exchange." -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
            }#catch
        }
        # Connect to Azure AD Sync
        foreach ($sys in ($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'AADSyncServers' | Where-Object AutoConnect -EQ $true | Select-Object -ExpandProperty Name)) 
        {
            $ConnectAADSyncParams = @{AADSyncServer = $sys; ErrorAction = 'Stop'}
            if (($Global:AADSyncServers | Where-Object AutoConnect -EQ $true).count -gt 1) {$ConnectAADSyncParams.UsePrefix = $true}
            try {
                Write-Log -Message "Attempting: Connect to $sys-AADSync." -Verbose
                Connect-AADSync @ConnectAADSyncParams
                Write-Log -Message "Succeeded: Connect to $sys-AADSync." -Verbose
            }#try
            catch {
                Write-Log -Message "Failed: Connect to $sys-AADSync." -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
            }#catch    
        }
        # Connect to Active Directory Forests
        if (Import-RequiredModule -ModuleName ActiveDirectory -ErrorAction Stop) 
        {
            foreach ($sys in ($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Where-Object AutoConnect -EQ $true | Select-Object -ExpandProperty Name)) {
                try {
                    Write-Log -Message "Attempting: Connect to AD Instance $sys." -Verbose
                    Connect-ADInstance -ActiveDirectoryInstance $sys -ErrorAction Stop
                    Write-Log -Message "Succeeded: Connect to AD Instance $sys." -Verbose
                }
                catch {
                    Write-Log -Message "FAILED: Connect to AD Instance $sys." -Verbose -ErrorLog
                    Write-Log -Message $_.tostring() -ErrorLog
                }
            }
        }
        # Connect to default Azure AD
        $DefaultTenant = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'Office365Tenants' | Where-Object -FilterScript {$_.autoconnect -eq $true} | Select-Object -First 1)
        if ($DefaultTenant.Count -eq 1) 
        {
            Connect-AzureAD -Tenant $DefaultTenant.Name -ErrorAction Stop
            Connect-AADRM -Tenant $DefaultTenant.Name -ErrorAction Stop
        }
        # Connect To PowerShell Systems
        foreach ($sys in ($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'PowershellSystems' | Where-Object AutoConnect -eq $true | Select-Object -ExpandProperty Name)) 
        {
            try {
                $message = "Connect to PowerShell on System $sys"
                Write-Log -Message $message -Verbose -EntryType Attempting
                Connect-PowerShellSystem -PowerShellSystem $sys -ErrorAction Stop
                Write-Log -Message $message -Verbose -EntryType Succeeded
            }#try
            catch {
                Write-Log -Message $message -Verbose -ErrorLog -EntryType Failed
                Write-Log -Message $_.tostring() -ErrorLog
            }#catch
        }
        $ProcessStatus.Outcome = $true
        $PSO = $ProcessStatus | Convert-HashTableToObject
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ExchangeOrganizations' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
    }#DynamicParam

    begin {
        # Bind the dynamic parameter to a friendly variable
        if ([string]::IsNullOrWhiteSpace($CommandPrefix)) {
            $Org = $PsBoundParameters[$ParameterName]
            if (-not [string]::IsNullOrWhiteSpace($Org)) {
                $orgobj = $Global:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'ExchangeOrganizations' | Where-Object {$_.name -eq $org}
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'SkypeOrganizations' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
    }#DynamicParam

    begin {
        # Bind the dynamic parameter to a friendly variable
        if ([string]::IsNullOrWhiteSpace($CommandPrefix)) {
            $Org = $PsBoundParameters[$ParameterName]
            if (-not [string]::IsNullOrWhiteSpace($Org)) {
                $orgobj = $Global:CurrentOrgAdminProfileSystems |  Where-Object SystemType -eq 'SkypeOrganizations' | Where-Object {$_.name -eq $org}
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
[ValidateSet('Set','Get')]
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
        [validateset('SAMAccountName','UserPrincipalName','ProxyAddress','Mail','mailNickname','employeeNumber','extensionattribute5','extensionattribute11','extensionattribute13','DistinguishedName','CanonicalName','ObjectGUID','mS-DS-ConsistencyGuid','SID','GivenNameSurname')]
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
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
            $ErrorRecord = New-ErrorRecord -Exception "AD Drive Not Available" -ErrorId ADDriveNotAvailable -ErrorCategory NotSpecified -TargetObject $ADInstance -Message "Required AD Drive not available"
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
            $Global:LookupADUserNotFound = @()
            $Global:LookupADUserAmbiguous = @()
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
                }#switch
                Write-Log -Message "Succeeded: Get-ADUser with identifier $ID for Attribute $IdentityType" 
            }#try
            catch {
                Write-Log -Message "FAILED: Get-ADUser with identifier $ID for Attribute $IdentityType" -Verbose -ErrorLog
                Write-Log -Message $_.tostring() -ErrorLog
                if ($ReportExceptions) {$Global:LookupADUserNotFound += $ID}
            }
            switch ($aduser.Count) {
                1 {
                    $TrimmedADUser = $ADUser | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                    Return $TrimmedADUser
                }#1
                0 {
                    if ($ReportExceptions) {$Global:LookupADUserNotFound += $ID}
                }#0
                Default {
                    if ($AmbiguousAllowed) {
                        $TrimmedADUser = $ADUser | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                        Return $TrimmedADUser    
                    }
                    else {
                        if ($ReportExceptions) {$Global:LookupADUserAmbiguous += $ID}
                    }
                }#Default
            }#switch
        }#foreach
    }#Process

    end {
        if ($ReportExceptions) {
            if ($Global:LookupADUserNotFound.count -ge 1) {
                Write-Log -Message 'Review logs or variable $Global:LookupADUserNotFound for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Global:LookupADUserNotFound -join "`n`t")" -ErrorLog
            }#if
            if ($Global:LookupADUserAmbiguous.count -ge 1) {
                Write-Log -Message 'Review logs or variable $Global:LookupADUserAmbiguous for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Global:LookupADUserAmbiguous -join "`n`t")" -ErrorLog
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
        $ValidateSet = @($Global:CurrentOrgAdminProfileSystems | Where-Object SystemType -eq 'ActiveDirectoryInstances' | Select-Object -ExpandProperty Name)
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
        return $RuntimeParameterDictionary
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
            Write-Log -Message "Succeeded: Set Location to AD Drive $("$ADInstance`:")" -Verbose -ErrorLog
            Write-Log -Message $_.tostring() -ErrorLog
            $ErrorRecord = New-ErrorRecord -Exception "AD Drive Not Available" -ErrorId ADDriveNotAvailable -ErrorCategory NotSpecified -TargetObject $ADInstance -Message "Required AD Drive not available"
            $PSCmdlet.ThrowTerminatingError($ErrorRecord)
        }
        $GetADObjectParams = @{ErrorAction = 'Stop'}
        if ($properties.count -ge 1) {
            #Write-Log -Message "Using Property List: $($properties -join ",") with Get-ADObject"
            $GetADObjectParams.Properties = $Properties
        }
        if ($ReportExceptions) {
            $Global:LookupADContactNotFound = @()
            $Global:LookupADContactAmbiguous = @()
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
                if ($ReportExceptions) {$Global:LookupADContactNotFound += $ID}
            }
            switch ($ADContact.Count) {
                1 {
                    $TrimmedADObject = $ADContact | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                    Return $TrimmedADObject
                }#1
                0 {
                    if ($ReportExceptions) {$Global:LookupADContactNotFound += $ID}
                }#0
                Default {
                    if ($AmbiguousAllowed) {
                        $TrimmedADObject = $ADContact | Select-Object -property * -ExcludeProperty Item, PropertyNames, *Properties, PropertyCount
                        Return $TrimmedADObject    
                    }
                    else {
                        if ($ReportExceptions) {$Global:LookupADContactAmbiguous += $ID}
                    }
                }#Default
            }#switch
        }#foreach
    }#Process

    end {
        if ($ReportExceptions) {
            if ($Global:LookupADContactNotFound.count -ge 1) {
                Write-Log -Message 'Review logs or variable $Global:LookupADObjectNotFound for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Global:LookupADContactNotFound -join "`n`t")" -ErrorLog
            }#if
            if ($Global:LookupADContactAmbiguous.count -ge 1) {
                Write-Log -Message 'Review logs or variable $Global:LookupADObjectAmbiguous for exceptions' -Verbose -ErrorLog
                Write-Log -Message "$($Global:LookupADContactAmbiguous -join "`n`t")" -ErrorLog
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
    Return $domain
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
            Return $result
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
##########################################################################################################
#Profile and Environment Initialization Functions
##########################################################################################################
Function Export-OrgProfile {
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
    $path = "$($Global:OneShellModuleFolderPath)\$name.json"
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
        Return $true
    }#try
    catch {
        $_
        throw "FAILED: Could not write Org Profile data to $path"
    }#catch

}#Function Export-OrgProfile
Function Get-OrgProfile {
    [cmdletbinding()]
    param(
        [parameter()]
        [validateset('load','list')]
        [string[]]$operation
        ,
        [parameter(ParameterSetName='')]
        $Location = $Global:OneShellModuleFolderPath 
        ,
        $OrgProfileType = 'OneShellOrgProfile'
    )
    begin {

    }
    process {
        if (Test-Path $Location) {
            $JSONProfiles = @(Get-ChildItem -Path $location -Filter *.json)
            if ($JSONProfiles.Count -ge 1) {
                $PotentialOrgProfiles = @(foreach ($file in $JSONProfiles) {Get-Content -Path $file.fullname -Raw | ConvertFrom-Json})
                $OrgProfiles = @($PotentialOrgProfiles | Where-Object {$_.ProfileType -eq $OrgProfileType})
                if ($OrgProfiles.Count -ge 1) {
                    switch ($operation) {
                        'Load' {
                            $Global:OrgProfiles = $OrgProfiles.Clone()
                            if ($operation -notcontains 'List') {Return $True}
                        }
                        'List' {
                            $OrgProfiles | Select-Object -Property @{n='Identity';e={$_.Identity}},@{n='Name';e={$_.General.Name}},@{n='Default';e={$_.General.Default}}
                        }
                    }

                }
                else {
                    throw "No valid Organization Profiles Were Found in $location"
                }
            }
        }
        else {
            throw "No valid Organization Profiles were found. $location is invalid."
        }
    }
}
Function Use-OrgProfile {
    param(
        [parameter(ParameterSetName = 'Object')]
        $profile 
        ,
        [parameter(ParameterSetName = 'Identity')]
        $Identity
    )
    begin {
        switch ($PSCmdlet.ParameterSetName) {
            'Object' {}
            'Identity' {
                $profile = $global:OrgProfiles | Where-Object -FilterScript {$_.Identity -eq $Identity}
            }
        }
    }#begin
    process {
        if ($global:CurrentOrgProfile -and $profile.Identity -ne $global:CurrentOrgProfile.Identity) {
            $global:CurrentOrgProfile = $profile
            Write-Log -message "Org Profile has been changed to $($global:CurrentOrgProfile.Identity).  Remove PSSessions and select an Admin Profile to load." -EntryType Notification -Verbose
        }
        else {
            $global:CurrentOrgProfile = $profile
            Write-Log -Message "Org Profile has been set to $($global:CurrentOrgProfile.Identity), $($global:CurrentOrgProfile.general.name)." -EntryType Notification -Verbose
        }
        $Global:CurrentOrgAdminProfileSystems = @()
        Return $true
    }#process
}
Function Select-OrgProfile {
    param(
        [parameter(Mandatory=$true)]
        [validateset('Use','Edit')]
        $purpose
    )
    $MenuDefinition = [pscustomobject]@{
        GUID = [guid]::NewGuid()
        Title = "Select Organization Profile to $purpose"
        Initialization = ''
        ParentGUID = $null
        Choices = @()
    }
    foreach ($profile in $Global:OrgProfiles) {
        $MenuDefinition.choices += [pscustomobject]@{
            choice=$profile.general.Name
            command=switch ($purpose) {
                'Edit' {
                    "Set-OrgProfile -Identity $($Profile.Identity)"
                }
                'Use' {
                    "Use-OrgProfile -Identity $($profile.identity)"
                }
            }#switch
            exit = $true
        }
    }
    Invoke-Menu -menudefinition $MenuDefinition 
}
function Get-OrgProfileSystem {
    param(
        $OrganizationIdentity
    )
    $targetOrgProfile = @($Global:OrgProfiles | Where-Object -FilterScript {$_.Identity -eq $OrganizationIdentity})
    switch ($targetOrgProfile.Count) {
        1 {}
        0 {throw "No matching Organization Profile was found for identity $OrganizationIdentity"}
        Default {throw "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"}
    }

    $systemtypes = $targetOrgProfile | Select-Object -Property * -ExcludeProperty Identity,General,ProfileType | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
    $systems = @()

    foreach ($systemtype in $systemtypes) {
        foreach ($sys in $targetorgprofile.$systemtype) {
            $system = $sys.psobject.copy()
            $system | Add-Member -MemberType NoteProperty -Name SystemType -Value $systemtype
            $systems += $system
        }
    }
    $systems
}
#developing
Function Use-AdminUserProfile {
    param(
        [parameter(ParameterSetName = 'Object')]
        $profile 
        ,
        [parameter(ParameterSetName = 'Identity')]
        $Identity
    )
    begin {
        switch ($PSCmdlet.ParameterSetName) {
            'Object' {}
            'Identity' {
                $profile = $Global:AdminUserProfiles | Where-Object -FilterScript {$_.Identity -eq $Identity}
            }
        }
    }#begin
    process{
        #check if there is already a "Current" admin profile and if it is different from the one being used/applied by this run of the function
        #need to add some clean-up functionality for sessions when there is a change, or make it always optional to reset all sessions with this function
        if ($global:CurrentAdminUserProfile -and $profile.Identity -ne $global:CurrentAdminUserProfile.Identity) 
        {
            $global:CurrentAdminUserProfile = $profile
            Write-Warning "Admin User Profile has been changed to $($global:CurrentAdminUserProfile.Identity). Remove PSSessions and then re-establish connectivity using Connect-RemoteSystems."
        }
        else {
            $global:CurrentAdminUserProfile = $profile
            Write-Verbose "Admin User Profile has been set to $($global:CurrentAdminUserProfile.Identity), $($global:CurrentAdminUserProfile.general.name)."
        }
        #Retrieve the systems from the current org profile
        $systems = Get-OrgProfileSystem -OrganizationIdentity $global:CurrentAdminUserProfile.general.OrganizationIdentity
        #Build the autoconnect property and the mapped credentials for each system and store in the CurrentOrgAdminProfileSystems Global variable
        $Global:CurrentOrgAdminProfileSystems = 
        @(
            foreach ($sys in $systems) {
                $sys | Add-Member -MemberType NoteProperty -Name Autoconnect -Value $null
                [boolean]$autoconnect = $global:CurrentAdminUserProfile.systems | Where-Object -FilterScript {$sys.Identity -eq $_.Identity} | foreach-Object {$_.autoconnect}
                $sys.AutoConnect = $autoconnect
                if (! $sys.Autoconnect) {$sys.Autoconnect = $false}
                $sysPreCredential = $global:CurrentAdminUserProfile.Credentials | Where-Object -FilterScript {$_.systems -contains $sys.Identity} 
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
        $Global:OneShellAdminUserProfileFolder = $global:CurrentAdminUserProfile.general.ProfileFolder
        $Global:LogFolderPath = "$Global:OneShellAdminUserProfileFolder\Logs\"
        $Global:ReferenceFolder = "$Global:OneShellAdminUserProfileFolder\Reference\"
        $Global:LogPath = "$Global:OneShellAdminUserProfileFolder\Logs\$Global:Stamp" + '-AdminOperations.log'
        $Global:ErrorLogPath = "$Global:OneShellAdminUserProfileFolder\Logs\$Global:Stamp" + '-AdminOperations-Errors.log'
        $Global:ExportDataPath = "$Global:OneShellAdminUserProfileFolder\Export\"
        Return $true
    }#process
}
Function Get-AdminUserProfile {
    [cmdletbinding()]
    param(
        [parameter()]
        [validateset('load','list')]
        [string[]]$operation
        ,
        [parameter()]
        $Location = "$env:UserProfile\OneShell\"
        ,
        $ProfileType = 'OneShellAdminUserProfile'
    )
    begin {

    }
    Process {
        if (Test-Path $Location) {
            $JSONProfiles = @(Get-ChildItem -Path $location -Filter *.JSON)
            if ($JSONProfiles.Count -ge 1) {
                $PotentialAdminUserProfiles = foreach ($file in $JSONProfiles) {Get-Content -Path $file.fullname -Raw | ConvertFrom-Json}
                $AdminUserProfiles = @($PotentialAdminUserProfiles | Where-Object {$_.ProfileType -eq $ProfileType -and $_.general.organizationidentity -eq $CurrentOrgProfile.Identity})
                if ($AdminUserProfiles.Count -ge 1) {
                    switch ($operation) {
                        'Load' {
                            $Global:AdminUserProfiles = $AdminUserProfiles #.Clone()
                            if ($operation -notcontains 'List') {Return $True}
                        }
                        'List' {
                            $AdminUserProfiles | Select-Object -Property @{n='Identity';e={$_.Identity}},@{n='Name';e={$_.General.Name}},@{n='Default';e={$_.General.Default}}
                        }
                    }
                }
                else {
                    Write-Warning "No valid Admin User Profiles Were Found in $location for $env:USERNAME for Organization Profile $($currentOrgProfile.Identity) for $($currentOrgProfile.General.Name)"
                    Return $false
                }
            }
            else {
                Write-Error "No valid Admin User Profiles Were Found in $location for $env:USERNAME for Organization Profile $($currentOrgProfile.Identity) for $($currentOrgProfile.General.Name)"
                Return $false
            }
        }
        else {
            Write-Error "No valid Admin User Profiles were found. $location is invalid."
            Return $false
        }
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
    foreach ($profile in $Global:AdminUserProfiles) {
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
function New-AdminUserProfile {
    param(
        $OrganizationIdentity
        ,
        [string]$name
    )
    $targetOrgProfile = @($Global:OrgProfiles | Where-Object -FilterScript {$_.Identity -eq $OrganizationIdentity})
    switch ($targetOrgProfile.Count) {
        1 {}
        0 {throw "No matching Organization Profile was found for identity $OrganizationIdentity"}
        Default {throw "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"}
    }
    $newAdminUserProfile = [ordered]@{
        Identity = [guid]::NewGuid()
        ProfileType = 'OneShellAdminUserProfile'
        General = [ordered]@{
            Name = if ($name) {"$name-" + $targetOrgProfile.general.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME} else {$targetOrgProfile.general.name + '-' + $env:USERNAME + '-' + $env:COMPUTERNAME}
            Host = $env:COMPUTERNAME
            OrganizationIdentity = $targetOrgProfile.identity
            ProfileFolder = $(Read-FolderBrowserDialog -Message 'Select a location for your profile folder. A folder named "OneShell" will be created here if one does not already exist.  Additionally, subfolders for Logs, Input, and Export files will be created under the OneShell folder.' -InitialDirectory $env:UserProfile ) + '\OneShell'
            Default = if ((Read-Choice -Message "Should this be the default profile for Organization Profile $($targetorgprofile.general.name)?" -Choices 'Yes','No' -DefaultChoice 1 -Title 'Default Profile?') -eq 0) {$true} else {$false}
        }
        Systems = @()
        Credentials = @()
    }
    #Get Org Profile Defined Systems
    $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
    #Get User's Credentials
    $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems)
    #Prepare Stored Credentials to associate with one or more systems
    #$exportcredentials | foreach {$_.systems=@()}

    foreach ($sys in $systems) {
        $label = $sys | Select-Object @{n='name';e={$_.SystemType + ': ' + $_.Name}} | Select-Object -ExpandProperty Name
        $prompt = "Do you want to Auto Connect to this system with this admin profile: `n`n$label"
        $autoConnectChoice = Read-Choice -Message $prompt -Choices 'Yes','No' -DefaultChoice 0 -Title 'Auto Connect?'
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
    $newAdminUserProfile.Credentials = @($exportcredentials)
    try {
        if (Add-AdminUserProfileFolders -AdminUserProfile $newAdminUserProfile -location $newAdminUserProfile.General.profileFolder -ErrorAction Stop) {
            if (Export-AdminUserProfile -profile $newAdminUserProfile -ErrorAction Stop) {
                if (Get-AdminUserProfile -operation load -ErrorAction Stop) {
                    Write-Log -Message "New Admin Profile with Name: $($newAdminUserProfile.General.Name) and Identity: $($newAdminUserProfile.Identity) was successfully configured, exported, and imported." -Verbose -ErrorAction SilentlyContinue
                    Write-Log -Message "To initialize the new profile for immediate use, run 'Use-AdminUserProfile -Identity $($newAdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                }
            }
        }
    
    }
    catch {
        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($newAdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
    }
    Return $newAdminUserProfile
}
function Set-AdminUserProfile {
    [cmdletbinding()]
    param(
        [parameter(ParameterSetName = 'Object')]
        $profile 
        ,
        [parameter(ParameterSetName = 'Identity')]
        $Identity
    )
    switch ($PSCmdlet.ParameterSetName) {
        'Object' {$editAdminUserProfile = $profile}
        'Identity' {$editAdminUserProfile = $($Global:AdminUserProfiles | Where-Object Identity -eq $Identity)}
    }
    $OrganizationIdentity = $editAdminUserProfile.General.OrganizationIdentity
    $targetOrgProfile = @($Global:OrgProfiles | Where-Object -FilterScript {$_.Identity -eq $OrganizationIdentity})
    switch ($targetOrgProfile.Count) {
        1 {}
        0 {throw "No matching Organization Profile was found for identity $OrganizationIdentity"}
        Default {throw "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"}
    }
    #Get Org Profile Defined Systems
    $systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)
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
    #Get User's Credentials
    $exportcredentials = @(Set-AdminUserProfileCredentials -systems $systems -credentials $editAdminUserProfile.Credentials -edit)
    #Prepare Stored Credentials to associate with one or more systems
    $exportcredentials | foreach {$_.systems=@()}
    #Prepare Edited System Entries variable:
    $EditedSystemEntries = @()
    foreach ($sys in $systems) {
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
        if (Add-AdminUserProfileFolders -AdminUserProfile $editAdminUserProfile -ErrorAction Stop) {
            if (Export-AdminUserProfile -profile $editAdminUserProfile -ErrorAction Stop) {
                if (Get-AdminUserProfile -operation load -ErrorAction Stop) {
                    Write-Log -Message "Edited Admin Profile with Name: $($editAdminUserProfile.General.Name) and Identity: $($editAdminUserProfile.Identity) was successfully configured, exported, and loaded." -Verbose -ErrorAction SilentlyContinue
                    Write-Log -Message "To initialize the edited profile for immediate use, run 'Use-AdminUserProfile -Identity $($editAdminUserProfile.Identity)'" -Verbose -ErrorAction SilentlyContinue
                }
            }
        }
    
    }
    catch {
        Write-Log -Message "FAILED: An Admin User Profile operation failed for $($editAdminUserProfile.Identity).  Review the Error Logs for Details." -ErrorLog -Verbose -ErrorAction SilentlyContinue
        Write-Log -Message $_.tostring() -ErrorLog -Verbose -ErrorAction SilentlyContinue
    }
    ##>
    Return $editAdminUserProfile
}
function Add-AdminUserProfileFolders {
    [cmdletbinding()]
    param(
        $AdminUserProfile
        ,
        $location = $env:USERPROFILE + '\OneShell'
    )
    $AdminUserJSONProfileFolder = $location
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
    Return $true
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
    #not sure that the following line would work since $OrganizationIdentity is not defined in this function
    #if (! $systems) {$systems = @(Get-OrgProfileSystem -OrganizationIdentity $OrganizationIdentity)}
    $labels = $systems | Select-Object @{n='name';e={$_.SystemType + ': ' + $_.Name}}     
    do {
        $prompt = @"
You may associate a credential with each of the following systems for AutoConnect: 

$($labels.name -join "`n")

You have created the following credentials so far: 
$($editableCredentials.UserName -join "`n") 

In the next step, you can modify the association of these credentials with the systems above. 

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
    Return $exportcredentials
}
Function Export-AdminUserProfile {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        $profile
        ,
        $path = "$($Env:USERPROFILE)\OneShell\"
    )
    $GUID = if ($profile.Identity -is 'GUID') {$name = $($profile.Identity.Guid) + '.JSON'} else {$name = $($profile.Identity) + '.JSON'}

    $fullpath = $path + $name
    $params =@{
        InputObject = $profile
        ErrorAction = 'Stop'
        Depth = 4
    }
    try {
        ConvertTo-Json @params | Out-File -FilePath $fullpath -Encoding ascii -ErrorAction Stop -Force 
        Return $true
    }#try
    catch {
        $_
        throw "FAILED: Could not write Admin User Profile data to $path"
    }#catch

}
Function Initialize-AdminEnvironment {
    [cmdletbinding(defaultparametersetname = 'AutoConnect')]
    param(
        [parameter(ParameterSetName = 'AutoConnect')]
        [switch]$AutoConnect
        ,
        [parameter(ParameterSetName = 'ShowMenu')]
        [switch]$ShowMenu
    )
    if (Get-OrgProfile -operation load) {
        $DefaultOrgProfile = @($global:OrgProfiles | Where-Object {$_.General.Default -eq $true})
        switch ($DefaultOrgProfile.Count) {
            {$_ -eq 1} {
                $message = @"
Loading Default Org Profile:  
Name: $($DefaultOrgProfile.General.Name)
Identity: $($DefaultOrgProfile.Identity) 
"@
                Write-Log -Message $message -Verbose -ErrorAction SilentlyContinue
                [boolean]$OrgProfileLoaded = Use-OrgProfile -Profile $DefaultOrgProfile
            }
            {$_ -gt 1} {
                Write-Error "FAILED: Multiple Org Profiles Are Set as Default: $($DefaultOrgProfile.Identity -join ',')"
            }
            {$_ -lt 1} {
                Write-Error 'FAILED: No Org Profiles Are Set as Default'
            }
        }
    }
    if ($OrgProfileLoaded) {
        if (Get-AdminUserProfile -operation load) {
            $DefaultAdminUserProfile = @($global:AdminUserProfiles | Where-Object -FilterScript {$_.General.Default -eq $true})
        }
        switch ($DefaultAdminUserProfile.Count) {
            {$_ -eq 1} {
                $message = @"
Loading Default Admin Profile for Default Org Profile:  
Name: $($DefaultAdminUserProfile.General.Name)
Identity: $($DefaultAdminUserProfile.Identity) 
"@
                Write-Log -Message $message -Verbose -ErrorAction SilentlyContinue
                [boolean]$AdminUserProfileLoaded = Use-AdminUserProfile -Profile $DefaultAdminUserProfile

            }
            {$_ -gt 1} {
                Write-Error "FAILED: Multiple Admin User Profiles Are Set as Default for $($CurrentOrgProfile.Identity): $($DefaultAdminUserProfile.Identity -join ',')"
                Use-AdminUserProfile -Identity (Select-AdminUserProfile -purpose Use)
            }
            {$_ -lt 1} {
                Write-Warning "No Admin User Profiles Are Set as Default for $($CurrentOrgProfile.Identity)"
                switch ($global:AdminUserProfiles.count) {
                    {$_ -ge 1} {
                        Use-AdminUserProfile -Identity (Select-AdminUserProfile -purpose Use)
                    }
                    {$_ -lt 1} {
                        $newAdminUserProfile = New-AdminUserProfile -OrganizationIdentity $CurrentOrgProfile.Identity
                    }
                }
            }
        }
    }#If $OrgProfileLoaded
    if ($AdminUserProfileLoaded) {
        Switch ($PSCmdlet.ParameterSetName) {
            'AutoConnect' {Connect-RemoteSystems}#AutoConnect
            'ShowMenu' {
                Start-Sleep -Seconds 2
                $menudefinition = [pscustomobject]@{
                    GUID = 'ac4ce63e-8b76-4381-a1d5-ad19510f47c7'
                    Title = 'OneShell Module Startup Menu'
                    Initialization = $Null
                    Choices = @(
                        [pscustomobject]@{choice='Connect to Autoconnect Remote Systems from Initialized Profile (Runs command Connect-RemoteSystems)';command='Connect-RemoteSystems';exit=$true}
                        [pscustomobject]@{choice='Manage Organization and/or Admin User Profiles';command='Invoke-Menu -menuGUID 9e7ff8e1-afbb-418d-a31f-9c07bce3ab33'}
                        [pscustomobject]@{choice='Exit to Command Line without Connecting to Autoconnect Remote Systems from the Initialized Profile';command='';exit=$true}
                    )
                    ParentGUID = $Null
                }
                Invoke-Menu -menudefinition $menudefinition
            }#ShowMenu
        }#Switch
    }#if
}
##########################################################################################################
#Globals
##########################################################################################################
#Import-Module PsMenu -Global #moved to module manifest - remove comment later
function Set-OneShellGlobalVariables {
    Write-Log -message 'Setting OneShell Global Variables' -Verbose
    $Global:OneShellModuleFolderPath = Split-Path $((Get-Module -ListAvailable -Name OneShell).Path)
    [string]$Global:E4_SkuPartNumber = 'ENTERPRISEWITHSCAL' 
    [string]$Global:E3_SkuPartNumber = 'ENTERPRISEPACK' 
    [string]$Global:E2_SkuPartNumber = 'STANDARDWOFFPACK' #Non-Profit SKU
    [string]$Global:E1_SkuPartNumber = 'STANDARDPACK'
    [string]$Global:K1_SkuPartNumber = 'DESKLESSPACK' 
    $Global:LogPreference = $True
    $Global:ScalarADAttributesToRetrieve = @(
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
        'Mail'
        'mailNickname'
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
    $Global:MultiValuedADAttributesToRetrieve = @(
        'proxyAddresses'
        'msexchextensioncustomattribute1'
        'msexchextensioncustomattribute2'
        'msexchextensioncustomattribute3'
        'msexchextensioncustomattribute4'
        'msexchextensioncustomattribute5'
        'memberof'
        'msExchPoliciesExcluded'
    )#MultiValuedADAttributesToRetrieve
    $Global:AllADAttributesToRetrieve = @($ScalarADAttributesToRetrieve + $MultiValuedADAttributesToRetrieve)
    $Global:AllADContactAttributesToRetrieve = $Global:AllADAttributesToRetrieve | Where-Object {$_ -notin ('surName','country')}
    $Global:Stamp = Get-TimeStamp
    #Module Menu Definitions
    $menudefinition = [pscustomobject]@{
        GUID = '14aee7c9-6e2a-48bd-bdff-93be72bfc65a'
        Title = 'OneShell Profile Maintenance'
        Initialization = $null
        Choices = @(
        )
        ParentGUID = $null
    }
    Add-GlobalMenuDefinition -MenuDefinition $menudefinition

    $menudefinition = [pscustomobject]@{
        GUID = '9e7ff8e1-afbb-418d-a31f-9c07bce3ab33'
        Title = 'OneShell Admin User Profile Maintenance'
        Initialization = $Null
        Choices = @(
            [pscustomobject]@{choice='View Existing Admin User Profiles';command='Get-AdminUserProfile -operation List; Read-Host -Prompt "Press enter to Continue"'}
            [pscustomobject]@{choice='Edit an existing Admin User Profile';command='Select-AdminUserProfile -purpose Edit'}
            [pscustomobject]@{choice='Use an existing Admin User Profile';command='Select-AdminUserProfile -purpose Use';exit = $true}
            [pscustomobject]@{choice='Create a new Admin User Profile';command='$prompt = "Enter a short descriptive name for this profile";New-AdminUserProfile -OrganizationIdentity $($CurrentOrgProfile.Identity) -name (read-host -Prompt $prompt)'}
        )
        ParentGUID = '14aee7c9-6e2a-48bd-bdff-93be72bfc65a'
    }
    Add-GlobalMenuDefinition -MenuDefinition $menudefinition

    $menudefinition = [pscustomobject]@{
    GUID = 'bfbcf228-1e2e-4289-a7cd-eae003cc3740'
    Title = 'OneShell Organization Profile Maintenance'
    Initialization = $Null
    Choices = @(
        [pscustomobject]@{choice='View Existing Organization Profiles';command='Get-OrgProfile -operation List; Read-Host -Prompt "Press enter to Continue"'}
        #[pscustomobject]@{choice='Edit an existing Organization Profile';command='Select-AdminUserProfile -purpose Edit'}
        [pscustomobject]@{choice='Use an existing Organization Profile';command='Select-OrgProfile -purpose Use'; exit = $true}
        #[pscustomobject]@{choice='Create a new Organization Profile';command='$prompt = "Enter a short descriptive name for this profile";New-AdminUserProfile -OrganizationIdentity $($CurrentOrgProfile.Identity) -name (read-host -Prompt $prompt)'}
    )
    ParentGUID = '14aee7c9-6e2a-48bd-bdff-93be72bfc65a'
    }
    Add-GlobalMenuDefinition -MenuDefinition $menudefinition
}
Set-OneShellGlobalVariables
##########################################################################################################
#Initialization
##########################################################################################################
#Do one of the following in your profile or run script:
#Initialize-AdminEnvironment
# OR
#Get-OrgProfile -operation load
#Select-OrgProfile -purpose Use
#Get-AdminUserProfile -operation load
#Use-AdminUserProfile -Identity [GUID] 
