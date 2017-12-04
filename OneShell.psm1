#!/usr/bin/env powershell
##########################################################################################################
#Utility and Support Functions
##########################################################################################################
#Used By Other OneShell Functions
function Get-ArrayIndexForValue
    {
        [cmdletbinding()]
        param(
            [parameter(mandatory=$true)]
            $array #The array for which you want to find a value's index
            ,
            [parameter(mandatory=$true)]
            $value #The Value for which you want to find an index
            ,
            [parameter()]
            $property #The property name for the value for which you want to find an index
        )
        if ([string]::IsNullOrWhiteSpace($Property))
        {
            Write-Verbose -Message 'Using Simple Match for Index'
            [array]::indexof($array,$value)
        }#if
        else
        {
            Write-Verbose -Message 'Using Property Match for Index'
            [array]::indexof($array.$property,$value)
        }#else
    }#Get-ArrayIndexForValue
function Get-TimeStamp
    {
        [string]$Stamp = Get-Date -Format yyyyMMdd-HHmm
        #$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToShortTimeString()) #check if this is faster to use than Get-Date
        $Stamp
    }#Get-TimeStamp
#Error Handling Functions and used by other OneShell Functions
function Get-AvailableExceptionsList
    {
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
        [CmdletBinding()]
        param()
        $irregulars = 'Dispose|OperationAborted|Unhandled|ThreadAbort|ThreadStart|TypeInitialization'
        $appDomains = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {-not $_.IsDynamic}
        $ExportedTypes = $appDomains | ForEach-Object {$_.GetExportedTypes()}
        $Exceptions = $ExportedTypes | Where-Object {$_.name -like '*exception*' -and $_.name -notmatch $irregulars}
        $exceptionsWithGetConstructorsMethod = $Exceptions | Where-Object -FilterScript {'GetConstructors' -in @($_ | Get-Member -MemberType Methods | Select-Object -ExpandProperty Name)}
        $exceptionsWithGetConstructorsMethod | Select-Object -ExpandProperty FullName
    }
function New-ErrorRecord
    {
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
    [cmdletbinding()]    
    param
    (
        [Parameter(Mandatory, Position = 0)]
        [string]
        $Exception
        ,
        [Parameter(Mandatory, Position = 1)]
        [Alias('ID')]
        [string]
        $ErrorId
        ,
        [Parameter(Mandatory, Position = 2)]
        [Alias('Category')]
        [Management.Automation.ErrorCategory]
        [ValidateSet('NotSpecified', 'OpenError', 'CloseError', 'DeviceError',
                'DeadlockDetected', 'InvalidArgument', 'InvalidData', 'InvalidOperation',
                'InvalidResult', 'InvalidType', 'MetadataError', 'NotImplemented',
                'NotInstalled', 'ObjectNotFound', 'OperationStopped', 'OperationTimeout',
                'SyntaxError', 'ParserError', 'PermissionDenied', 'ResourceBusy',
                'ResourceExists', 'ResourceUnavailable', 'ReadError', 'WriteError',
        'FromStdErr', 'SecurityError')]
        $ErrorCategory
        ,
        [Parameter(Mandatory, Position = 3)]
        $TargetObject
        ,
        [string]
        $Message
        ,
        [Exception]
        $InnerException
    )
    begin
    {
        Add-Type -AssemblyName Microsoft.PowerShell.Commands.Utility
        if (-not (Test-Path -Path variable:script:AvailableExceptionsList))
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
    }
function Get-CallerPreference
    {
        <#
        .Synopsis
        Fetches "Preference" variable values from the caller's scope.
        .DESCRIPTION
        Script module functions do not automatically inherit their caller's variables, but they can be
        obtained through the $PSCmdlet variable in Advanced Functions.  This function is a helper function
        for any script module Advanced Function; by passing in the values of $ExecutionContext.SessionState
        and $PSCmdlet, Get-CallerPreference will set the caller's preference variables locally.
        .PARAMETER Cmdlet
        The $PSCmdlet object from a script module Advanced Function.
        .PARAMETER SessionState
        The $ExecutionContext.SessionState object from a script module Advanced Function.  This is how the
        Get-CallerPreference function sets variables in its callers' scope, even if that caller is in a different
        script module.
        .PARAMETER Name
        Optional array of parameter names to retrieve from the caller's scope.  Default is to retrieve all
        Preference variables as defined in the about_Preference_Variables help file (as of PowerShell 4.0)
        This parameter may also specify names of variables that are not in the about_Preference_Variables
        help file, and the function will retrieve and set those as well.
        .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Imports the default PowerShell preference variables from the caller into the local scope.
        .EXAMPLE
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name 'ErrorActionPreference','SomeOtherVariable'

        Imports only the ErrorActionPreference and SomeOtherVariable variables into the local scope.
        .EXAMPLE
        'ErrorActionPreference','SomeOtherVariable' | Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Same as Example 2, but sends variable names to the Name parameter via pipeline input.
        .INPUTS
        String
        .OUTPUTS
        None.  This function does not produce pipeline output.
        .LINK
        about_Preference_Variables
        #>
        #https://gallery.technet.microsoft.com/scriptcenter/Inherit-Preference-82343b9d
        [CmdletBinding(DefaultParameterSetName = 'AllVariables')]
        param (
            [Parameter(Mandatory)]
            [ValidateScript({ $_.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
            $Cmdlet,

            [Parameter(Mandatory)]
            [Management.Automation.SessionState]
            $SessionState,

            [Parameter(ParameterSetName = 'Filtered', ValueFromPipeline)]
            [string[]]
            $Name
        )
        begin
        {
            $filterHash = @{}
        }
        process
        {
            if ($null -ne $Name)
            {
                foreach ($string in $Name)
                {
                    $filterHash[$string] = $true
                }
            }
        }
        end
        {
            # List of preference variables taken from the about_Preference_Variables help file in PowerShell version 4.0
            $vars = @{
                'ErrorView' = $null
                'FormatEnumerationLimit' = $null
                'LogCommandHealthEvent' = $null
                'LogCommandLifecycleEvent' = $null
                'LogEngineHealthEvent' = $null
                'LogEngineLifecycleEvent' = $null
                'LogProviderHealthEvent' = $null
                'LogProviderLifecycleEvent' = $null
                'MaximumAliasCount' = $null
                'MaximumDriveCount' = $null
                'MaximumErrorCount' = $null
                'MaximumFunctionCount' = $null
                'MaximumHistoryCount' = $null
                'MaximumVariableCount' = $null
                'OFS' = $null
                'OutputEncoding' = $null
                'ProgressPreference' = $null
                'PSDefaultParameterValues' = $null
                'PSEmailServer' = $null
                'PSModuleAutoLoadingPreference' = $null
                'PSSessionApplicationName' = $null
                'PSSessionConfigurationName' = $null
                'PSSessionOption' = $null
                'ErrorActionPreference' = 'ErrorAction'
                'DebugPreference' = 'Debug'
                'ConfirmPreference' = 'Confirm'
                'WhatIfPreference' = 'WhatIf'
                'VerbosePreference' = 'Verbose'
                'WarningPreference' = 'WarningAction'
            }
            foreach ($entry in $vars.GetEnumerator())
            {
                if (([string]::IsNullOrEmpty($entry.Value) -or -not $Cmdlet.MyInvocation.BoundParameters.ContainsKey($entry.Value)) -and
                    ($PSCmdlet.ParameterSetName -eq 'AllVariables' -or $filterHash.ContainsKey($entry.Name)))
                {
                    $variable = $Cmdlet.SessionState.PSVariable.Get($entry.Key)
                    
                    if ($null -ne $variable)
                    {
                        if ($SessionState -eq $ExecutionContext.SessionState)
                        {
                            Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
                        }
                        else
                        {
                            $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                        }
                    }
                }
            }
            if ($PSCmdlet.ParameterSetName -eq 'Filtered')
            {
                foreach ($varName in $filterHash.Keys)
                {
                    if (-not $vars.ContainsKey($varName))
                    {
                        $variable = $Cmdlet.SessionState.PSVariable.Get($varName)
                    
                        if ($null -ne $variable)
                        {
                            if ($SessionState -eq $ExecutionContext.SessionState)
                            {
                                Set-Variable -Scope 1 -Name $variable.Name -Value $variable.Value -Force -Confirm:$false -WhatIf:$false
                            }
                            else
                            {
                                $SessionState.PSVariable.Set($variable.Name, $variable.Value)
                            }
                        }
                    }
                }
            }
        } # end
    } # function Get-CallerPreference
#Useful Functions
function Get-ADDrive {get-psdrive -PSProvider ActiveDirectory}
function New-GUID {[GUID]::NewGuid()}
#Conversion and Testing Functions
function New-SplitArrayRange
    {
        <#  
        .SYNOPSIS 
        Provides Start and End Ranges to Split an array into a specified number of parts (new arrays) or parts (new arrays) with a specified number (size) of elements
        .PARAMETER inArray
        A one dimensional array you want to split
        .EXAMPLE  
        Split-array -inArray @(1,2,3,4,5,6,7,8,9,10) -parts 3
        .EXAMPLE  
        Split-array -inArray @(1,2,3,4,5,6,7,8,9,10) -size 3
        .NOTE
        Derived from https://gallery.technet.microsoft.com/scriptcenter/Split-an-array-into-parts-4357dcc1#content
        #>
        [cmdletbinding()]
        param(
        [parameter(Mandatory)]
        [array]$inputArray
        ,
        [parameter(Mandatory,ParameterSetName ='Parts')]
        [int]$parts
        ,
        [parameter(Mandatory,ParameterSetName ='Size')]
        [int]$size
        )
        switch ($PSCmdlet.ParameterSetName)
        {
            'Parts'
            {
                $PartSize = [Math]::Ceiling($inputArray.count / $parts)
            }#Parts
            'Size'
            {
                $PartSize = $size
                $parts = [Math]::Ceiling($inputArray.count / $size)
            }#Size
        }#switch
        for ($i=1; $i -le $parts; $i++)
        {
            $start = (($i-1)*$PartSize)
            $end = (($i)*$PartSize) - 1
            if ($end -ge $inputArray.count) {$end = $inputArray.count}
            $SplitArrayRange = [pscustomobject]@{
                Part = $i
                Start = $start
                End = $end
            }
            Write-Output -InputObject $SplitArrayRange
        }#for
    }
function Convert-HashtableToObject
    {
        [CmdletBinding()]
        PARAM
        (
            [Parameter(ValueFromPipeline, Mandatory)]
            [HashTable]$hashtable
            ,
            [switch]$Combine
            ,
            [switch]$Recurse
        )
        BEGIN
        {
            $output = @()
        }
        PROCESS
        {
            if($recurse)
            {
                $keys = $hashtable.Keys | ForEach-Object { $_ }
                Write-Verbose -Message "Recursing $($Keys.Count) keys"
                foreach($key in $keys) {
                    if($hashtable.$key -is [HashTable]) {
                        $hashtable.$key = Convert-HashtableToObject -hashtable $hashtable.$key -Recurse # -Combine:$combine
                    }
                }
            }
            if($combine)
            {
                $output += @(New-Object -TypeName PSObject -Property $hashtable)
                Write-Verbose -Message "Combining Output = $($Output.Count) so far"
            }
            else
            {
                New-Object -TypeName PSObject -Property $hashtable
            }
        }
        END {
            if($combine -and $output.Count -gt 1)
            {
                Write-Verbose -Message "Combining $($Output.Count) cached outputs"
                $output | Join-Object
            }
            else
            {
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
            [Parameter(Position=0,Mandatory,
            HelpMessage='Please specify an object',ValueFromPipeline)]
            [ValidateNotNullorEmpty()]
            $InputObject,
            [switch]$NoEmpty,
            [string[]]$Exclude
        )

        Process {
            #get type using the [Type] class because deserialized objects won't have
            #a GetType() method which is what we would normally use.

            $TypeName = [type]::GetTypeArray($InputObject).name
            Write-Verbose -Message "Converting an object of type $TypeName"
        
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
                        Write-Verbose -Message "Skipping $_ as empty"
                    }
                    else {
                        Write-Verbose -Message "Adding property $_"
                        $hash.Add($_,$inputobject.$_)
                    }
                } #if exclude notcontains
                else {
                    Write-Verbose -Message "Excluding $_"
                }
            } #foreach
            Write-Verbose -Message 'Writing the result to the pipeline'
            Write-Output -InputObject $hash
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
            [parameter(ValueFromPipeline=$True)]
            [securestring[]]$SecureString
        )
        
        BEGIN {}
        PROCESS {
            foreach ($ss in $SecureString)
            {
            if ($ss -is 'SecureString')
            {[Runtime.InteropServices.marshal]::PtrToStringAuto([Runtime.InteropServices.marshal]::SecureStringToBSTR($ss))}
            }
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
        [Convert]::ToBase64String($Guid.ToByteArray())
    }
function Get-GUIDFromImmutableID
    {
    [cmdletbinding()]
        param(
            $ImmutableID
        )
        [GUID][convert]::frombase64string($ImmutableID) 
    }
function Get-Checksum
    {
        Param (
            [parameter(Mandatory=$True)]
            [ValidateScript({Test-FilePath -path $_})]
            [string]$File
            ,
            [ValidateSet('sha1','md5')]
            [string]$Algorithm='sha1'
        )
        $FileObject = Get-Item -Path $File
        $fs = new-object System.IO.FileStream $($FileObject.FullName), 'Open'
        $algo = [type]"System.Security.Cryptography.$Algorithm"
        $crypto = $algo::Create()
        $hash = [BitConverter]::ToString($crypto.ComputeHash($fs)).Replace('-', '')
        $fs.Close()
        $hash
    }
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
    if ($raw) {$UninstallEntries | Sort-Object -Property DisplayName}
    else {
        $UninstallEntries | Sort-Object -Property DisplayName | Select-Object -Property $property
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
    $RecordCount = $AllRecipients.count
    $cr=0
    foreach ($r in $AllRecipients) 
    {
        $cr++
        $writeProgressParams = @{
            Activity = 'Processing Recipient Alias for Test-ExchangeAlias.  Building Global Variable which future uses of Test-ExchangeAlias will use unless the -RefreshAliasData parameter is used.'
            Status = "Record $cr of $RecordCount"
            PercentComplete = $cr/$RecordCount * 100
            CurrentOperation = "Processing Recipient: $($r.GUID.tostring())"
        }
        Write-Progress @writeProgressParams
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
    Write-Progress @writeProgressParams -Completed
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
        Write-Log -message 'Running New-TestExchangeAlias'
        New-TestExchangeAlias -ExchangeOrganization $ExchangeOrganization
    }
  }
  else 
  {
    Write-Log -message 'Running New-TestExchangeAlias'
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
            Write-Output -InputObject $false
        }
    }
    else {
        Write-Output -InputObject $true
    }
  }
  else {
    Write-Output -InputObject $true
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
        Write-Log -Message 'Alias already exists in the TestExchangeAlias Table' -EntryType Failed
        Write-Output -InputObject $false
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
        Write-Log -message 'Running New-TestExchangeProxyAddress'
        New-TestExchangeProxyAddress -ExchangeOrganization $ExchangeOrganization
    }
  }
  else
  {
    Write-Log -message 'Running New-TestExchangeProxyAddress'
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
            Write-Output -InputObject $false
        }
    }
    else {
        Write-Output -InputObject $true
    }
  }
  else {
    Write-Output -InputObject $true
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
    Write-Output -InputObject $false
  }
  else
  {
    $Script:TestExchangeProxyAddress.$ProxyAddress = @()
    $Script:TestExchangeProxyAddress.$ProxyAddress += $ObjectGUID
  }
}#function Add-ExchangeProxyAddressToTestExchangeProxyAddress

function Test-RecipientObjectForUnwantedSMTPAddresses
{
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$WantedDomains
        ,
        [Parameter(Mandatory)]
        [ValidateScript({($_ | Test-Member -name 'EmailAddresses') -or ($_ | Test-Member -name 'ProxyAddresses')})]
        [psobject[]]$Recipient
        ,
        [Parameter(Mandatory)]
        [ValidateSet('ReportUnwanted','ReportAll','TestOnly')]
        [string]$Operation = 'TestOnly'
        ,
        [bool]$ValidateSMTPAddress = $true
    )
    foreach ($R in $Recipient)
    {
        Switch ($R)
        {
            {$R | Test-Member -Name 'EmailAddresses'}
            {$AddrAtt = 'EmailAddresses'}
            {$R | Test-Member -Name 'ProxyAddresses'}
            {$AddrAtt = 'ProxyAddresses'}
        }
        $Addresses = @($R.$addrAtt)
        $TestedAddresses = @(
            foreach ($A in $Addresses)
            {
                if ($A -like 'smtp:*')
                {
                    $RawA = $A.split(':')[1]
                    $ADomain = $RawA.split('@')[1]
                    $IsSupportedDomain = $ADomain -in $WantedDomains
                    $outputRecord = 
                        [pscustomobject]@{
                            DistinguishedName = $R.DistinguishedName
                            Identity = $R.Identity
                            Address = $RawA
                            Domain = $ADomain
                            IsSupportedDomain = $IsSupportedDomain
                            IsValidSMTPAddress = $null
                        }
                    if ($ValidateSMTPAddress)
                    {
                        $IsValidSMTPAddress = Test-EmailAddress -EmailAddress $RawA
                        $outputRecord.IsValidSMTPAddress = $IsValidSMTPAddress
                    }
                }
                Write-Output -InputObject $outputRecord
            }
        )
       switch ($Operation)
       {
            'TestOnly'
            {
                if ($TestedAddresses.IsSupportedDomain -contains $false -or $TestedAddresses.IsValidSMTPAddress -contains $false)
                {Write-Output -InputObject $false}
                else 
                {Write-Output -InputObject $true}
            }
            'ReportUnwanted'
            {
                $UnwantedAddresses = @($TestedAddresses | Where-Object -FilterScript {$_.IsSupportedDomain -eq $false -or $_.IsValidSMTPAddress -eq $false})
                if ($UnwantedAddresses.Count -ge 1)
                {
                    Write-Output -InputObject $UnwantedAddresses
                }
            }
            'ReportAll'
            {
                Write-Output -InputObject $TestedAddresses
            }
       }
    }#foreach R in Recipient
}#function
function Get-DuplicateEmailAddresses
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        $ExchangeOrganization
    )
    Write-Verbose -Message "Building Exchange Proxy Address Hashtable with New-TestExchangeProxyAddress"
    New-TestExchangeProxyAddress -ExchangeOrganization $ExchangeOrganization
    #$TestExchangeProxyAddress = Get-OneShellVariableValue -Name TestExchangeProxyAddress
    Write-Verbose -Message "Filtering Exchange Proxy Address Hashtable for Addresses Assigned to Multiple Recipients"
    $duplicateAddresses = $TestExchangeProxyAddress.GetEnumerator() | Where-Object -FilterScript {$_.Value.count -gt 1}
    Write-Verbose -Message "Iterating through duplicate addresses and creating output"
    $duplicatnum = 0
    foreach ($dup in $duplicateAddresses)
    {
        $duplicatnum++
        foreach ($val in $dup.value)
        {
            $splat =@{
                cmdlet = 'get-recipient'
                ExchangeOrganization = $ExchangeOrganization
                ErrorAction = 'Stop'
                splat = @{
                    Identity = $val
                    ErrorAction = 'Stop'
                }#innersplat
            }#outersplat
            try
            {
                $Recipient = Invoke-ExchangeCommand @splat
            }#try
            catch
            {
                $message = "Get-Recipient $val in Exchange Organization $ExchangeOrganization"
                Write-Log -Message $message -EntryType Failed -ErrorLog
            }#catch
            $duplicateobject = [pscustomobject]@{
                DuplicateAddress = $dup.Name
                DuplicateNumber = $duplicatnum
                DuplicateRecipientCount = $dup.Value.Count
                RecipientDN = $Recipient.distinguishedName
                RecipientAlias = $recipient.alias
                RecipientPrimarySMTPAddress = $recipient.primarysmtpaddress
                RecipientGUID = $Recipient.guid
                RecipientTypeDetails = $Recipient.RecipientTypeDetails
            }
            Write-Output -InputObject $duplicateobject
        }#Foreach
    }
}#function
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
  Process
  {
    Connect-Exchange -ExchangeOrganization $ExchangeOrganization
    $Recipient = Invoke-ExchangeCommand -cmdlet Get-Recipient -ExchangeOrganization $ExchangeOrganization -string "-Identity $Identity -ErrorAction SilentlyContinue" -ErrorAction SilentlyContinue
    if ($Recipient.$RecipientAttributeToCheck -eq $RecipientAttributeValue) {
        Write-Log -Message "Checking $identity for value $RecipientAttributeValue in attribute $RecipientAttributeToCheck." -EntryType Succeeded  
        Write-Output -InputObject $true
    }
    elseif ($InitiateSynchronization) {
        Write-Log -Message "Initiating Directory Synchronization and Checking/Waiting for a maximum of $MaxSyncWaitMinutes minutes." -EntryType Notification
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
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
            Write-Log -Message 'Maximum Synchronization Wait Time Met or Exceeded' -EntryType Notification -ErrorLog
        }
        if ($Recipient.$RecipientAttributeToCheck -eq $RecipientAttributeValue) {
            Write-Log -Message "Checking $identity for value $RecipientAttributeValue in attribute $RecipientAttributeToCheck." -EntryType Succeeded
            Write-Output -InputObject $true
        }
        else {Write-Output -InputObject $false}
    }
    else {Write-Output -InputObject $false}
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
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  do {
    Try {
        $value = Get-Variable -Name $VariableName -ValueOnly -Scope $scope -ErrorAction SilentlyContinue
    }
    Catch {
    }
    $scope++
  }
  until (-not [string]::IsNullOrWhiteSpace($value) -or $stopwatch.ElapsedMilliseconds -ge $timeout -or $scope -ge $ScopeLevels)
  Write-Output -InputObject $value
}
Function Write-Log
{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
        ,
        [Parameter(Position=1)]
        [string]$LogPath
        ,
        [Parameter(Position=2)]
        [switch]$ErrorLog
        ,
        [Parameter(Position=3)]
        [string]$ErrorLogPath
        ,
        [Parameter(Position=4)]
        [ValidateSet('Attempting','Succeeded','Failed','Notification')]
        [string]$EntryType
    )
    Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -Name VerbosePreference
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
Write-Log -Message "$CallingFunction completed." -EntryType Notification}
Function Write-StartFunctionStatus {
    param($CallingFunction)
Write-Log -Message "$CallingFunction starting." -EntryType Notification}
function Out-FileUtf8NoBom {
  #requires -version 3
  <#
      .SYNOPSIS
      Outputs to a UTF-8-encoded file *without a BOM* (byte-order mark).

      .DESCRIPTION
      Mimics the most important aspects of Out-File:
      * Input objects are sent to Out-String first.
      * -Append allows you to append to an existing file, -NoClobber prevents
      overwriting of an existing file.
      * -Width allows you to specify the line width for the text representations
      of input objects that aren't strings.
      However, it is not a complete implementation of all Out-String parameters:
      * Only a literal output path is supported, and only as a parameter.
      * -Force is not supported.

      Caveat: *All* pipeline input is buffered before writing output starts,
          but the string representations are generated and written to the target
          file one by one.

      .NOTES
      The raison d'être for this advanced function is that, as of PowerShell v5, 
      Out-File still lacks the ability to write UTF-8 files without a BOM: 
      using -Encoding UTF8 invariably prepends a BOM.
      http://stackoverflow.com/questions/5596982/using-powershell-to-write-a-file-in-utf-8-without-the-bom
  #>
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory, Position=0)]
    [string] $LiteralPath
    ,
    [switch] $Append
    ,
    [switch] $NoClobber
    ,
    [AllowNull()] [int] $Width
    ,
    [Parameter(ValueFromPipeline)] 
    $InputObject
  )
  # Make sure that the .NET framework sees the same working dir. as PS
  # and resolve the input path to a full path.
  #[Environment]::CurrentDirectory = $PWD
  $LiteralPath = [IO.Path]::GetFullPath($LiteralPath)
  # If -NoClobber was specified, throw an exception if the target file already
  # exists.
  if ($NoClobber -and (Test-Path $LiteralPath)) { 
    Throw [IO.IOException] "The file '$LiteralPath' already exists."
  }
  # Create a StreamWriter object.
  # Note that we take advantage of the fact that the StreamWriter class by default:
  # - uses UTF-8 encoding
  # - without a BOM.
  $sw = New-Object IO.StreamWriter $LiteralPath, $Append
  $htOutStringArgs = @{}
  if ($Width) {
    $htOutStringArgs += @{ Width = $Width }
  }
    # Note: By not using begin / process / end blocks, we're effectively running
  #       in the end block, which means that all pipeline input has already
  #       been collected in automatic variable $Input.
  #       We must use this approach, because using | Out-String individually
  #       in each iteration of a process block would format each input object
  #       with an indvidual header.
  try {
    $InputObject | Out-String -Stream @htOutStringArgs | ForEach-Object { $sw.WriteLine($_) }
  } finally {
    $sw.Dispose()
  }
}
Function Export-Data
{
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
    [parameter(ParameterSetName='delimited')]
    [string]$Delimiter = ','
    ,
    [switch]$ReturnExportFilePath
    ,
    [parameter()]
    [ValidateSet('Unicode','BigEndianUnicode','Ascii','Default','UTF8','UTF8NOBOM','UTF7','UTF32')]
    [string]$Encoding = 'Ascii'
  )
  #Determine Export File Path
  $stamp = Get-TimeStamp
    switch ($DataType)
    {
        'xml'
        {
            $ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp  + $DataToExportTitle + '.xml')
        }#xml
        'json'
        {
            $ExportFilePath = Join-Path -Path $exportFolderPath  -ChildPath $($Stamp  + $DataToExportTitle + '.json')
        }#json
        'csv'
        {
            if ($Append)
            {
                $mostrecent = @(get-childitem -Path $ExportFolderPath -Filter "*$DataToExportTitle.csv" | Sort-Object -Property CreationTime -Descending | Select-Object -First 1)
                if ($mostrecent.count -eq 1)
                {
                    $ExportFilePath = $mostrecent[0].fullname
                }#if
                else {$ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp  + $DataToExportTitle + '.csv')}#else
            }#if
            else {$ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp  + $DataToExportTitle + '.csv')}#else
        }#csv
    }#switch $dataType
    #Attempt Export of Data to File
    $message = "Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath"
    Write-Log -Message $message -EntryType Attempting
    Try
    {
        $formattedData = $(
            switch ($DataType)
            {
                'xml'
                {
                    $DataToExport | ConvertTo-Xml -Depth $Depth -ErrorAction Stop -NoTypeInformation -As String
                }#xml
                'json'
                {
                    $DataToExport | ConvertTo-Json -Depth $Depth -ErrorAction Stop
                }#json
                'csv'
                {
                    $DataToExport | ConvertTo-Csv -ErrorAction Stop -NoTypeInformation -Delimiter $Delimiter
                }#csv
            }
        )
        $outFileParams = @{
          ErrorAction = 'Stop'
          InputObject = $formattedData
          LiteralPath = $ExportFilePath
        }
        switch ($Encoding)
        {
          'UTF8NOBOM'
          {
            if ($Append)
            {
              $outFileParams.Append = $true
            }
            Out-FileUtf8NoBom @outFileParams
          }
          Default
          {
            $outFileParams.Encoding = $Encoding
            if ($append)
            {
              $outFileParams.Append = $true
            }
            Out-File @outFileParams
          }
        }
        if ($ReturnExportFilePath) {Write-Output -InputObject $ExportFilePath}
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
    }
    Write-Output -InputObject $exportCredential
}
Function Remove-AgedFiles
{
  [cmdletbinding(SupportsShouldProcess,ConfirmImpact = 'Medium')]
  param(
    [int]$Days
    ,
    [parameter()]
    [validatescript({Test-IsWriteableDirectory -Path $_})]
    [string[]]$Directory
    ,
    [switch]$Recurse
  )
    $now = Get-Date
    $daysAgo = $now.AddDays(-$days)
    $splat=@{
        File=$true
    }
    if ($PSBoundParameters.ContainsKey('Recurse'))
    {
        $splat.Recurse = $true
    }
    foreach ($d in $Directory)
    {
        $splat.path = $d
        $files = Get-ChildItem @splat
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
                    $speak.SpeakAsync("$secondsremaining") > $null}
                else {
                    $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                }
            }
        }
        'Minutes' {
            $seconds = $frequency * 60
            if ($voice -and ($secondsremaining % $seconds -eq 0)) {
                $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                if ($minutesremaining -ge 1) {
                    $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                }
                else {
                    if ($secondsremaining -ge 1) {
                        $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                    }
                }
            }
        }
        'Hours' {
            $seconds = $frequency * 60 * 60
            if ($voice -and ($secondsremaining % $seconds -eq 0)) {
                $hoursremaining = $remaining.TotalHours.tostring("#.##")
                if ($hoursremaining -ge 1) {
                    $speak.SpeakAsync("$hoursremaining hours remaining") > $null
                }
                else {
                    $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                    if ($minutesremaining -ge 1) {
                        $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                    }
                    else {
                        if ($secondsremaining -ge 1) {
                            $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
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
                    $speak.SpeakAsync("$daysremaining days remaining") > $null
                }
                else {
                    $hoursremaining = $remaining.TotalHours.tostring("#.##")
                    if ($hoursremaining -ge 1) {
                        $speak.SpeakAsync("$hoursremaining hours remaining") > $null
                    }
                    else {
                        $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                        if ($minutesremaining -ge 1) {
                            $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                        }
                        else {
                            if ($secondsremaining -ge 1) {
                                $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                            }
                        }
                    }
                        
                }
            }
        }
    }
    $currentvrt = $vrts | Where-Object -FilterScript {$_.countdownpoint -ge $($secondsremaining - 1)} | Select-Object -First 1
    if ($currentvrt) {
        $Frequency = $currentvrt.frequency
        $Units = $currentvrt.units
        $vrts = $vrts | Where-Object -FilterScript  {$_countdownpoint -ne $currentvrt.countdownpoint}
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
function Read-InputBoxDialog
{ # Show input box popup and return the value entered by the user. 
  param(
    [string]$Message
    ,
    [Alias('WindowTitle')]
    [string]$Title
    ,
    [string]$DefaultText
  )

  $Script:UserInput = $null
  #Region BuildWPFWindow
  # Add required assembly
  Add-Type -AssemblyName WindowsBase
  Add-Type -AssemblyName PresentationCore
  Add-Type -AssemblyName PresentationFramework
  # Create a Size Object
  $wpfSize = new-object System.Windows.Size
  $wpfSize.Height = [double]::PositiveInfinity
  $wpfSize.Width = [double]::PositiveInfinity
  # Create a Window
  $Window = New-Object Windows.Window
  $Window.Title = $WindowTitle
  $Window.MinWidth = 250
  $Window.SizeToContent ='WidthAndHeight'
  $window.WindowStartupLocation='CenterScreen'
  # Create a grid container with 3 rows, one for the message, one for the text box, and one for the buttons
  $Grid =  New-Object Windows.Controls.Grid
  $FirstRow = New-Object Windows.Controls.RowDefinition
  $FirstRow.Height = 'Auto'
  $grid.RowDefinitions.Add($FirstRow)
  $SecondRow = New-Object Windows.Controls.RowDefinition
  $SecondRow.Height = 'Auto'
  $grid.RowDefinitions.Add($SecondRow)
  $ThirdRow = New-Object Windows.Controls.RowDefinition
  $ThirdRow.Height = 'Auto'
  $grid.RowDefinitions.Add($ThirdRow)
  $ColumnOne = New-Object Windows.Controls.ColumnDefinition
  $ColumnOne.Width = 'Auto'
  $grid.ColumnDefinitions.Add($ColumnOne)
  $ColumnTwo = New-Object Windows.Controls.ColumnDefinition
  $ColumnTwo.Width = 'Auto'
  $grid.ColumnDefinitions.Add($ColumnTwo)
  # Create a label for the message
  $label = New-Object Windows.Controls.Label
  $label.Content = $Message
  $label.Margin = '5,5,5,5'
  $label.HorizontalAlignment = 'Left'
  $label.Measure($wpfSize)
  #add the label to Row 1
  $label.SetValue([Windows.Controls.Grid]::RowProperty,0)
  $label.SetValue([Windows.Controls.Grid]::ColumnSpanProperty,2)
  $textbox = New-Object Windows.Controls.TextBox
  $textbox.name = 'InputBox'
  $textbox.Text = $DefaultText
  $textbox.Margin = '10,10,10,10'
  $textbox.MinWidth = 200
  $textbox.SetValue([Windows.Controls.Grid]::RowProperty,1)
  $textbox.SetValue([Windows.Controls.Grid]::ColumnSpanProperty,2)
  $OKButton = New-Object Windows.Controls.Button
  $OKButton.Name = 'OK'
  $OKButton.Content = 'OK'
  $OKButton.ToolTip = 'OK'
  $OKButton.HorizontalAlignment = 'Center'
  $OKButton.VerticalAlignment = 'Top'
  $OKButton.Add_Click({
        [Object]$sender = $args[0]
        [Windows.RoutedEventArgs]$e = $args[1]
        $Script:UserInput = $textbox.text
        $Window.DialogResult = $true
        $Window.Close()
    })
  $OKButton.SetValue([Windows.Controls.Grid]::RowProperty,2)
  $OKButton.SetValue([Windows.Controls.Grid]::ColumnProperty,0)
  $OKButton.Margin = '5,5,5,5'
  $CancelButton = New-Object Windows.Controls.Button
  $CancelButton.Name = 'Cancel'
  $CancelButton.Content = 'Cancel'
  $CancelButton.ToolTip = 'Cancel'
  $CancelButton.HorizontalAlignment = 'Center'
  $CancelButton.VerticalAlignment = 'Top'
  $CancelButton.Margin = '5,5,5,5'
  $CancelButton.Measure($wpfSize)
  $CancelButton.Add_Click({
        [Object]$sender = $args[0]
        [Windows.RoutedEventArgs]$e = $args[1]
        $Window.DialogResult = $false
        $Window.Close()
    })
  $CancelButton.SetValue([Windows.Controls.Grid]::RowProperty,2)
  $CancelButton.SetValue([Windows.Controls.Grid]::ColumnProperty,1)
  $CancelButton.Height = $CancelButton.DesiredSize.Height
  $CancelButton.Width = $CancelButton.DesiredSize.Width + 10
  $OKButton.Height = $CancelButton.DesiredSize.Height
  $OKButton.Width = $CancelButton.DesiredSize.Width + 10
  $Grid.AddChild($label)
  $Grid.AddChild($textbox)
  $Grid.AddChild($OKButton)
  $Grid.AddChild($CancelButton)
  $window.Content = $Grid
  if ($window.ShowDialog())
  {
    $Script:UserInput
  }
} 
function Read-OpenFileDialog
{
  [cmdletbinding()]
  param(
    [string]$WindowTitle
    ,
    [string]$InitialDirectory
    ,
    [string]$Filter = 'All files (*.*)|*.*'
    ,
    [switch]$AllowMultiSelect
  )
    Add-Type -AssemblyName System.Windows.Forms
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = $WindowTitle
    if ($PSBoundParameters.ContainsKey('InitialDirectory')) { $openFileDialog.InitialDirectory = $InitialDirectory }
    $openFileDialog.Filter = $Filter
    if ($AllowMultiSelect) { $openFileDialog.MultiSelect = $true }
    $openFileDialog.ShowHelp = $true
    # Without this line the ShowDialog() function may hang depending on system configuration and running from console vs. ISE.     
    $result = $openFileDialog.ShowDialog()
    switch ($Result)
    {
        'OK'
        {
            if ($AllowMultiSelect)
            {
                Write-Output -InputObject $openFileDialog.Filenames
            } else
            {
                Write-Output -InputObject $openFileDialog.Filename
            } 
        }
        'Cancel'
        {
        }
    }
    $openFileDialog.Dispose()
    Remove-Variable -Name openFileDialog
}#Read-OpenFileDialog
function Read-PromptForChoice
{
  [cmdletbinding(DefaultParameterSetName='StringChoices')]
  Param(
    [string]$Message
    ,
    [Parameter(Mandatory,ParameterSetName='StringChoices')]
    [ValidateNotNullOrEmpty()]
    [alias('StringChoices')]
    [String[]]$Choices
    ,
    [Parameter(Mandatory,ParameterSetName='ObjectChoices')]
    [ValidateNotNullOrEmpty()]
    [alias('ObjectChoices')]
    [psobject[]]$ChoiceObjects
    ,
    [int]$DefaultChoice = -1
    #[int[]]$DefaultChoices = @(0)
    ,
    [string]$Title = [string]::Empty
    ,
    [Parameter(ParameterSetName='StringChoices')]
    [switch]$Numbered
  )
    #Build Choice Objects
  switch ($PSCmdlet.ParameterSetName)
  {
    'StringChoices'
    #Create the Choice Objects
    {
        if ($Numbered)
        {
            $choiceCount = 0
            $ChoiceObjects = @(
                foreach ($choice in $Choices)
                {
                    $choiceCount++
                    [PSCustomObject]@{
                        Enumerator = $choiceCount
                        Choice = $choice
                    }
                }
            )
        }
        else
        {
            [char[]]$choiceEnumerators = @()
            $ChoiceObjects = @(
                foreach ($choice in $Choices)
                {
                    $Enumerator = $null
                    foreach ($char in $choice.ToCharArray())
                    {
                        if ($char -notin $choiceEnumerators -and $char -match '[a-zA-Z]' )
                        {
                            $Enumerator = $char
                            $choiceEnumerators += $Enumerator
                            break
                        }
                    }
                    if ($Enumerator -eq $null)
                    {
                        $EnumeratorError = New-ErrorRecord -Exception System.Management.Automation.RuntimeException -ErrorId 0 -ErrorCategory InvalidData -TargetObject $choice -Message 'Unable to determine an enumerator'
                        $PSCmdlet.ThrowTerminatingError($EnumeratorError)
                    }
                    else
                    {
                        [PSCustomObject]@{
                            Enumerator = $Enumerator
                            Choice = $choice
                        }
                    }
                }
            )
        }
    }
    'ObjectChoices'
    #Validate the Choice Objects using the first object as a representative
    {
        if ($ChoiceObjects[0].Enumerator -eq $null -or $ChoiceObjects[0].Choice -eq $null)
        {
            $ChoiceObjectError = New-ErrorRecord -Exception System.Management.Automation.RuntimeException -ErrorId 1 -ErrorCategory InvalidData -TargetObject $ChoiceObjects[0] -Message 'Choice Object(s) do not include the required enumerator and/or choice properties'
            $PSCmdlet.ThrowTerminatingError($ChoiceObjectError)
        }
    }
  }#Switch
  [Management.Automation.Host.ChoiceDescription[]]$PossibleChoices = @(
    $ChoiceObjects | ForEach-Object {
        $Enumerator = $_.Enumerator
        $Choice = $_.Choice
        $Description = if (-not [string]::IsNullOrWhiteSpace($_.Description)) {$_.Description} else {$_.Choice}
        $ChoiceWithEnumerator =
            if ($Numbered)
            {
                "&$Enumerator $($Choice)"
            }
            else
            {
                $index = $choice.IndexOf($Enumerator)
                if ($index -eq -1)
                {
                    "&$Enumerator $($Choice)"
                }
                else
                {
                    $choice.insert($index,'&')
                }
            }
        New-Object System.Management.Automation.Host.ChoiceDescription $ChoiceWithEnumerator, $Description
    }
  )
  $Host.UI.PromptForChoice($Title, $Message, $PossibleChoices, $DefaultChoice)
}#Read-Choice
function Read-Choice
{
  [cmdletbinding()]
  param(
    [string]$Title = [string]::Empty
    ,
    [string]$Message
    ,
    [Parameter(Mandatory,ParameterSetName='StringChoices')]
    [ValidateNotNullOrEmpty()]
    [alias('StringChoices')]
    [String[]]$Choices
    ,
    [Parameter(Mandatory,ParameterSetName='ObjectChoices')]
    [ValidateNotNullOrEmpty()]
    [alias('ObjectChoices')]
    [psobject[]]$ChoiceObjects
    ,
    [int]$DefaultChoice = -1
    ,
    [Parameter(ParameterSetName='StringChoices')]
    [switch]$Numbered
    ,
    [switch]$Vertical
    ,
    [switch]$ReturnChoice
  )
  #Region ProcessChoices
  #Prepare the PossibleChoices objects
  switch ($PSCmdlet.ParameterSetName)
  {
    'StringChoices'
    #Create the Choice Objects
    {
        if ($Numbered)
        {
            $choiceCount = 0
            $ChoiceObjects = @(
                foreach ($choice in $Choices)
                {
                    $choiceCount++
                    [PSCustomObject]@{
                        Enumerator = $choiceCount
                        Choice = $choice
                    }
                }
            )
        }
        else
        {
            [char[]]$choiceEnumerators = @()
            $ChoiceObjects = @(
                foreach ($choice in $Choices)
                {
                    $Enumerator = $null
                    foreach ($char in $choice.ToCharArray())
                    {
                        if ($char -notin $choiceEnumerators -and $char -match '[a-zA-Z]' )
                        {
                            $Enumerator = $char
                            $choiceEnumerators += $Enumerator
                            break
                        }
                    }
                    if ($Enumerator -eq $null)
                    {
                        $EnumeratorError = New-ErrorRecord -Exception System.Management.Automation.RuntimeException -ErrorId 0 -ErrorCategory InvalidData -TargetObject $choice -Message 'Unable to determine an enumerator'
                        $PSCmdlet.ThrowTerminatingError($EnumeratorError)
                    }
                    else
                    {
                        [PSCustomObject]@{
                            Enumerator = $Enumerator
                            Choice = $choice
                        }
                    }
                }
            )
        }
    }
    'ObjectChoices'
    #Validate the Choice Objects using the first object as a representative
    {
        if ($ChoiceObjects[0].Enumerator -eq $null -or $ChoiceObjects[0].Choice -eq $null)
        {
            $ChoiceObjectError = New-ErrorRecord -Exception System.Management.Automation.RuntimeException -ErrorId 1 -ErrorCategory InvalidData -TargetObject $ChoiceObjects[0] -Message 'Choice Object(s) do not include the required enumerator and/or choice properties'
            $PSCmdlet.ThrowTerminatingError($ChoiceObjectError)
        }
    }
  }#Switch
  $possiblechoices = @(
    $ChoiceObjects | ForEach-Object {
        $Enumerator = $_.Enumerator
        $Choice = $_.Choice
        $Description = if (-not [string]::IsNullOrWhiteSpace($_.Description)) {$_.Description} else {$_.Choice}
        $ChoiceWithEnumerator = 
            if ($Numbered)
            {
                "_$Enumerator $($Choice)"
            }
            else
            {
                $index = $choice.IndexOf($Enumerator)
                if ($index -eq -1)
                {
                    "_$Enumerator $($Choice)"
                }
                else
                {
                    $choice.insert($index,'_')
                }
            }
       [pscustomobject]@{
            ChoiceText = $Choice
            ChoiceWithEnumerator = $ChoiceWithEnumerator
            Description = $Description
       }
    }
  )
  $Script:UserChoice = $null
  #EndRegion ProcessChoices
  #Region Layout
  if ($Vertical)
  {
    $layout = 'Vertical'
  } else
  {
    $layout = 'Horizontal'
  }
  #EndRegion Layout
  #Region BuildWPFWindow
  # Add required assembly
  Add-Type -AssemblyName WindowsBase
  Add-Type -AssemblyName PresentationCore
  Add-Type -AssemblyName PresentationFramework
  # Create a Size Object
  $wpfSize = new-object System.Windows.Size
  $wpfSize.Height = [double]::PositiveInfinity
  $wpfSize.Width = [double]::PositiveInfinity
  # Create a Window
  $Window = New-Object Windows.Window
  $Window.Title = $Title
  $Window.SizeToContent ='WidthAndHeight'
  $window.WindowStartupLocation='CenterScreen'
  # Create a grid container with x rows, one for the message, x for the buttons
  $Grid =  New-Object Windows.Controls.Grid
  $FirstRow = New-Object Windows.Controls.RowDefinition
  $FirstRow.Height = 'Auto'
  $grid.RowDefinitions.Add($FirstRow)
  # Create a label for the message
  $label = New-Object Windows.Controls.Label
  $label.Content = $Message
  $label.Margin = '5,5,5,5'
  $label.HorizontalAlignment = 'Left'
  $label.Measure($wpfSize)
  #add the label to Row 1
  $label.SetValue([Windows.Controls.Grid]::RowProperty,0)
  #prepare for button sizing
  $buttonHeights = @()
  $buttonWidths = @()
  if ($layout -eq 'Horizontal') {$label.SetValue([Windows.Controls.Grid]::ColumnSpanProperty,$($choices.Count))}
  elseif ($layout -eq 'Vertical') {$buttonWidths += $label.DesiredSize.Width}
  #create the buttons and add them to the grid
  $buttonIndex = 0
  foreach ($pc in $possiblechoices)
  {
    # Create a button to get running Processes
    Set-Variable -Name "buttonControl$buttonIndex" -Value (New-Object Windows.Controls.Button) -Scope local
    $tempButton = Get-Variable -Name "buttonControl$buttonIndex" -ValueOnly
    $tempButton.Name = "Choice$buttonIndex"
    $tempButton.Content = $pc.ChoiceWithEnumerator
    $tempButton.Tooltip = $pc.Description
    $tempButton.HorizontalAlignment = 'Center'
    $tempButton.VerticalAlignment = 'Top'
    # Add an event on the Get Processes button
    $tempButton.Add_Click({
        [Object]$sender = $args[0]
        [Windows.RoutedEventArgs]$e = $args[1]
        $Script:UserChoice = $sender.content.tostring()
        $Window.DialogResult = $true
        $Window.Close()
    })
    switch ($layout)
    {
        'Vertical'
        {
            #Create additional row for each button
            $Row = New-Object Windows.Controls.RowDefinition
            $Row.Height = 'Auto'
            $grid.RowDefinitions.Add($Row)
            $RowIndex = $buttonIndex + 1
            $tempButton.SetValue([Windows.Controls.Grid]::RowProperty,$RowIndex)
        }
        'Horizontal'
        {
            #Create additional row for the buttons
            $Row = New-Object Windows.Controls.RowDefinition
            $Row.Height = 'Auto'
            $grid.RowDefinitions.Add($Row)
            $RowIndex = 1
            $tempButton.SetValue([Windows.Controls.Grid]::RowProperty,$RowIndex)
            #create additional column for each button
            $Column = New-Object Windows.Controls.ColumnDefinition
            $Column.Width = 'Auto'
            $grid.ColumnDefinitions.Add($Column)
            $ColumnIndex = $buttonIndex
            $tempButton.SetValue([Windows.Controls.Grid]::ColumnProperty,$ColumnIndex)
        }
    }
    $tempButton.MinHeight = 10
    $tempButton.Margin = '5,5,5,5'
    $tempButton.Measure($wpfSize)
    $buttonheights += $tempButton.desiredSize.Height
    $buttonwidths += $tempButton.desiredSize.Width
    $buttonIndex++
  }
  $buttonHeight = ($buttonHeights | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum)
  Write-Verbose -Message "Button Height is $buttonHeight"
  $buttonWidth = ($buttonWidths| Measure-Object -Maximum | Select-Object -ExpandProperty Maximum) + 10
  Write-Verbose -Message "Button Width is $buttonWidth"
  $buttons = Get-Variable -Name 'buttonControl*' -Scope local -ValueOnly
  $buttonIndex = 0
  foreach ($button in $buttons)
  {
    $button.Height = $buttonHeight
    $button.Width = $buttonWidth
    $grid.AddChild($button)
    if ($buttonIndex -eq $DefaultChoice)
    {
        $null = $button.focus()
    }
    $buttonIndex++
  }
  # Add the elements to the relevant parent control
  $Grid.AddChild($label)
  $window.Content = $Grid
  #EndRegion BuildWPFWindow
  # Show the window
    
  if ($window.ShowDialog())
  {
    if ($ReturnChoice)
    {
        $cindex = Get-ArrayIndexForValue -array $possiblechoices -value $Script:UserChoice -property ChoiceWithEnumerator
        $possiblechoices[$cindex].ChoiceText
    } 
    else
    {
        Get-ArrayIndexForValue -array $possiblechoices -value $Script:UserChoice -property ChoiceWithEnumerator
    }
  }
}#Read-Choice
function Read-FolderBrowserDialog
{# Show an Open Folder Dialog and return the directory selected by the user. 
  [cmdletbinding()]
    Param(
        [string]$Description
        ,
        [string]$InitialDirectory
        ,
        [string]$RootDirectory
        ,
        [switch]$NoNewFolderButton
    )
    Add-Type -AssemblyName System.Windows.Forms
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($NoNewFolderButton) {$FolderBrowserDialog.ShowNewFolderButton = $false}
    if ($PSBoundParameters.ContainsKey('Description')) {$FolderBrowserDialog.Description = $Description}
    if ($PSBoundParameters.ContainsKey('InitialDirectory')) {$FolderBrowserDialog.SelectedPath = $InitialDirectory}
    if ($PSBoundParameters.ContainsKey('RootDirectory')) {$FolderBrowserDialog.RootFolder = $RootDirectory}
    $Result = $FolderBrowserDialog.ShowDialog()
    switch ($Result)
    {
        'OK'
        {
            $folder = $FolderBrowserDialog.SelectedPath
            Write-Output -InputObject $folder
        }
        'Cancel'
        {
        }
    }
    $FolderBrowserDialog.Dispose()
    Remove-Variable -Name FolderBrowserDialog
}#Read-FolderBrowswerDialog
Function New-DynamicParameter
{
    <#
        .SYNOPSIS
            Helper function to simplify creating dynamic parameters
        
        .DESCRIPTION
            Helper function to simplify creating dynamic parameters

            Example use cases:
                Include parameters only if your environment dictates it
                Include parameters depending on the value of a user-specified parameter
                Provide tab completion and intellisense for parameters, depending on the environment

            Please keep in mind that all dynamic parameters you create will not have corresponding variables created.
            One of the examples illustrates a generic method for populating appropriate variables from dynamic parameters
            Alternatively, manually reference $PSBoundParameters for the dynamic parameter value

        .NOTES
            Credit to http://jrich523.wordpress.com/2013/05/30/powershell-simple-way-to-add-dynamic-parameters-to-advanced-function/
            https://raw.githubusercontent.com/RamblingCookieMonster/PowerShell/master/New-DynamicParam.ps1
            MIT License
            Copyright (c) 2016 Warren Frame

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

        .PARAMETER Name
            Name of the dynamic parameter

        .PARAMETER Type
            Type for the dynamic parameter.  Default is string

        .PARAMETER Alias
            If specified, one or more aliases to assign to the dynamic parameter

        .PARAMETER ValidateSet
            If specified, set the ValidateSet attribute of this dynamic parameter

        .PARAMETER Mandatory
            If specified, set the Mandatory attribute for this dynamic parameter

        .PARAMETER ParameterSetName
            If specified, set the ParameterSet attribute for this dynamic parameter

        .PARAMETER Position
            If specified, set the Position attribute for this dynamic parameter

        .PARAMETER ValueFromPipelineByPropertyName
            If specified, set the ValueFromPipelineByPropertyName attribute for this dynamic parameter

        .PARAMETER HelpMessage
            If specified, set the HelpMessage for this dynamic parameter
        
        .PARAMETER DPDictionary
            If specified, add resulting RuntimeDefinedParameter to an existing RuntimeDefinedParameterDictionary (appropriate for multiple dynamic parameters)
            If not specified, create and return a RuntimeDefinedParameterDictionary (appropriate for a single dynamic parameter)

            See final example for illustration

        .EXAMPLE
            
            function Show-Free
            {
                [CmdletBinding()]
                Param()
                DynamicParam {
                    $options = @( gwmi win32_volume | %{$_.driveletter} | sort )
                    New-DynamicParam -Name Drive -ValidateSet $options -Position 0 -Mandatory
                }
                begin{
                    #have to manually populate
                    $drive = $PSBoundParameters.drive
                }
                process{
                    $vol = gwmi win32_volume -Filter "driveletter='$drive'"
                    "{0:N2}% free on {1}" -f ($vol.Capacity / $vol.FreeSpace),$drive
                }
            } #Show-Free

            Show-Free -Drive <tab>

        # This example illustrates the use of New-DynamicParam to create a single dynamic parameter
        # The Drive parameter ValidateSet populates with all available volumes on the computer for handy tab completion / intellisense

        .EXAMPLE

        # I found many cases where I needed to add more than one dynamic parameter
        # The DPDictionary parameter lets you specify an existing dictionary
        # The block of code in the Begin block loops through bound parameters and defines variables if they don't exist

            Function Test-DynPar{
                [cmdletbinding()]
                param(
                    [string[]]$x = $Null
                )
                DynamicParam
                {
                    #Create the RuntimeDefinedParameterDictionary
                    $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
            
                    New-DynamicParam -Name AlwaysParam -ValidateSet @( gwmi win32_volume | %{$_.driveletter} | sort ) -DPDictionary $Dictionary

                    #Add dynamic parameters to $dictionary
                    if($x -eq 1)
                    {
                        New-DynamicParam -Name X1Param1 -ValidateSet 1,2 -mandatory -DPDictionary $Dictionary
                        New-DynamicParam -Name X1Param2 -DPDictionary $Dictionary
                        New-DynamicParam -Name X3Param3 -DPDictionary $Dictionary -Type DateTime
                    }
                    else
                    {
                        New-DynamicParam -Name OtherParam1 -Mandatory -DPDictionary $Dictionary
                        New-DynamicParam -Name OtherParam2 -DPDictionary $Dictionary
                        New-DynamicParam -Name OtherParam3 -DPDictionary $Dictionary -Type DateTime
                    }
            
                    #return RuntimeDefinedParameterDictionary
                    $Dictionary
                }
                Begin
                {
                    #This standard block of code loops through bound parameters...
                    #If no corresponding variable exists, one is created
                        #Get common parameters, pick out bound parameters not in that set
                        Function _temp { [cmdletbinding()] param() }
                        $BoundKeys = $PSBoundParameters.keys | Where-Object { (get-command _temp | select -ExpandProperty parameters).Keys -notcontains $_}
                        foreach($param in $BoundKeys)
                        {
                            if (-not ( Get-Variable -name $param -scope 0 -ErrorAction SilentlyContinue ) )
                            {
                                New-Variable -Name $Param -Value $PSBoundParameters.$param
                                Write-Verbose "Adding variable for dynamic parameter '$param' with value '$($PSBoundParameters.$param)'"
                            }
                        }

                    #Appropriate variables should now be defined and accessible
                        Get-Variable -scope 0
                }
            }

        # This example illustrates the creation of many dynamic parameters using New-DynamicParam
            # You must create a RuntimeDefinedParameterDictionary object ($dictionary here)
            # To each New-DynamicParam call, add the -DPDictionary parameter pointing to this RuntimeDefinedParameterDictionary
            # At the end of the DynamicParam block, return the RuntimeDefinedParameterDictionary
            # Initialize all bound parameters using the provided block or similar code

        .FUNCTIONALITY
            PowerShell Language

    #>
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [string]
        $Name
        ,
        [System.Type]
        $Type = [string]
        ,
        [string[]]
        $Alias = @()
        ,
        [string[]]
        $ValidateSet
        ,
        [bool]
        $Mandatory = $true
        ,
        [string]
        $ParameterSetName="__AllParameterSets"
        ,
        [int]
        $Position
        ,
        [switch]
        $ValueFromPipelineByPropertyName
        ,
        [string]
        $HelpMessage
        ,
        $DPDictionary
    )
    #Create attribute object, add attributes, add to collection   
        $ParamAttr = New-Object System.Management.Automation.ParameterAttribute
        $ParamAttr.ParameterSetName = $ParameterSetName
        if($mandatory)
        {
            $ParamAttr.Mandatory = $True
        }
        if($Position -ne $null)
        {
            $ParamAttr.Position=$Position
        }
        if($ValueFromPipelineByPropertyName)
        {
            $ParamAttr.ValueFromPipelineByPropertyName = $True
        }
        if($HelpMessage)
        {
            $ParamAttr.HelpMessage = $HelpMessage
        }

        $AttributeCollection = New-Object 'Collections.ObjectModel.Collection[System.Attribute]'
        $AttributeCollection.Add($ParamAttr)
    
    #param validation set if specified
        if($ValidateSet)
        {
            $ParamOptions = New-Object System.Management.Automation.ValidateSetAttribute -ArgumentList $ValidateSet
            $AttributeCollection.Add($ParamOptions)
        }
    #Aliases if specified
        if($Alias.count -gt 0) {
            $ParamAlias = New-Object System.Management.Automation.AliasAttribute -ArgumentList $Alias
            $AttributeCollection.Add($ParamAlias)
        }

 
    #Create the dynamic parameter
        $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)
    
    #Add the dynamic parameter to an existing dynamic parameter dictionary, or create the dictionary and add it
    if(-not $null -eq $DPDictionary)
    {
        Write-Verbose -Message "Using Existing DPDictionary"
        $DPDictionary.Add($Name, $Parameter)
        Write-Output -InputObject $DPDictionary
    }
    else
    {
        Write-Verbose -Message "Creating New DPDictionary"
        $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $Dictionary.Add($Name, $Parameter)
        Write-Output -inputobject $Dictionary
    }
}
#end function New-DynamicParameter
function Set-DynamicParameterVariable
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory)]
            [System.Management.Automation.RuntimeDefinedParameterDictionary]$dictionary
        )
        foreach ($p in $Dictionary.Keys)
        {
            Set-Variable -Name $p -Value $Dictionary.$p.value -Scope 1
            #Write-Verbose "Adding/Setting variable for dynamic parameter '$p' with value '$($PSBoundParameters.$p)'"
        }
    }
#end function Set-DynamicParameterVariable
Function Get-CommonParameter
    {
        [cmdletbinding(SupportsShouldProcess)]
        param()
        $MyInvocation.MyCommand.Parameters.Keys
    }
function Get-AllParameters
    {
        [cmdletbinding()]
        param
        (
            $BoundParameters
            ,
            $AllParameters
            ,
            [switch]$IncludeCommon
        )
        $AllKeys = $($AllParameters.Keys ; $BoundParameters.Keys)
        $allKeys = $AllKeys | Sort-Object -Unique
        if ($IncludeCommon -ne $true)
        {
            $allKeys = $AllKeys | Where-Object -FilterScript {$_ -notin @(Get-CommonParameter)}
        }
        Write-Output -InputObject $AllKeys
    }
function Get-AllParametersWithAValue
    {
        [cmdletbinding()]
        param
        (
            $BoundParameters
            ,
            $AllParameters
            ,
            [switch]$IncludeCommon
            ,
            $Scope = 1
        )
        $getAllParametersParams = @{
            BoundParameters = $BoundParameters
            AllParameters = $AllParameters
        }
        if ($IncludeCommon -eq $true) {$getAllParametersParams.IncludeCommon = $true}
        $allParameterKeys = Get-AllParameters @getAllParametersParams
        $AllParametersWithAValue = @(
            foreach ($k in $allParameterKeys)
            {
                try
                {
                    Get-Variable -Name $k -Scope $Scope -ErrorAction Stop | Where-Object -FilterScript {$null -ne $_.Value -and -not [string]::IsNullOrWhiteSpace($_.Value)}
                }
                catch
                {
                    #don't care if a particular variable is not found
                }
            }
        )
        Write-Output -InputObject $AllParametersWithAValue
    }

##########################################################################################################
#Exchange Recipient Related Functions
##########################################################################################################
function Get-RecipientCmdlet
{
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
}#Get-RecipientCmdlet
function Get-ExchangeRecipient
{
[cmdletbinding()]
param(
[parameter(Mandatory)]
[string[]]$Identity
)
DynamicParam
{
    $dictionary = New-ExchangeOrganizationDynamicParameter -Mandatory -Multivalued
    Write-Output -InputObject $dictionary
}
begin
{
    Set-DynamicParameterVariable -dictionary $dictionary
    foreach ($o in $ExchangeOrganization)
    {
        if ((Connect-Exchange -ExchangeOrganization $o) -ne $true)
        {throw ("Connection to Exchange Organization $o Failed")}
    }
}
process
{
    foreach ($ID in $Identity)
    {
        $InvokeExchangeCommandParams = @{
            #ErrorAction = 'Stop'
            WarningAction = 'SilentlyContinue'
            Cmdlet = 'Get-Recipient'
            splat = @{
                Identity = $ID
                WarningAction = 'SilentlyContinue'
                #ErrorAction = 'Stop'
            }
        }
        foreach ($o in $exchangeOrganization)
        {
            $InvokeExchangeCommandParams.ExchangeOrganization = $o
            Invoke-ExchangeCommand @InvokeExchangeCommandParams
        }
    }
}#process
}

function Find-PrimarySMTPAddress
{
    [cmdletbinding()]
    Param
    (
        [parameter(mandatory = $true)]
        [Alias('EmailAddresses')]
        [string[]]$ProxyAddresses
    )
    $PrimaryAddresses = @($ProxyAddresses | Where-Object {$_ -clike 'SMTP:*'} | ForEach-Object {($_ -split ':')[1]})
    switch ($PrimaryAddresses.count) 
    {
        1 
        {
            $PrimarySMTPAddress = $PrimaryAddresses[0]
            Write-Output -InputObject $PrimarySMTPAddress
        }#1
        0 
        {
            Write-Output -InputObject $null
        }#0
        Default 
        {
            Write-Output -InputObject $false
        }#Default
    }#switch 
}
#end function Find-PrimarySMTPAddress

##########################################################################################################
#Azure AD Helper Functions
##########################################################################################################
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
                EnabledServices = @($user.Licenses.servicestatus | Select-Object -Property @{n='Service';e={$_.serviceplan.servicename}},@{n='Status';e={$_.provisioningstatus}} | where-object Status -ne 'Disabled' | Select-Object -ExpandProperty Service)
                DisabledServices = @($user.Licenses.servicestatus | Select-Object -Property @{n='Service';e={$_.serviceplan.servicename}},@{n='Status';e={$_.provisioningstatus}} | where-object Status -eq 'Disabled' | Select-Object -ExpandProperty Service)
                UsageLocation = $user.UsageLocation
                LicenseReconciliationNeeded = $user.LicenseReconciliationNeeded
            }#result
            Write-Output -InputObject $result
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
                        getresult -user $user 
                    }#try
                    catch{
                        Write-Log -message "Unable to locate MSOL User with UserPrincipalName $UPN" -ErrorLog
                        Write-Log -message $_.tostring() -ErrorLog
                    }#catch

                }#foreach
            }#UserPrincipalName
            'MSOLUserObject' {
                foreach ($user in $msoluser) {
                    getresult -user $user 
                }#foreach
            }#MSOLUserObject
        }#switch
    }#process
    end {
    }#end
}
##########################################################################################################
#Module Variables and Variable Functions
##########################################################################################################
function Get-OneShellVariable
    {
        [cmdletbinding()]
        param
        (
            [string]$Name
        )
        Try
        {
            Get-Variable -Scope Script -Name $name -ErrorAction Stop
        }
        Catch
        {
            Write-Verbose -Message "Variable $name Not Found" -Verbose
        }
    }#end function Get-OneShellVariable
function Get-OneShellVariableValue
    {
        [cmdletbinding()]
        param
        (
        [string]$Name
        )
        Try
        {
            Get-Variable -Scope Script -Name $name -ValueOnly -ErrorAction Stop
        }
        Catch
        {
            Write-Verbose -Message "Variable $name Not Found" -Verbose
        }
    }#end function Get-OneShellVariableValue
function Set-OneShellVariable
    {
        [cmdletbinding()]
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
        [cmdletbinding()]
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
        [cmdletbinding()]
        param
        (
            [string]$Name
        )
        Remove-Variable -Scope Script -Name $name
    }
function Set-OneShellVariables
    {
        [cmdletbinding()]
        Param()
        #Write-Log -message 'Setting OneShell Module Variables'
        $Script:OneShellModuleFolderPath = $PSScriptRoot #Split-Path $((Get-Module -ListAvailable -Name OneShell).Path)
        $script:OneShellOrgProfilePath = @(Join-Path $env:ProgramData OneShell)
        <#    [string]$Script:E4_SkuPartNumber = 'ENTERPRISEWITHSCAL' 
        [string]$Script:E3_SkuPartNumber = 'ENTERPRISEPACK' 
        [string]$Script:E2_SkuPartNumber = 'STANDARDWOFFPACK' #Non-Profit SKU
        [string]$Script:E1_SkuPartNumber = 'STANDARDPACK'
        [string]$Script:K1_SkuPartNumber = 'DESKLESSPACK' #>
        $Script:LogPreference = $True
        #AdvancedOneShell needs updated for the following:
        $Script:ScalarADAttributes = @(
            'altRecipient'
            'c'
            'CanonicalName'
            'city'
            'cn'
            'co'
            'country'
            'company'
            'deliverandRedirect'
            'department'
            'displayName'
            'DistinguishedName'
            'employeeID'
            'employeeNumber'
            'enabled'
            'extensionattribute1'
            'extensionattribute10'
            'extensionattribute11'
            'extensionattribute12'
            'extensionattribute13'
            'extensionattribute14'
            'extensionattribute15'
            'extensionattribute2'
            'extensionattribute3'
            'extensionattribute4'
            'extensionattribute5'
            'extensionattribute6'
            'extensionattribute7'
            'extensionattribute8'
            'extensionattribute9'
            'forwardingAddress'
            'GivenName'
            'homeMDB'
            'homeMTA'
            'legacyExchangeDN'
            'Mail'
            'mailNickname'
            'mS-DS-ConsistencyGuid'
            'msExchArchiveGUID'
            'msExchArchiveName'
            'msExchGenericForwardingAddress'
            'msExchHideFromAddressLists'
            'msExchHomeServerName'
            'msExchMailboxGUID'
            'msExchMasterAccountSID'
            'msExchRecipientDisplayType'
            'msExchRecipientTypeDetails'
            'msExchRemoteRecipientType'
            'msExchUsageLocation'
            'msExchUserCulture'
            'msExchVersion'
            'msExchWhenMailboxCreated'
            'notes'
            'ObjectGUID'
            'physicalDeliveryOfficeName'
            'SamAccountName'
            'SurName'
            'targetAddress'
            'userPrincipalName'
            'whenChanged'
            'whenCreated'
            'AccountExpirationDate'
            'LastLogonDate'
            'createTimeStamp'
            'modifyTimeStamp'
        )#Scalar Attributes to Retrieve
        $Script:MultiValuedADAttributes = @(
            'memberof'
            'msexchextensioncustomattribute1'
            'msexchextensioncustomattribute2'
            'msexchextensioncustomattribute3'
            'msexchextensioncustomattribute4'
            'msexchextensioncustomattribute5'
            'msExchPoliciesExcluded'
            'proxyAddresses'
        )#MultiValuedADAttributesToRetrieve
        $Script:ADUserAttributes = @($script:ScalarADAttributes + $Script:MultiValuedADAttributes)
        $Script:ADContactAttributes = @('CanonicalName','CN','Created','createTimeStamp','Deleted','Description','DisplayName','DistinguishedName','givenName','instanceType','internetEncoding','isDeleted','LastKnownParent','legacyExchangeDN','mail','mailNickname','mAPIRecipient','memberOf','Modified','modifyTimeStamp','msExchADCGlobalNames','msExchALObjectVersion','msExchPoliciesExcluded','Name','ObjectCategory','ObjectClass','ObjectGUID','ProtectedFromAccidentalDeletion','proxyAddresses','showInAddressBook','sn','targetAddress','textEncodedORAddress','uSNChanged','uSNCreated','whenChanged','whenCreated')
        $Script:ADGroupAttributes = $Script:ADUserAttributes |  Where-Object {$_ -notin ('surName','country','homeMDB','homeMTA','msExchHomeServerName')}
        $Script:ADPublicFolderAttributes = $Script:ADUserAttributes |  Where-Object {$_ -notin ('surName','country','homeMDB','homeMTA','msExchHomeServerName')}
        $Script:ADGroupAttributesWMembership = $Script:ADGroupAttributes + 'Members' 
        $Script:Stamp = Get-TimeStamp
    }
##########################################################################################################
#Import functions from included ps1 files
##########################################################################################################
#. $(Join-Path $PSScriptRoot 'ProfileWizardFunctions.ps1')
. $(Join-Path $PSScriptRoot 'UtilityFunctions.ps1')
. $(Join-Path $PSScriptRoot 'SystemConnectionFunctions.ps1')
. $(Join-Path $PSScriptRoot 'ProfileFunctions.ps1')
. $(Join-Path $PSScriptRoot 'TestFunctions.ps1')
. $(Join-Path $PSScriptRoot 'ActiveDirectoryFunctions.ps1')
##########################################################################################################
#Initialization
##########################################################################################################
Set-OneShellVariables
#Do one of the following in your profile or run script:
#Initialize-AdminEnvironment -showmenu or Initialize-AdminEnvironment -OrgProfileIdentity <value> -AdminUserProfileIdentity <value>
