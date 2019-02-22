    Function New-ErrorRecord
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
        trap [Microsoft.PowerShell.Commands.NewObjectCommand]
        {
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

