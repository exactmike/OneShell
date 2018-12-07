function Update-OneShellServiceType
{
    [CmdletBinding()]
    param(
        [parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-Path -Path $_ })]
        [string[]]$Path
    )
    Begin
    {
        $ServiceTypeFiles = @(Get-ChildItem -Path $Script:ServiceTypesDirectory -Filter '*.json' -Recurse)
    }
    Process
    {
        $ServiceTypeFiles += $(
            foreach ($p in $Path)
            {
                $item = Get-Item -Path $p
                switch ($item.PSIsContainer)
                {
                    $true
                    {
                        Get-ChildItem -Path $p -Filter '*.json' -Recurse
                    }
                    $false
                    {
                        if ($item.FullName -like '*.json')
                        {
                            $item
                        }
                    }
                }
            }
        )
    }
    End
    {
        $Script:ServiceTypes = @(
            foreach ($stf in $ServiceTypeFiles)
            {
                import-JSON -Path $stf.fullname -ErrorAction Stop # need to add a uniqueness detection for overrides / prevention of duplicate types
            }
        )
    }

}
function Remove-Member
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipeline)]
        [psobject[]]$Object
        ,
        [parameter(Mandatory)]
        [string]$Member
    )
    begin {}
    process
    {
        foreach ($o in $Object)
        {
            $o.psobject.Members.Remove($Member)
        }
    }
}
#end function Remove-Member
function Join-Object
{
    <#
        .SYNOPSIS
            Join data from two sets of objects based on a common value

        .DESCRIPTION
            Join data from two sets of objects based on a common value

            For more details, see the accompanying blog post:
                http://ramblingcookiemonster.github.io/Join-Object/

            For even more details,  see the original code and discussions that this borrows from:
                Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections
                Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

        .PARAMETER Left
            'Left' collection of objects to join.  You can use the pipeline for Left.

            The objects in this collection should be consistent.
            We look at the properties on the first object for a baseline.

        .PARAMETER Right
            'Right' collection of objects to join.

            The objects in this collection should be consistent.
            We look at the properties on the first object for a baseline.

        .PARAMETER LeftJoinProperty
            Property on Left collection objects that we match up with RightJoinProperty on the Right collection

        .PARAMETER RightJoinProperty
            Property on Right collection objects that we match up with LeftJoinProperty on the Left collection

        .PARAMETER LeftProperties
            One or more properties to keep from Left.  Default is to keep all Left properties (*).

            Each property can:
                - Be a plain property name like "Name"
                - Contain wildcards like "*"
                - Be a hashtable like @{Name="Product Name";Expression={$_.Name}}.
                    Name is the output property name
                    Expression is the property value ($_ as the current object)

                    Alternatively, use the Suffix or Prefix parameter to avoid collisions
                    Each property using this hashtable syntax will be excluded from suffixes and prefixes

        .PARAMETER RightProperties
            One or more properties to keep from Right.  Default is to keep all Right properties (*).

            Each property can:
                - Be a plain property name like "Name"
                - Contain wildcards like "*"
                - Be a hashtable like @{Name="Product Name";Expression={$_.Name}}.
                    Name is the output property name
                    Expression is the property value ($_ as the current object)

                    Alternatively, use the Suffix or Prefix parameter to avoid collisions
                    Each property using this hashtable syntax will be excluded from suffixes and prefixes

        .PARAMETER Prefix
            If specified, prepend Right object property names with this prefix to avoid collisions

            Example:
                Property Name                   = 'Name'
                Suffix                          = 'j_'
                Resulting Joined Property Name  = 'j_Name'

        .PARAMETER Suffix
            If specified, append Right object property names with this suffix to avoid collisions

            Example:
                Property Name                   = 'Name'
                Suffix                          = '_j'
                Resulting Joined Property Name  = 'Name_j'

        .PARAMETER Type
            Type of join.  Default is AllInLeft.

            AllInLeft will have all elements from Left at least once in the output, and might appear more than once
            if the where clause is true for more than one element in right, Left elements with matches in Right are
            preceded by elements with no matches.
            SQL equivalent: outer left join (or simply left join)

            AllInRight is similar to AllInLeft.

            OnlyIfInBoth will cause all elements from Left to be placed in the output, only if there is at least one
            match in Right.
            SQL equivalent: inner join (or simply join)

            AllInBoth will have all entries in right and left in the output. Specifically, it will have all entries
            in right with at least one match in left, followed by all entries in Right with no matches in left,
            followed by all entries in Left with no matches in Right.
            SQL equivalent: full join

        .EXAMPLE
            #
            #Define some input data.

            $l = 1..5 | Foreach-Object {
                [pscustomobject]@{
                    Name = "jsmith$_"
                    Birthday = (Get-Date).adddays(-1)
                }
            }

            $r = 4..7 | Foreach-Object{
                [pscustomobject]@{
                    Department = "Department $_"
                    Name = "Department $_"
                    Manager = "jsmith$_"
                }
            }

            #We have a name and Birthday for each manager, how do we find their department, using an inner join?
            Join-Object -Left $l -Right $r -LeftJoinProperty Name -RightJoinProperty Manager -Type OnlyIfInBoth -RightProperties Department


                # Name    Birthday             Department
                # ----    --------             ----------
                # jsmith4 4/14/2015 3:27:22 PM Department 4
                # jsmith5 4/14/2015 3:27:22 PM Department 5

        .EXAMPLE
            #
            #Define some input data.

            $l = 1..5 | Foreach-Object {
                [pscustomobject]@{
                    Name = "jsmith$_"
                    Birthday = (Get-Date).adddays(-1)
                }
            }

            $r = 4..7 | Foreach-Object{
                [pscustomobject]@{
                    Department = "Department $_"
                    Name = "Department $_"
                    Manager = "jsmith$_"
                }
            }

            #We have a name and Birthday for each manager, how do we find all related department data, even if there are conflicting properties?
            $l | Join-Object -Right $r -LeftJoinProperty Name -RightJoinProperty Manager -Type AllInLeft -Prefix j_

                # Name    Birthday             j_Department j_Name       j_Manager
                # ----    --------             ------------ ------       ---------
                # jsmith1 4/14/2015 3:27:22 PM
                # jsmith2 4/14/2015 3:27:22 PM
                # jsmith3 4/14/2015 3:27:22 PM
                # jsmith4 4/14/2015 3:27:22 PM Department 4 Department 4 jsmith4
                # jsmith5 4/14/2015 3:27:22 PM Department 5 Department 5 jsmith5

        .EXAMPLE
            #
            #Hey!  You know how to script right?  Can you merge these two CSVs, where Path1's IP is equal to Path2's IP_ADDRESS?

            #Get CSV data
            $s1 = Import-CSV $Path1
            $s2 = Import-CSV $Path2

            #Merge the data, using a full outer join to avoid omitting anything, and export it
            Join-Object -Left $s1 -Right $s2 -LeftJoinProperty IP_ADDRESS -RightJoinProperty IP -Prefix 'j_' -Type AllInBoth |
                Export-CSV $MergePath -NoTypeInformation

        .EXAMPLE
            #
            # "Hey Warren, we need to match up SSNs to Active Directory users, and check if they are enabled or not.
            #  I'll e-mail you an unencrypted CSV with all the SSNs from gmail, what could go wrong?"

            # Import some SSNs.
            $SSNs = Import-CSV -Path D:\SSNs.csv

            #Get AD users, and match up by a common value, samaccountname in this case:
            Get-ADUser -Filter "samaccountname -like 'wframe*'" |
                Join-Object -LeftJoinProperty samaccountname -Right $SSNs `
                            -RightJoinProperty samaccountname -RightProperties ssn `
                            -LeftProperties samaccountname, enabled, objectclass

        .NOTES
            This borrows from:
                Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections/
                Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

            Changes:
                Always display full set of properties
                Display properties in order (left first, right second)
                If specified, add suffix or prefix to right object property names to avoid collisions
                Use a hashtable rather than ordereddictionary (avoid case sensitivity)

        .LINK
            http://ramblingcookiemonster.github.io/Join-Object/

        .FUNCTIONALITY
            PowerShell Language

        #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeLine = $true)]
        [object[]] $Left,

        # List to join with $Left
        [Parameter(Mandatory = $true)]
        [object[]] $Right,

        [Parameter(Mandatory = $true)]
        [string] $LeftJoinProperty,

        [Parameter(Mandatory = $true)]
        [string] $RightJoinProperty,

        [object[]]$LeftProperties = '*',

        # Properties from $Right we want in the output.
        # Like LeftProperties, each can be a plain name, wildcard or hashtable. See the LeftProperties comments.
        [object[]]$RightProperties = '*',

        [validateset( 'AllInLeft', 'OnlyIfInBoth', 'AllInBoth', 'AllInRight')]
        [Parameter(Mandatory = $false)]
        [string]$Type = 'AllInLeft',

        [string]$Prefix,
        [string]$Suffix
    )
    Begin
    {
        function AddItemProperties($item, $properties, $hash)
        {
            if ($null -eq $item)
            {
                return
            }

            foreach ($property in $properties)
            {
                $propertyHash = $property -as [hashtable]
                if ($null -ne $propertyHash)
                {
                    $hashName = $propertyHash["name"] -as [string]
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $expressionValue = $expression.Invoke($item)[0]

                    $hash[$hashName] = $expressionValue
                }
                else
                {
                    foreach ($itemProperty in $item.psobject.Properties)
                    {
                        if ($itemProperty.Name -like $property)
                        {
                            $hash[$itemProperty.Name] = $itemProperty.Value
                        }
                    }
                }
            }
        }

        function TranslateProperties
        {
            [cmdletbinding()]
            param(
                [object[]]$Properties,
                [psobject]$RealObject,
                [string]$Side)

            foreach ($Prop in $Properties)
            {
                $propertyHash = $Prop -as [hashtable]
                if ($null -ne $propertyHash)
                {
                    $hashName = $propertyHash["name"] -as [string]
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $ScriptString = $expression.tostring()
                    if ($ScriptString -notmatch 'param\(')
                    {
                        Write-Verbose "Property '$HashName'`: Adding param(`$_) to scriptblock '$ScriptString'"
                        $Expression = [ScriptBlock]::Create("param(`$_)`n $ScriptString")
                    }

                    $Output = @{Name = $HashName; Expression = $Expression }
                    Write-Verbose "Found $Side property hash with name $($Output.Name), expression:`n$($Output.Expression | out-string)"
                    $Output
                }
                else
                {
                    foreach ($ThisProp in $RealObject.psobject.Properties)
                    {
                        if ($ThisProp.Name -like $Prop)
                        {
                            Write-Verbose "Found $Side property '$($ThisProp.Name)'"
                            $ThisProp.Name
                        }
                    }
                }
            }
        }

        function WriteJoinObjectOutput($leftItem, $rightItem, $leftProperties, $rightProperties)
        {
            $properties = @{}

            AddItemProperties $leftItem $leftProperties $properties
            AddItemProperties $rightItem $rightProperties $properties

            New-Object psobject -Property $properties
        }

        #Translate variations on calculated properties.  Doing this once shouldn't affect perf too much.
        foreach ($Prop in @($LeftProperties + $RightProperties))
        {
            if ($Prop -as [hashtable])
            {
                foreach ($variation in ('n', 'label', 'l'))
                {
                    if (-not $Prop.ContainsKey('Name') )
                    {
                        if ($Prop.ContainsKey($variation) )
                        {
                            $Prop.Add('Name', $Prop[$Variation])
                        }
                    }
                }
                if (-not $Prop.ContainsKey('Name') -or $Prop['Name'] -like $null )
                {
                    Throw "Property is missing a name`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }


                if (-not $Prop.ContainsKey('Expression') )
                {
                    if ($Prop.ContainsKey('E') )
                    {
                        $Prop.Add('Expression', $Prop['E'])
                    }
                }

                if (-not $Prop.ContainsKey('Expression') -or $Prop['Expression'] -like $null )
                {
                    Throw "Property is missing an expression`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }
            }
        }

        $leftHash = @{}
        $rightHash = @{}

        # Hashtable keys can't be null; we'll use any old object reference as a placeholder if needed.
        $nullKey = New-Object psobject

        $bound = $PSBoundParameters.keys -contains "InputObject"
        if (-not $bound)
        {
            [System.Collections.ArrayList]$LeftData = @()
        }
    }
    Process
    {
        #We pull all the data for comparison later, no streaming
        if ($bound)
        {
            $LeftData = $Left
        }
        Else
        {
            foreach ($Object in $Left)
            {
                [void]$LeftData.add($Object)
            }
        }
    }
    End
    {
        foreach ($item in $Right)
        {
            $key = $item.$RightJoinProperty

            if ($null -eq $key)
            {
                $key = $nullKey
            }

            $bucket = $rightHash[$key]

            if ($null -eq $bucket)
            {
                $bucket = New-Object System.Collections.ArrayList
                $rightHash.Add($key, $bucket)
            }

            $null = $bucket.Add($item)
        }

        foreach ($item in $LeftData)
        {
            $key = $item.$LeftJoinProperty

            if ($null -eq $key)
            {
                $key = $nullKey
            }

            $bucket = $leftHash[$key]

            if ($null -eq $bucket)
            {
                $bucket = New-Object System.Collections.ArrayList
                $leftHash.Add($key, $bucket)
            }

            $null = $bucket.Add($item)
        }

        $LeftProperties = TranslateProperties -Properties $LeftProperties -Side 'Left' -RealObject $LeftData[0]
        $RightProperties = TranslateProperties -Properties $RightProperties -Side 'Right' -RealObject $Right[0]

        #I prefer ordered output. Left properties first.
        [string[]]$AllProps = $LeftProperties

        #Handle prefixes, suffixes, and building AllProps with Name only
        $RightProperties = foreach ($RightProp in $RightProperties)
        {
            if (-not ($RightProp -as [Hashtable]))
            {
                Write-Verbose "Transforming property $RightProp to $Prefix$RightProp$Suffix"
                @{
                    Name       = "$Prefix$RightProp$Suffix"
                    Expression = [scriptblock]::create("param(`$_) `$_.'$RightProp'")
                }
                $AllProps += "$Prefix$RightProp$Suffix"
            }
            else
            {
                Write-Verbose "Skipping transformation of calculated property with name $($RightProp.Name), expression:`n$($RightProp.Expression | out-string)"
                $AllProps += [string]$RightProp["Name"]
                $RightProp
            }
        }

        $AllProps = $AllProps | Select-Object -Unique

        Write-Verbose "Combined set of properties: $($AllProps -join ', ')"

        foreach ( $entry in $leftHash.GetEnumerator() )
        {
            $key = $entry.Key
            $leftBucket = $entry.Value

            $rightBucket = $rightHash[$key]

            if ($null -eq $rightBucket)
            {
                if ($Type -eq 'AllInLeft' -or $Type -eq 'AllInBoth')
                {
                    foreach ($leftItem in $leftBucket)
                    {
                        WriteJoinObjectOutput $leftItem $null $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            }
            else
            {
                foreach ($leftItem in $leftBucket)
                {
                    foreach ($rightItem in $rightBucket)
                    {
                        WriteJoinObjectOutput $leftItem $rightItem $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            }
        }

        if ($Type -eq 'AllInRight' -or $Type -eq 'AllInBoth')
        {
            foreach ($entry in $rightHash.GetEnumerator())
            {
                $key = $entry.Key
                $rightBucket = $entry.Value

                $leftBucket = $leftHash[$key]

                if ($null -eq $leftBucket)
                {
                    foreach ($rightItem in $rightBucket)
                    {
                        WriteJoinObjectOutput $null $rightItem $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            }
        }
    }
}
#end function Join-Object
function Update-ExistingObjectFromMultivaluedAttribute
{
    [CmdletBinding()]
    param
    (
        $ParentObject
        ,
        $ChildObject
        ,
        $MultiValuedAttributeName
        ,
        $IdentityAttributeName
    )
    $index = Get-ArrayIndexForValue -array $ParentObject.$MultiValuedAttributeName -value $ChildObject.$IdentityAttributeName -property $IdentityAttributeName
    $ParentObject.$MultiValuedAttributeName[$index] = $ChildObject
    $ParentObject
}
#end function Update-ExistingObjectFromMultivaluedAttribute
function Remove-ExistingObjectFromMultivaluedAttribute
{
    [CmdletBinding()]
    param
    (
        $ParentObject
        ,
        $ChildObject
        ,
        $MultiValuedAttributeName
        ,
        $IdentityAttributeName
    )
    $index = Get-ArrayIndexForValue -array $ParentObject.$MultiValuedAttributeName -value $ChildObject.$IdentityAttributeName -property $IdentityAttributeName
    $originalChildObjectContainer = @($ParentObject.$MultiValuedAttributeName)
    $newChildObjectContainer = @($originalChildObjectContainer | Where-Object -FilterScript {$_.Identity -ne $originalChildObjectContainer[$index].$IdentityAttributeName})
    $ParentObject.$MultiValuedAttributeName = $newChildObjectContainer
    $ParentObject
}
#end function Remove-ExistingObjectFromMultivaluedAttribute
function Import-JSON
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [ValidateScript( {Test-Path -Path $_})]
        $Path
        ,
        [parameter()]
        [validateSet('Unicode', 'UTF7', 'UTF8', 'ASCII', 'UTF32', 'BigEndianUnicode', 'Default', 'OEM')]
        $Encoding
    )
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
    end
    {
        $GetContentParams = @{
            Path = $Path
            Raw  = $true
        }
        if ($null -ne $Encoding)
        {$GetContentParams.Encoding = $Encoding}
        try
        {
            $Content = Get-Content @GetContentParams
        }
        catch
        {
            $_
        }
        if ($null -eq $content -or $content.Length -lt 1)
        {
            throw("No content found in file $Path")
        }
        else
        {
            ConvertFrom-Json -InputObject $Content
        }
    }
}
#end function Import-JSON
function Get-ArrayIndexForValue
{
    [cmdletbinding()]
    param(
        [parameter(mandatory = $true)]
        $array #The array for which you want to find a value's index
        ,
        [parameter(mandatory = $true)]
        $value #The Value for which you want to find an index
        ,
        [parameter()]
        $property #The property name for the value for which you want to find an index
    )
    if ([string]::IsNullOrWhiteSpace($Property))
    {
        Write-Verbose -Message 'Using Simple Match for Index'
        [array]::indexof($array, $value)
    }#if
    else
    {
        Write-Verbose -Message 'Using Property Match for Index'
        [array]::indexof($array.$property, $value)
    }#else
}
#End function Get-ArrayIndexForValue
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
#end function Get-AvailableExceptionsList
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
#end function New-ErrorRecord
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
        [ValidateScript( { $_.GetType().FullName -eq 'System.Management.Automation.PSScriptCmdlet' })]
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
            'ErrorView'                     = $null
            'FormatEnumerationLimit'        = $null
            'LogCommandHealthEvent'         = $null
            'LogCommandLifecycleEvent'      = $null
            'LogEngineHealthEvent'          = $null
            'LogEngineLifecycleEvent'       = $null
            'LogProviderHealthEvent'        = $null
            'LogProviderLifecycleEvent'     = $null
            'MaximumAliasCount'             = $null
            'MaximumDriveCount'             = $null
            'MaximumErrorCount'             = $null
            'MaximumFunctionCount'          = $null
            'MaximumHistoryCount'           = $null
            'MaximumVariableCount'          = $null
            'OFS'                           = $null
            'OutputEncoding'                = $null
            'ProgressPreference'            = $null
            'PSDefaultParameterValues'      = $null
            'PSEmailServer'                 = $null
            'PSModuleAutoLoadingPreference' = $null
            'PSSessionApplicationName'      = $null
            'PSSessionConfigurationName'    = $null
            'PSSessionOption'               = $null
            'ErrorActionPreference'         = 'ErrorAction'
            'DebugPreference'               = 'Debug'
            'ConfirmPreference'             = 'Confirm'
            'WhatIfPreference'              = 'WhatIf'
            'VerbosePreference'             = 'Verbose'
            'WarningPreference'             = 'WarningAction'
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
}
#end function Get-CallerPreference

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
        if ($recurse)
        {
            $keys = $hashtable.Keys | ForEach-Object { $_ }
            Write-Verbose -Message "Recursing $($Keys.Count) keys"
            foreach ($key in $keys)
            {
                if ($hashtable.$key -is [HashTable])
                {
                    $hashtable.$key = Convert-HashtableToObject -hashtable $hashtable.$key -Recurse # -Combine:$combine
                }
            }
        }
        if ($combine)
        {
            $output += @(New-Object -TypeName PSObject -Property $hashtable)
            Write-Verbose -Message "Combining Output = $($Output.Count) so far"
        }
        else
        {
            New-Object -TypeName PSObject -Property $hashtable
        }
    }
    END
    {
        if ($combine -and $output.Count -gt 1)
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
function Out-FileUtf8NoBom
{
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
        [Parameter(Mandatory, Position = 0)]
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
    if ($NoClobber -and (Test-Path $LiteralPath))
    {
        Throw [IO.IOException] "The file '$LiteralPath' already exists."
    }
    # Create a StreamWriter object.
    # Note that we take advantage of the fact that the StreamWriter class by default:
    # - uses UTF-8 encoding
    # - without a BOM.
    $sw = New-Object IO.StreamWriter $LiteralPath, $Append
    $htOutStringArgs = @{}
    if ($Width)
    {
        $htOutStringArgs += @{ Width = $Width }
    }
    # Note: By not using begin / process / end blocks, we're effectively running
    #       in the end block, which means that all pipeline input has already
    #       been collected in automatic variable $Input.
    #       We must use this approach, because using | Out-String individually
    #       in each iteration of a process block would format each input object
    #       with an indvidual header.
    try
    {
        $InputObject | Out-String -Stream @htOutStringArgs | ForEach-Object { $sw.WriteLine($_) }
    }
    finally
    {
        $sw.Dispose()
    }
}
Function Export-OneShellData
{
    [cmdletbinding(DefaultParameterSetName = 'delimited')]
    param(
        $ExportFolderPath = $script:ExportDataPath
        ,
        [string]$DataToExportTitle
        ,
        $DataToExport
        ,
        [parameter(ParameterSetName = 'xml/json')]
        [int]$Depth = 2
        ,
        [parameter(ParameterSetName = 'delimited')]
        [parameter(ParameterSetName = 'xml/json')]
        [ValidateSet('xml', 'csv', 'json', 'clixml')]
        [string]$DataType
        ,
        [parameter(ParameterSetName = 'delimited')]
        [switch]$Append
        ,
        [parameter(ParameterSetName = 'delimited')]
        [string]$Delimiter = ','
        ,
        [switch]$ReturnExportFilePath
        ,
        [parameter()]
        [ValidateSet('Unicode', 'BigEndianUnicode', 'Ascii', 'Default', 'UTF8', 'UTF8NOBOM', 'UTF7', 'UTF32')]
        [string]$Encoding = 'Ascii'
    )
    #Determine Export File Path
    #validate append
    if ($Append -eq $true -and $DataType -ne 'csv')
    {
        throw("-Append is not supported with data type $DataType.  It is only supported with data type 'csv'")
    }
    $stamp = GetTimeStamp
    #Build the ExportFilePath value
    switch ($DataType)
    {
        'xml'
        {
            $ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp + $DataToExportTitle + '.xml')
        }#xml
        'clixml'
        {
            $ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp + $DataToExportTitle + '.xml')
        }#xml
        'json'
        {
            $ExportFilePath = Join-Path -Path $exportFolderPath  -ChildPath $($Stamp + $DataToExportTitle + '.json')
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
                else {$ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp + $DataToExportTitle + '.csv')}#else
            }#if
            else {$ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp + $DataToExportTitle + '.csv')}#else
        }#csv
    }#switch $dataType
    #Attempt Export of Data to File
    $message = "Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath"
    Write-OneShellLog -Message $message -EntryType Attempting
    Try
    {
        $formattedData = $(
            switch ($DataType)
            {
                'xml'
                {
                    $DataToExport | ConvertTo-Xml -Depth $Depth -ErrorAction Stop -NoTypeInformation -As String
                }#xml
                'clixml'
                {
                    #$DataToExport | ConvertTo-CliXML -Depth -errorAction Stop -Encoding $Encoding #not supported in Windows PowerShell, also need to handle Encoding if UTF8NOBOM is specified
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
            LiteralPath = $ExportFilePath
        }
        switch ($Encoding)
        {
            'UTF8NOBOM'
            {
                if ($Append)
                {
                    $outFileParams.Append = $true
                    $outFileParams.InputObject = $formattedData
                }
                Out-FileUtf8NoBom @outFileParams
            }
            Default
            {
                $outFileParams.Encoding = $Encoding
                if ($DataType -eq 'clixml')
                {
                    $outFileParams.Depth = $Depth
                    $outFileParams.InputObject = $DataToExport
                    Export-Clixml @outFileParams
                }
                else
                {
                    $outFileParams.InputObject = $formattedData
                    if ($append)
                    {
                        $outFileParams.Append = $true
                    }
                    Out-File @outFileParams
                }
            }
        }
        if ($ReturnExportFilePath) {$ExportFilePath}
        Write-OneShellLog -Message $message -EntryType Succeeded
    }#try
    Catch
    {
        Write-OneShellLog -Message "FAILED: Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath" -Verbose -ErrorLog
        Write-OneShellLog -Message $_.tostring() -ErrorLog
    }#catch
}
#End Function Export-Data
Function Remove-OneShellAgedFile
{
    [cmdletbinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [int]$Days
        ,
        [parameter()]
        [validatescript( {Test-IsWriteableDirectory -Path $_})]
        [string[]]$Directory
        ,
        [switch]$Recurse
    )
    $now = Get-Date
    $daysAgo = $now.AddDays( - $days)
    $splat = @{
        File = $true
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
function New-OneShellTimer
{
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
        [validateset('Seconds', 'Minutes', 'Hours', 'Days')]
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

    switch ($units)
    {
        'Seconds' {$timespan = [timespan]::FromSeconds($length)}
        'Minutes' {$timespan = [timespan]::FromMinutes($length)}
        'Hours' {$timespan = [timespan]::FromHours($length)}
        'Days' {$timespan = [timespan]::FromDays($length)}
    }

    if ($voice)
    {
        Add-Type -AssemblyName System.speech
        $speak = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
        $speak.Rate = 3
        $speak.Volume = 100
    }

    if ($altReport.Count -ge 1)
    {
        $vrts = @()
        foreach ($vr in $altReport)
        {
            $vrt = @{}
            switch ($vr.Units)
            {
                'Seconds'
                {
                    #convert frequency units to seconds
                    $vrt.seconds = $vr.frequency
                    $vrt.frequency = $vr.frequency
                    $vrt.units = $vr.Units
                    $vrt.countdownpoint = $vr.countdownpoint
                }
                'Minutes'
                {
                    #convert frequency units to seconds
                    $vrt.seconds = $vr.frequency * 60
                    $vrt.frequency = $vrt.seconds * $vr.frequency
                    $vrt.units = $vr.units
                    $vrt.countdownpoint = $vr.countdownpoint * 60
                }
                'Hours'
                {
                    #convert frequency units to seconds
                    $vrt.seconds = $vr.frequency * 60 * 60
                    $vrt.frequency = $vrt.seconds * $vr.frequency
                    $vrt.units = $vr.units
                    $vrt.countdownpoint = $vr.countdownpoint * 60 * 60
                }
                'Days'
                {
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
    if ($delay) {New-Timer -units Seconds -length $delay -voice -showprogress -Frequency 1}
    $starttime = Get-Date
    $endtime = $starttime.AddTicks($timespan.Ticks)

    if ($showprogress)
    {
        $writeprogressparams = @{
            Activity         = "Starting Timer for $length $units"
            Status           = 'Running'
            PercentComplete  = 0
            CurrentOperation = 'Starting'
            SecondsRemaining = $timespan.TotalSeconds
        }
        Write-Progress @writeprogressparams
    }

    do
    {
        if ($nextsecond)
        {
            $nextsecond = $nextsecond.AddSeconds(1)
        }
        else {$nextsecond = $starttime.AddSeconds(1)}
        $currenttime = Get-Date
        [timespan]$remaining = $endtime - $currenttime
        $secondsremaining = if ($remaining.TotalSeconds -gt 0) {$remaining.TotalSeconds.toUint64($null)} else {0}
        if ($showprogress)
        {
            $writeprogressparams.CurrentOperation = 'Countdown'
            $writeprogressparams.SecondsRemaining = $secondsremaining
            $writeprogressparams.PercentComplete = ($secondsremaining / $timespan.TotalSeconds) * 100
            $writeprogressparams.Activity = "Running Timer for $length $units"
            Write-Progress @writeprogressparams
        }

        switch ($Units)
        {
            'Seconds'
            {
                $seconds = $Frequency
                if ($voice -and ($secondsremaining % $seconds -eq 0))
                {
                    if ($Frequency -lt 3)
                    {
                        $speak.Rate = 5
                        $speak.SpeakAsync("$secondsremaining") > $null
                    }
                    else
                    {
                        $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                    }
                }
            }
            'Minutes'
            {
                $seconds = $frequency * 60
                if ($voice -and ($secondsremaining % $seconds -eq 0))
                {
                    $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                    if ($minutesremaining -ge 1)
                    {
                        $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                    }
                    else
                    {
                        if ($secondsremaining -ge 1)
                        {
                            $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                        }
                    }
                }
            }
            'Hours'
            {
                $seconds = $frequency * 60 * 60
                if ($voice -and ($secondsremaining % $seconds -eq 0))
                {
                    $hoursremaining = $remaining.TotalHours.tostring("#.##")
                    if ($hoursremaining -ge 1)
                    {
                        $speak.SpeakAsync("$hoursremaining hours remaining") > $null
                    }
                    else
                    {
                        $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                        if ($minutesremaining -ge 1)
                        {
                            $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                        }
                        else
                        {
                            if ($secondsremaining -ge 1)
                            {
                                $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                            }
                        }
                    }
                }
            }
            'Days'
            {
                $seconds = $frequency * 24 * 60 * 60
                if ($voice -and ($secondsremaining % $seconds -eq 0))
                {
                    $daysremaining = $remaining.TotalDays.tostring("#.##")
                    if ($daysremaining -ge 1)
                    {
                        $speak.SpeakAsync("$daysremaining days remaining") > $null
                    }
                    else
                    {
                        $hoursremaining = $remaining.TotalHours.tostring("#.##")
                        if ($hoursremaining -ge 1)
                        {
                            $speak.SpeakAsync("$hoursremaining hours remaining") > $null
                        }
                        else
                        {
                            $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                            if ($minutesremaining -ge 1)
                            {
                                $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                            }
                            else
                            {
                                if ($secondsremaining -ge 1)
                                {
                                    $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                                }
                            }
                        }

                    }
                }
            }
        }
        $currentvrt = $vrts | Where-Object -FilterScript {$_.countdownpoint -ge $($secondsremaining - 1)} | Select-Object -First 1
        if ($currentvrt)
        {
            $Frequency = $currentvrt.frequency
            $Units = $currentvrt.units
            $vrts = $vrts | Where-Object -FilterScript {$_countdownpoint -ne $currentvrt.countdownpoint}
        }
        Start-Sleep -Milliseconds $($nextsecond - (get-date)).TotalMilliseconds
    }
    until ($secondsremaining -eq 0)
    if ($showprogress)
    {
        $writeprogressparams.completed = $true
        $writeprogressparams.Activity = "Completed Timer for $length $units"
        Write-Progress @writeprogressparams
    }
}
#end function New-OneShellTimer
function New-OneShellGUID {[GUID]::NewGuid()}
function Add-RequiredMember
{
    <#
    .PARAMETER RequiredMember
    An Array of strings which designate the names of the required members for the input object
    .PARAMETER InputObject
    An Array of strings which designate the names of the required members for the input object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 1)]
        [string[]]$RequiredMember
        ,
        [Parameter(Mandatory, ValueFromPipeline, Position = 2)]
        [psobject[]]$InputObject
    )
    Process
    {
        foreach ($io in $InputObject)
        {
            foreach ($rm in $RequiredMember)
            {
                if ($null -ne $rm -and -not [string]::IsNullOrEmpty($rm))
                {
                    if (-not (Test-Member -InputObject $io -Name $rm))
                    {
                        Add-Member -InputObject $io -MemberType NoteProperty -Name $rm -Value $null
                    }
                }
            }
        }
    }
}
function Get-MicrosoftAzureADTenantID
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory, Position = 1)]
        [string]$TenantSubdomain
    )
    if ($TenantSubdomain -like '*.onmicrosoft.com')
    {$TenantSubdomainFragment = $TenantSubdomain.Split('.')[0]}
    elseif ([char[]]$TenantSubdomain -notcontains '.')
    {$TenantSubdomainFragment = $TenantSubdomain}
    else
    {throw("Unexpected value provided for $TenantSubdomain")}
    Write-Verbose -Message "Calculated URI: $URI"
    $URI = 'https://login.windows.net/' + $TenantSubdomainFragment + '.onmicrosoft.com' + '/.well-known/openid-configuration'
    (Invoke-WebRequest -Uri $URI | ConvertFrom-Json).token_endpoint.Split('/')[3]
}
function ConvertFrom-FQDN
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string[]]$FQDN
    )
    process
    {
        foreach ($f in $FQDN)
        {
            “DC=$($f.replace(“.”, “,DC=”))”
        }
    }
}

function Get-ParameterSplatFromDefinition
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [psobject[]]$ParameterDefinition
        ,
        [parameter()]
        [ValidateSet('Continue','Ignore','Inquire','SilentlyContinue','Stop','Suspend')]
        [string]$ValueForErrorAction
        ,
        [parameter()]
        [ValidateSet('Continue','Ignore','Inquire','SilentlyContinue','Stop','Suspend')]
        [string]$ValueForWarningAction
    )
    Begin
    {
        $ParametersForSplatting = @{}
        if ($PSBoundParameters.ContainsKey('ValueForErrorAction'))
        {
            $ParametersForSplatting.ErrorAction = $ValueForErrorAction
        }
        if ($PSBoundParameters.ContainsKey('ValueForWarningAction'))
        {
            $ParametersForSplatting.WarningAction = $ValueForWarningAction
        }
    }
    Process
    {
        foreach ($pd in $ParameterDefinition)
        {
            $value = $(
                switch ($pd.ValueType)
                {
                    'Static'
                    {$pd.Value}
                    'ScriptBlock'
                    {
                        $ValueGeneratingScriptBlock = [scriptblock]::Create($pd.Value)
                        &$ValueGeneratingScriptBlock
                    }
                }
            )
            $ParametersForSplatting.$($pd.name) = $value
        }
    }
    End
    {
        $ParametersForSplatting
    }
}
