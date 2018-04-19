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
        [string]$Name
        ,
        [parameter()]
        [System.Type]$Type = [string]
        ,
        [parameter()]
        [string[]]$Alias = @()
        ,
        [parameter()]
        [string[]]$ValidateSet
        ,
        [parameter()]
        [bool]$ValidateNotNullOrEmpty
        ,
        [parameter()]
        [bool]$Mandatory = $true
        ,
        [parameter()]
        [string]$ParameterSetName = "__AllParameterSets"
        ,
        [parameter()]
        [int]$Position
        ,
        [parameter()]
        [bool]$ValueFromPipelineByPropertyName = $false
        ,
        [parameter()]
        [bool]$ValueFromPipeline = $false
        ,
        [parameter()]
        [string]$HelpMessage
        ,
        [parameter()]
        $DefaultValue
        ,
        [parameter()]
        $DPDictionary
    )
    $ParamAttr = New-Object System.Management.Automation.ParameterAttribute
    $ParamAttr.ParameterSetName = $ParameterSetName
    $ParamAttr.Mandatory = $Mandatory
    if ($PSBoundParameters.ContainsKey('Position'))
    {
        $ParamAttr.Position = $Position
    }
    $ParamAttr.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName
    $ParamAttr.ValueFromPipeline = $ValueFromPipeline
    if ($PSboundParameters.ContainsKey('HelpMessage'))
    {
        $ParamAttr.HelpMessage = $HelpMessage
    }

    $AttributeCollection = New-Object 'Collections.ObjectModel.Collection[System.Attribute]'
    $AttributeCollection.Add($ParamAttr)

    if ($PSBoundParameters.ContainsKey('ValidateSet'))
    {
        $ParamOptions = New-Object System.Management.Automation.ValidateSetAttribute -ArgumentList $ValidateSet
        $AttributeCollection.Add($ParamOptions)
    }
    #Aliases if specified
    if ($Alias.count -gt 0)
    {
        $ParamAlias = New-Object System.Management.Automation.AliasAttribute -ArgumentList $Alias
        $AttributeCollection.Add($ParamAlias)
    }

    #Create the dynamic parameter
    $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)

    #Set the default value #added by MC
    if (
        #$PSBoundParameters.ContainsKey($DefaultValue)
        $null -ne $DefaultValue
    )
    {
        Write-Verbose -Message "adding Default Value to Parameter $($Parameter.Name)"
        $Parameter.Value = $DefaultValue
    }

    #Add the dynamic parameter to an existing dynamic parameter dictionary, or create the dictionary and add it
    if (-not $null -eq $DPDictionary)
    {
        Write-Verbose -Message "Using Existing DPDictionary"
        $DPDictionary.Add($Name, $Parameter)
        $DPDictionary
    }
    else
    {
        Write-Verbose -Message "Creating New DPDictionary"
        $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $Dictionary.Add($Name, $Parameter)
        $Dictionary
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
    [cmdletbinding()]
    param()
    $MyInvocation.MyCommand.Parameters.Keys
}
#end function Get-CommonParameter
function Get-AllParameter
{
    [cmdletbinding()]
    param
    (
        $BoundParameters #$PSBoundParameters
        ,
        $AllParameters #$MyInvocation.MyCommand.Parameters
        ,
        [switch]$IncludeCommon
    )
    $AllKeys = $($AllParameters.Keys ; $BoundParameters.Keys)
    $AllKeys = $AllKeys | Sort-Object -Unique
    if ($IncludeCommon -ne $true)
    {
        $AllKeys = $AllKeys | Where-Object -FilterScript {$_ -notin @(Get-CommonParameter)}
    }
    $AllKeys
}
#end function Get-AllParameter
function Get-AllParametersWithAValue
{
    [cmdletbinding()]
    param
    (
        $BoundParameters #$PSBoundParameters
        ,
        $AllParameters #$MyInvocation.MyCommand.Parameters
        ,
        [switch]$IncludeCommon
        ,
        $Scope = 1
    )
    $getAllParameterParams = @{
        BoundParameters = $BoundParameters
        AllParameters   = $AllParameters
    }
    if ($IncludeCommon -eq $true) {$getAllParametersParams.IncludeCommon = $true}
    $AllParameterKeys = Get-AllParameter @getAllParameterParams
    $AllParametersWithAValue = @(
        foreach ($k in $AllParameterKeys)
        {
            try
            {
                Get-Variable -Name $k -Scope $Scope -ErrorAction Stop | Where-Object -FilterScript {$null -ne $_.Value -and -not [string]::IsNullOrWhiteSpace($_.Value)}
            }
            catch
            {
                #don't care if a particular variable is not found
                Write-Verbose -Message "$k was not found"
            }
        }
    )
    $AllParametersWithAValue
}
#end function Get-AllParametersWithAValue
