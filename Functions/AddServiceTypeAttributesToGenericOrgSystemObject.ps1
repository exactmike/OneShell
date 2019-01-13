    Function AddServiceTypeAttributesToGenericOrgSystemObject
    {
        
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        $OrgSystemObject
        ,
        [parameter(Mandatory)]
        $ServiceType
        ,
        [parameter()]
        $dictionary
    )#end param
    #Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    if ($null -ne $dictionary)
    {
        Set-DynamicParameterVariable -dictionary $dictionary
    }
    $ServiceTypeDefinition = Get-OneShellServiceTypeDefinition -ServiceType $ServiceType
    Write-Verbose -Message "Using ServiceTypeDefinition $($ServiceTypeDefinition.name)"
    if ($null -ne $ServiceTypeDefinition.ServiceTypeAttributes.System -and $ServiceTypeDefinition.ServiceTypeAttributes.System.count -ge 1)
    {
        foreach ($a in $ServiceTypeDefinition.ServiceTypeAttributes.System.name)
        {
            $Value = $(Get-Variable -Name $a -Scope Local).Value
            Write-Verbose -Message "Value for $a is $($value -join ',')"
            $OrgSystemObject.ServiceTypeAttributes | Add-Member -MemberType NoteProperty -Name $a -Value $Value
        }
    }
    $OrgSystemObject

    }

