    Function Add-RequiredMember
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
        [AllowNull()]
        [AllowEmptyCollection()]
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

