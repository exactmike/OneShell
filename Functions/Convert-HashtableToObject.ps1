    Function Convert-HashtableToObject
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

