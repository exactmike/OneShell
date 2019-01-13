    Function Test-CommandIsPresent
    {
        
    Param ([string]$command)
    Try {if (Get-Command -Name $command -ErrorAction Stop) {$true}}
    Catch {$false}

    }

