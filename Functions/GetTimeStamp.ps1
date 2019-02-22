    Function GetTimeStamp
    {
        
    [string]$Stamp = Get-Date -Format yyyyMMdd-HHmmss
    #$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToShortTimeString()) #check if this is faster to use than Get-Date
    $Stamp

    }

