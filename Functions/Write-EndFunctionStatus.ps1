    Function Write-EndFunctionStatus
    {
        
    param($CallingFunction)
    Write-OneShellLog -Message "$CallingFunction completed." -EntryType Notification

    }

