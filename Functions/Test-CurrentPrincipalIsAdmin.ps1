    Function Test-CurrentPrincipalIsAdmin
    {
        
    $currentPrincipal = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')

    }

