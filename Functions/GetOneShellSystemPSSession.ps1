function GetOneShellSystemPSSession
{
    [cmdletbinding()]
    param
    (
        $ServiceObject
    )
    [string]$SessionNameWildcard = $($ServiceObject.Identity) + '*'
    #$message = "Run Get-PSSession for name like $SessionNameWildcard"
    try
    {
        #Write-OneShellLog -Message $message -EntryType Attempting
        $ServiceSession = @(Get-PSSession -Name $SessionNameWildcard -ErrorAction Stop)
        #Write-OneShellLog -Message $message -EntryType Succeeded
    }
    catch
    {
        $myerror = $_
        #Write-OneShellLog -Message $message -EntryType Failed
        #Write-OneShellLog -Message $myerror.tostring() -ErrorLog
    }
    $ServiceSession
}
#end function GetOneShellSystemPSSession