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

