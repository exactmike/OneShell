    Function Test-DirectoryPath
    {
        
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$path
    )
    if (Test-Path -Path $path -PathType Container)
    {
        $item = Get-Item -Path $path
        if ($item.GetType().fullname -eq 'System.IO.DirectoryInfo')
        {$true}
        else
        {$false}
    }
    else
    {$false}

    }

