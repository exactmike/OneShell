    Function Test-IsWriteableDirectory
    {
        
    #Credits to the following:
    #http://poshcode.org/2236
    #http://stackoverflow.com/questions/9735449/how-to-verify-whether-the-share-has-write-access
    [CmdletBinding()]
    param
    (
        [parameter()]
        [ValidateScript(
            {
                $IsContainer = Test-Path -Path ($_) -PathType Container
                if ($IsContainer)
                {
                    $Item = Get-Item -Path $_
                    if ($item.PsProvider.Name -eq 'FileSystem') {$true}
                    else {$false}
                }
                else {$false}
            }
        )]
        [string]$Path
    )
    try
    {
        $testPath = Join-Path -Path $Path -ChildPath ([IO.Path]::GetRandomFileName())
        New-Item -Path $testPath -ItemType File -ErrorAction Stop > $null
        $true
    }
    catch
    {
        $false
    }
    finally
    {
        Remove-Item -Path $testPath -ErrorAction SilentlyContinue
    }

    }

