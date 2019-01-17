    Function Update-OneShellServiceType
    {

    [CmdletBinding()]
    param(
        [parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateScript({Test-Path -Path $_ })]
        [string[]]$Path = $Script:ServiceTypesDirectory
    )
    Begin
    {
        $ServiceTypeFiles = @(Get-ChildItem -Path $Path -Filter '*.json' -Recurse)
    }
    Process
    {
        $ServiceTypeFiles += $(
            foreach ($p in $Path)
            {
                $item = Get-Item -Path $p
                switch ($item.PSIsContainer)
                {
                    $true
                    {
                        Get-ChildItem -Path $p -Filter '*.json' -Recurse
                    }
                    $false
                    {
                        if ($item.FullName -like '*.json')
                        {
                            $item
                        }
                    }
                }
            }
        )
    }
    End
    {
        $Script:ServiceTypes = @(
            foreach ($stf in $ServiceTypeFiles)
            {
                Import-Json -Path $stf.fullname -ErrorAction Stop # need to add a uniqueness detection for overrides / prevention of duplicate types
            }
        )
    }


    }
