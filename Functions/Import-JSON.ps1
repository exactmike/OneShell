    Function Import-JSON
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [ValidateScript( {Test-Path -Path $_})]
        $Path
        ,
        [parameter()]
        [validateSet('Unicode', 'UTF7', 'UTF8', 'ASCII', 'UTF32', 'BigEndianUnicode', 'Default', 'OEM')]
        $Encoding
    )
    begin
    {
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }
    end
    {
        $GetContentParams = @{
            Path = $Path
            Raw  = $true
        }
        if ($null -ne $Encoding)
        {$GetContentParams.Encoding = $Encoding}
        try
        {
            $Content = Get-Content @GetContentParams
        }
        catch
        {
            $_
        }
        if ($null -eq $content -or $content.Length -lt 1)
        {
            throw("No content found in file $Path")
        }
        else
        {
            ConvertFrom-Json -InputObject $Content
        }
    }

    }

