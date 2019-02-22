Function Export-OneShellData
{
    [cmdletbinding(DefaultParameterSetName = 'delimited')]
    param(
        $ExportFolderPath = $script:ExportDataPath
        ,
        [string]$DataToExportTitle
        ,
        $DataToExport
        ,
        [parameter(ParameterSetName = 'xml/json')]
        [int]$Depth = 2
        ,
        [parameter(ParameterSetName = 'delimited')]
        [parameter(ParameterSetName = 'xml/json')]
        [ValidateSet('xml', 'csv', 'json', 'clixml')]
        [string]$DataType
        ,
        [parameter(ParameterSetName = 'delimited')]
        [switch]$Append
        ,
        [parameter(ParameterSetName = 'delimited')]
        [string]$Delimiter = ','
        ,
        [switch]$ReturnExportFilePath
        ,
        [parameter()]
        [ValidateSet('Unicode', 'BigEndianUnicode', 'Ascii', 'Default', 'UTF8', 'UTF8NOBOM', 'UTF7', 'UTF32')]
        [string]$Encoding = 'Ascii'
    )
    #Determine Export File Path
    #validate append
    if ($Append -eq $true -and $DataType -ne 'csv')
    {
        throw("-Append is not supported with data type $DataType.  It is only supported with data type 'csv'")
    }
    Function GetTimeStamp
    {
        [string]$Stamp = Get-Date -Format yyyyMMdd-HHmmss
        #$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToShortTimeString()) #check if this is faster to use than Get-Date
        $Stamp
    }
    $stamp = GetTimeStamp
    #Build the ExportFilePath value
    switch ($DataType)
    {
        'xml'
        {
            $ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp + $DataToExportTitle + '.xml')
        }#xml
        'clixml'
        {
            $ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp + $DataToExportTitle + '.xml')
        }#xml
        'json'
        {
            $ExportFilePath = Join-Path -Path $exportFolderPath  -ChildPath $($Stamp + $DataToExportTitle + '.json')
        }#json
        'csv'
        {
            if ($Append)
            {
                $mostrecent = @(get-childitem -Path $ExportFolderPath -Filter "*$DataToExportTitle.csv" | Sort-Object -Property CreationTime -Descending | Select-Object -First 1)
                if ($mostrecent.count -eq 1)
                {
                    $ExportFilePath = $mostrecent[0].fullname
                }#if
                else {$ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp + $DataToExportTitle + '.csv')}#else
            }#if
            else {$ExportFilePath = Join-Path -Path $exportFolderPath -ChildPath $($Stamp + $DataToExportTitle + '.csv')}#else
        }#csv
    }#switch $dataType
    #Attempt Export of Data to File
    $message = "Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath"
    Write-OneShellLog -Message $message -EntryType Attempting
    Try
    {
        $formattedData = $(
            switch ($DataType)
            {
                'xml'
                {
                    $DataToExport | ConvertTo-Xml -Depth $Depth -ErrorAction Stop -NoTypeInformation -As String
                }#xml
                'clixml'
                {
                    #$DataToExport | ConvertTo-CliXML -Depth -errorAction Stop -Encoding $Encoding #not supported in Windows PowerShell, also need to handle Encoding if UTF8NOBOM is specified
                }#xml
                'json'
                {
                    $DataToExport | ConvertTo-Json -Depth $Depth -ErrorAction Stop
                }#json
                'csv'
                {
                    $DataToExport | ConvertTo-Csv -ErrorAction Stop -NoTypeInformation -Delimiter $Delimiter
                }#csv
            }
        )
        $outFileParams = @{
            ErrorAction = 'Stop'
            LiteralPath = $ExportFilePath
        }
        switch ($Encoding)
        {
            'UTF8NOBOM'
            {
                if ($Append)
                {
                    $outFileParams.Append = $true
                    $outFileParams.InputObject = $formattedData
                }
                Out-FileUtf8NoBom @outFileParams
            }
            Default
            {
                $outFileParams.Encoding = $Encoding
                if ($DataType -eq 'clixml')
                {
                    $outFileParams.Depth = $Depth
                    $outFileParams.InputObject = $DataToExport
                    Export-Clixml @outFileParams
                }
                else
                {
                    $outFileParams.InputObject = $formattedData
                    if ($append)
                    {
                        $outFileParams.Append = $true
                    }
                    Out-File @outFileParams
                }
            }
        }
        if ($ReturnExportFilePath) {$ExportFilePath}
        Write-OneShellLog -Message $message -EntryType Succeeded
    }#try
    Catch
    {
        Write-OneShellLog -Message "FAILED: Export of $DataToExportTitle as Data Type $DataType to File $ExportFilePath" -Verbose -ErrorLog
        Write-OneShellLog -Message $_.tostring() -ErrorLog
    }#catch

}
