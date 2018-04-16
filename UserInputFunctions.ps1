function Read-PromptForChoice
{
    [cmdletbinding(DefaultParameterSetName = 'StringChoices')]
    Param(
        [string]$Message
        ,
        [Parameter(Mandatory, ParameterSetName = 'StringChoices')]
        [ValidateNotNullOrEmpty()]
        [alias('StringChoices')]
        [String[]]$Choices
        ,
        [Parameter(Mandatory, ParameterSetName = 'ObjectChoices')]
        [ValidateNotNullOrEmpty()]
        [alias('ObjectChoices')]
        [psobject[]]$ChoiceObjects
        ,
        [int]$DefaultChoice = -1
        #[int[]]$DefaultChoices = @(0)
        ,
        [string]$Title = [string]::Empty
        ,
        [Parameter(ParameterSetName = 'StringChoices')]
        [switch]$Numbered
    )
    #Build Choice Objects
    switch ($PSCmdlet.ParameterSetName)
    {
        'StringChoices'
        #Create the Choice Objects
        {
            if ($Numbered)
            {
                $choiceCount = 0
                $ChoiceObjects = @(
                    foreach ($choice in $Choices)
                    {
                        $choiceCount++
                        [PSCustomObject]@{
                            Enumerator = $choiceCount
                            Choice     = $choice
                        }
                    }
                )
            }
            else
            {
                [char[]]$choiceEnumerators = @()
                $ChoiceObjects = @(
                    foreach ($choice in $Choices)
                    {
                        $Enumerator = $null
                        foreach ($char in $choice.ToCharArray())
                        {
                            if ($char -notin $choiceEnumerators -and $char -match '[a-zA-Z]' )
                            {
                                $Enumerator = $char
                                $choiceEnumerators += $Enumerator
                                break
                            }
                        }
                        if ($null -eq $Enumerator)
                        {
                            $EnumeratorError = New-ErrorRecord -Exception System.Management.Automation.RuntimeException -ErrorId 0 -ErrorCategory InvalidData -TargetObject $choice -Message 'Unable to determine an enumerator'
                            $PSCmdlet.ThrowTerminatingError($EnumeratorError)
                        }
                        else
                        {
                            [PSCustomObject]@{
                                Enumerator = $Enumerator
                                Choice     = $choice
                            }
                        }
                    }
                )
            }
        }
        'ObjectChoices'
        #Validate the Choice Objects using the first object as a representative
        {
            if ($null -eq $ChoiceObjects[0].Enumerator -or $null -eq $ChoiceObjects[0].Choice)
            {
                $ChoiceObjectError = New-ErrorRecord -Exception System.Management.Automation.RuntimeException -ErrorId 1 -ErrorCategory InvalidData -TargetObject $ChoiceObjects[0] -Message 'Choice Object(s) do not include the required enumerator and/or choice properties'
                $PSCmdlet.ThrowTerminatingError($ChoiceObjectError)
            }
        }
    }#Switch
    [Management.Automation.Host.ChoiceDescription[]]$PossibleChoices = @(
        $ChoiceObjects | ForEach-Object {
            $Enumerator = $_.Enumerator
            $Choice = $_.Choice
            $Description = if (-not [string]::IsNullOrWhiteSpace($_.Description)) {$_.Description} else {$_.Choice}
            $ChoiceWithEnumerator = $(
                if ($Numbered)
                {
                    "&$Enumerator $($Choice)"
                }
                else
                {
                    $index = $choice.IndexOf($Enumerator)
                    if ($index -eq -1)
                    {
                        "&$Enumerator $($Choice)"
                    }
                    else
                    {
                        $choice.insert($index, '&')
                    }
                }
            )
            New-Object System.Management.Automation.Host.ChoiceDescription $ChoiceWithEnumerator, $Description
        }
    )
    $Host.UI.PromptForChoice($Title, $Message, $PossibleChoices, $DefaultChoice)
}
#End Function Read-PromptForChoice
function Read-OpenFileDialog
{
    [cmdletbinding()]
    param(
        [string]$WindowTitle
        ,
        [string]$InitialDirectory
        ,
        [string]$Filter = 'All files (*.*)|*.*'
        ,
        [switch]$AllowMultiSelect
    )
    Add-Type -AssemblyName System.Windows.Forms
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = $WindowTitle
    if ($PSBoundParameters.ContainsKey('InitialDirectory')) { $openFileDialog.InitialDirectory = $InitialDirectory }
    $openFileDialog.Filter = $Filter
    if ($AllowMultiSelect) { $openFileDialog.MultiSelect = $true }
    $openFileDialog.ShowHelp = $true
    # Without this line the ShowDialog() function may hang depending on system configuration and running from console vs. ISE.
    $result = $openFileDialog.ShowDialog()
    switch ($Result)
    {
        'OK'
        {
            if ($AllowMultiSelect)
            {
                $openFileDialog.Filenames
            }
            else
            {
                $openFileDialog.Filename
            }
        }
        'Cancel'
        {
        }
    }
    $openFileDialog.Dispose()
    Remove-Variable -Name openFileDialog
}#Read-OpenFileDialog
function Read-FolderBrowserDialog
{
    # Show an Open Folder Dialog and return the directory selected by the user.
    [cmdletbinding()]
    Param(
        [string]$Description
        ,
        [string]$InitialDirectory
        ,
        [string]$RootDirectory
        ,
        [switch]$NoNewFolderButton
    )
    Add-Type -AssemblyName System.Windows.Forms
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($NoNewFolderButton) {$FolderBrowserDialog.ShowNewFolderButton = $false}
    if ($PSBoundParameters.ContainsKey('Description')) {$FolderBrowserDialog.Description = $Description}
    if ($PSBoundParameters.ContainsKey('InitialDirectory')) {$FolderBrowserDialog.SelectedPath = $InitialDirectory}
    if ($PSBoundParameters.ContainsKey('RootDirectory')) {$FolderBrowserDialog.RootFolder = $RootDirectory}
    $Result = $FolderBrowserDialog.ShowDialog()
    switch ($Result)
    {
        'OK'
        {
            $folder = $FolderBrowserDialog.SelectedPath
            $folder
        }
        'Cancel'
        {
        }
    }
    $FolderBrowserDialog.Dispose()
    Remove-Variable -Name FolderBrowserDialog
}#Read-FolderBrowswerDialog
