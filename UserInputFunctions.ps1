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
