    Function Select-ProfileSystem
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $Systems
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Get')]
        [string]$Operation
    )
    $message = "Select system to $Operation"
    $CredChoices = @(foreach ($s in $Systems) {"$($s.servicetype):$($s.name):$($s.Identity)"})
    #$whichone = Read-Choice -Message $message -Choices $CredChoices -DefaultChoice 0 -Title $message -Numbered -Vertical
    $whichone = Read-PromptForChoice -Message $message -Choices $CredChoices -DefaultChoice 0 -Numbered
    $systems[$whichone]

    }

