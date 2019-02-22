    Function Select-Profile
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [pscustomobject[]]$Profiles
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Associate', 'Get', 'Use')]
        [string]$Operation
    )
    $message = "Select profile to $Operation"
    $Choices = @(foreach ($i in $Profiles) {"$($i.name):$($i.Identity)"})
    #$whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
    $whichone = Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered
    $Profiles[$whichone]

    }

