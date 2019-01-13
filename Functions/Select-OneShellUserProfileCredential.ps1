    Function Select-OneShellUserProfileCredential
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [psobject[]]$Credential
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Associate')]
        [string]$Operation
    )
    $message = "Select credential to $Operation"
    $Choices = @(foreach ($i in $Credential) {"$($i.username):$($i.Identity)"})
    #$whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
    $whichone = Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered
    $Credential[$whichone]

    }

