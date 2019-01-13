    Function Select-OneShellOrgProfileSystemEndpoint
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $Endpoints
        ,
        [parameter(Mandatory)]
        [ValidateSet('Remove', 'Edit', 'Associate')]
        [string]$Operation
    )
    $message = "Select endpoint to $Operation"
    $Choices = @(foreach ($i in $Endpoints) {"$($i.ServiceType):$($i.address):$($i.Identity)"})
    #$whichone = Read-Choice -Message $message -Choices $Choices -DefaultChoice 0 -Title $message -Numbered -Vertical
    $whichone = Read-PromptForChoice -Message $message -Choices $Choices -DefaultChoice 0 -Numbered
    $Endpoints[$whichone]

    }

