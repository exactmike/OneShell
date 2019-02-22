    Function Remove-ExistingObjectFromMultivaluedAttribute
    {
        
    [CmdletBinding()]
    param
    (
        $ParentObject
        ,
        $ChildObject
        ,
        $MultiValuedAttributeName
        ,
        $IdentityAttributeName
    )
    $index = Get-ArrayIndexForValue -array $ParentObject.$MultiValuedAttributeName -value $ChildObject.$IdentityAttributeName -property $IdentityAttributeName
    $originalChildObjectContainer = @($ParentObject.$MultiValuedAttributeName)
    $newChildObjectContainer = @($originalChildObjectContainer | Where-Object -FilterScript {$_.Identity -ne $originalChildObjectContainer[$index].$IdentityAttributeName})
    $ParentObject.$MultiValuedAttributeName = $newChildObjectContainer
    $ParentObject

    }

