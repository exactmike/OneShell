    Function Update-ExistingObjectFromMultivaluedAttribute
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
    $ParentObject.$MultiValuedAttributeName[$index] = $ChildObject
    $ParentObject

    }

