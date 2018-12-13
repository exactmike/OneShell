function Find-CommandPrefixToUse
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory)]
        $ServiceObject
    )
    $CommandPrefix = $(
        if ($null -ne $ServiceObject.PreferredPrefix) #this allows a blank string to be the PreferredPrefix . . . which is what an user may want
        {
            $ServiceObject.PreferredPrefix
        }
        else
        {
            if ($null -ne $endpoint.CommandPrefix)
            {
                $endpoint.CommandPrefix
            }
            else
            {
                $ServiceObject.Defaults.CommandPrefix
            }
        }
    )
    $CommandPrefix
}
#end function Find-CommandPrefixToUse