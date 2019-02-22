    Function Remove-Member
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipeline)]
        [psobject[]]$Object
        ,
        [parameter(Mandatory)]
        [string]$Member
    )
    begin {}
    process
    {
        foreach ($o in $Object)
        {
            $o.psobject.Members.Remove($Member)
        }
    }

    }

