function Find-EndpointToUse
{
    [cmdletbinding()]
    param
    (
        [parameter()]
        [AllowNull()]
        $EndpointIdentity
        ,
        $ServiceObject
        ,
        $EndpointGroup
        ,
        [parameter()]
        [ValidateSet('Admin', 'MRS')]
        $EndpointType = 'Admin'
    )
    $FilteredEndpoints = @(
        switch ($null -eq $EndpointIdentity)
        {
            $false
            {
                #Write-verbose -Message "Endpoint Identity was specified.  Return only that endpoint."
                if ($EndpointIdentity -notin $ServiceObject.Endpoints.Identity)
                {throw("Invalid Endpoint Identity $EndpointIdentity was specified. System $($ServiceObject.Identity) has no such endpoint.")}
                else
                {
                    $ServiceObject.Endpoints | Where-Object -FilterScript {$_.Identity -eq $EndpointIdentity}
                }
            }
            $true
            {
                #Write-verbose -message "Endpoint Identity was not specified.  Return all applicable endpoints, with preferred first if specified."
                switch ($null -eq $ServiceObject.PreferredEndpoint)
                {
                    $false
                    {
                        #Write-Verbose -Message "Preferred Endpoint is specified."
                        $PreEndpoints = @(
                            switch ($null -eq $EndpointGroup)
                            {
                                $true
                                {
                                    #Write-Verbose -message 'EndpointGroup was not specified'
                                    $ServiceObject.Endpoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType} | Sort-Object -Property Precedence
                                }#end false
                                $false
                                {
                                    #Write-Verbose -message 'EndpointGroup was specified'
                                    $ServiceObject.Endpoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType -and $_.EndpointGroup -eq $EndpointGroup} | Sort-Object -Property Precedence
                                }#end true
                            }#end switch
                        )
                        $PreEndpoints | Where-Object {$_.Identity -eq $ServiceObject.PreferredEndpoint} | ForEach-Object {$_.Precedence = -1}
                        $PreEndpoints
                    }#end false
                    $true
                    {
                        #Write-Verbose -Message "Preferred Endpoint is not specified."
                        switch ($null -eq $EndpointGroup)
                        {
                            $true
                            {
                                #Write-Verbose -message 'EndpointGroup was not specified'
                                $ServiceObject.Endpoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType} | Sort-Object -Property Precedence
                            }#end false
                            #EndpointGroup was specified
                            $false
                            {
                                #Write-Verbose -message 'EndpointGroup was specified'
                                $ServiceObject.Endpoints | Where-Object -FilterScript {$_.EndpointType -eq $EndpointType -and $_.EndpointGroup -eq $EndpointGroup} | Sort-Object -Property Precedence
                            }#end true
                        }#end switch
                    }#end true
                }#end switch
            }#end $true
        }#end switch
    )
    $GroupedEndpoints = @($FilteredEndpoints | Group-Object -Property Precedence)
    $GroupedEndpoints
}
#end function Find-EndpointToUse