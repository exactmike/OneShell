    Function Set-OneShellUserProfileSystem
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline, Mandatory)]
        [string[]]$Identity
        ,
        [parameter()]
        [validateset($true, $false)]
        [bool]$AutoConnect
        ,
        [parameter()]
        [validateset($true, $false)]
        [bool]$AutoImport
        ,
        [parameter()]
        [validateset($true, $false)]
        [bool]$UsePSRemoting
        ,
        [parameter()]
        [ValidateScript( {($_.length -ge 2 -and $_.length -le 5) -or [string]::isnullorempty($_)})]
        [string]$PreferredPrefix
        ,
        [parameter()]
        [allowNull()]
        [string]$PreferredEndpoint
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )#end param
    Process
    {
        $UserProfile = @(Get-OneShellUserProfile -Identity $ProfileIdentity -Path $Path -OrgProfilePath $OrgProfilePath -ErrorAction Stop)
        if ($UserProfile.Count -ne 1)
        {throw("Ambiguous or not found User ProfileIdentity $ProfileIdentity was specified")}
        else
        {$UserProfile = $UserProfile[0]}
        foreach ($i in $Identity)
        {
            $System = @(Get-OneShellUserProfileSystem -ProfileIdentity $ProfileIdentity -Identity $i -Path $Path -OrgProfilePath $OrgProfilePath -ErrorAction Stop)
            if ($System.Count -ne 1)
            {throw("Ambiguous or not found System Identity $i was specified")}
            else
            {$System = $System[0]}
            #Edit the System
            switch ($PSBoundParameters.getenumerator())
            {
                {$_.key -eq 'AutoConnect'}
                {$System.AutoConnect = $AutoConnect}
                {$_.key -eq 'AutoImport'}
                {
                    if ($true -eq $AutoImport -and ($false -eq $system.UsePSRemoting -or $false -eq $UsePSRemoting))
                    {
                        Write-Warning -Message 'When UsePSRemoting is set to $false, AutoImport $true will be effective when connecting to a System.'
                    }
                    $System.AutoImport = $AutoImport
                }
                {$_.key -eq 'UsePSRemoting'}
                {
                    $System.UsePSRemoting = $UsePSRemoting
                    if ($false -eq $UsePSRemoting)
                    {
                        if ($true -eq $System.AutoImport)
                        {
                            Write-Warning -Message 'When UsePSRemoting is set to $False, AutoImport is also set to $False'
                            $AutoImport = $false
                            $System.AutoImport = $AutoImport
                        }
                    }
                }
                {$_.key -eq 'PreferredPrefix'}
                {$System.PreferredPrefix = $PreferredPrefix}
                {$_.key -eq 'PreferredEndpoint'}
                {
                    $Endpoints = Get-OneShellOrgProfileSystemEndpoint -Identity $PreferredEndpoint -SystemIdentity $system.Identity -ProfileIdentity $UserProfile.Organization.Identity -Path $OrgProfilePath -ErrorAction 'Stop'
                    if ($_.value -in $Endpoints.Identity -or $null -eq $_.value)
                    {
                        $System.PreferredEndpoint = $PreferredEndpoint
                    }
                    else
                    {
                        throw("Invalid Endpoint Identity $PreferredEndpoint was provided. No such endpoint exists for system $($system.identity).")
                    }
                }
            }
            #remove any extraneous properties
            $System = $System | Select-Object -Property $(GetUserProfileSystemPropertySet)
            #Save the system changes to the User Profile
            $UserProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $UserProfile -ChildObject $System -MultiValuedAttributeName Systems -IdentityAttributeName Identity -ErrorAction 'Stop'
            Export-OneShellUserProfile -profile $UserProfile -path $path -ErrorAction 'Stop'
        }
    }#end Process

    }

