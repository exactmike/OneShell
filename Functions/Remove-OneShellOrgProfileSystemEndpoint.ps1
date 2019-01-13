    Function Remove-OneShellOrgProfileSystemEndpoint
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$SystemIdentity
        ,
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$Path = $Script:OneShellOrgProfilePath
    )
    Process
    {
        #Get Org Profile
        $OrgProfile = Get-OneShellOrgProfile -Identity $ProfileIdentity -Path $Path -ErrorAction Stop
        #Get the System
        $System = Get-OneShellOrgProfileSystem -Identity $SystemIdentity -Path $Path -ErrorAction Stop
        if ($System.Endpoints.Count -eq 0) {throw('There are no endpoints to remove')}
        #Get the Endpoint
        foreach ($i in $Identity)
        {
            $endPoint = @($System.Endpoints | Where-Object -FilterScript {
                    $_.Identity -eq $i -or $_.Address -eq $i
                })
            if ($endPoint.Count -ne 1) {throw ("Invalid or Ambiguous Endpoint Identity $Identity Provided")}
            else {$Endpoint = $Endpoint[0]}
            $System = Remove-ExistingObjectFromMultivaluedAttribute -ParentObject $System -ChildObject $endPoint -MultiValuedAttributeName Endpoints -IdentityAttributeName Identity
            $OrgProfile = Update-ExistingObjectFromMultivaluedAttribute -ParentObject $OrgProfile -ChildObject $system -MultiValuedAttributeName Systems -IdentityAttributeName Identity
            Export-OneShellOrgProfile -Path $OrgProfile.DirectoryPath -profile $OrgProfile -ErrorAction Stop
        }
    }

    }

