    Function Get-OneShellOrgProfileSystemEndpoint
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        $ProfileIdentity
        ,
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$SystemIdentity
        ,
        [parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )
    Process
    {
        #Get the System
        $System = Get-OneShellOrgProfileSystem -Identity $SystemIdentity -Path $Path -ErrorAction Stop -ProfileIdentity $ProfileIdentity
        $Endpoints = @(
            $System.endpoints | Where-Object  -FilterScript {$_.Identity -in $identity -or $_.Address -in $Identity -or (Test-IsNullOrWhiteSpace -String $identity)}
        )
        $Endpoints
    }

    }

