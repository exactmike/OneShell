    Function Get-OneShellUserProfileSystem
    {
        
    [cmdletbinding(DefaultParameterSetName = 'All')]
    param
    (
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$ProfileIdentity
        ,
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$ServiceType
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
        $UserProfiles = @(
            $GetUserProfileParams = @{
                ErrorAction = 'Stop'
                Path        = $Path
            }
            if (Test-IsNotNullOrWhiteSpace -String $ProfileIdentity)
            {
                $GetUserProfileParams.Identity = $ProfileIdentity
            }
            Get-OneShellUserProfile @GetUserProfileParams
        )#end UserProfiles
        Write-Verbose -Message "Got $($UserProfiles.count) User Profiles"
        $OutputSystems = @(
            foreach ($up in $UserProfiles)
            {
                $orgProfile = Get-OneShellOrgProfile -Identity $up.organization.Identity -ErrorAction Stop -Path $OrgProfilePath
                foreach ($us in $up.systems)
                {
                    $os = $orgProfile.systems | Where-Object -FilterScript {$_.Identity -eq $us.identity}
                    $us | Select-Object -Property *, @{n = 'ServiceType'; e = {$os.ServiceType}}, @{n = 'Name'; e = {$os.name}}, @{n = 'ProfileName'; e = {$up.Name}}, @{n = 'ProfileIdentity'; e = {$up.Identity}}, @{n = 'OrgName'; e = {$orgProfile.Name}}, @{n = 'OrgIdentity'; e = {$orgProfile.Identity}}
                }
            }
        )
        #filter based on Identity and Service Type
        $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.ServiceType -in $ServiceType -or (Test-IsNullorWhiteSpace -String $ServiceType)})
        $OutputSystems = @($OutputSystems | Where-Object -FilterScript {$_.Identity -in $Identity -or $_.Name -in $Identity -or (Test-IsNullorWhiteSpace -String $Identity)})
        $OutputSystems
    }#end Process

    }

