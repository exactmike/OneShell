    Function Set-OneShellOrgProfile
    {
        
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(ParameterSetName = 'Identity', Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Identity
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [psobject[]]$Systems #Enables copying systems from one org profile to another.  No validation is implemented, however. Replaces all existing Systems when used so use or build an array of systems to use. Use with caution for existing profiles.
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string[]]$Path = $Script:OneShellOrgProfilePath
    )
    Process
    {
        foreach ($i in $Identity)
        {
            #Get the Org Profile
            $GetOrgProfileParams = @{
                ErrorAction = 'Stop'
                Identity    = $Identity
                Path        = $Path
            }
            $OrgProfile = $(Get-OneShellOrgProfile @GetOrgProfileParams)
            Write-Verbose -Message "Selected Org Profile is $($OrgProfile.Name)"
            foreach ($p in $PSBoundParameters.GetEnumerator())
            {
                if ($p.key -in @('Name', 'Systems'))
                {
                    $OrgProfile.$($p.key) = $p.value
                }
            }
            Export-OneShellOrgProfile -profile $OrgProfile -Path $OrgProfile.DirectoryPath -ErrorAction 'Stop'
        }
    }

    }

