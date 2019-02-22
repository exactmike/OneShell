    Function Set-OneShellUserProfile
    {
        
    [cmdletbinding(DefaultParameterSetName = "Identity")]
    param
    (
        [parameter(ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [string[]]$Identity
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$ProfileFolder
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$LogFolder
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$ExportDataFolder
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$InputFilesFolder
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$Name
        ,
        [parameter(ValueFromPipelineByPropertyName)]
        [ValidateScript( {Test-EmailAddress -EmailAddress $_})]
        $MailFromSMTPAddress
        ,
        [parameter()]
        [switch]$UpdateSystemsFromOrgProfile
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )
    Begin
    {
        $PotentialUserProfiles = GetPotentialUserProfiles -path $Path
    }
    Process
    {
        foreach ($i in $Identity)
        {
            $UserProfile = GetSelectProfile -ProfileType User -Path $path -PotentialProfiles $PotentialUserProfiles -Identity $i -Operation Edit
            $GetOrgProfileParams = @{
                ErrorAction = 'Stop'
                Path        = $orgProfilePath
                Identity    = $UserProfile.organization.identity
            }
            $targetOrgProfile = @(Get-OneShellOrgProfile @GetOrgProfileParams)
            #Check the Org Identity for validity (exists, not ambiguous)
            switch ($targetOrgProfile.Count)
            {
                1
                {}
                0
                {
                    $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $UserProfile.organization.identity -Message "No matching Organization Profile was found for identity $OrganizationIdentity"
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
                Default
                {
                    $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $UserProfile.organization.identity -Message "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            }
            #Update the User Profile Version if necessary
            $UserProfile = UpdateUserProfileObjectVersion -UserProfile $UserProfile
            #Update the profile itself
            if ($PSBoundParameters.ContainsKey('UpdateSystemsFromOrgProfile') -and $UpdateSystemsFromOrgProfile -eq $true)
            {
                $UpdateUserProfileSystemParams = @{
                    ErrorAction    = 'Stop'
                    ProfileObject  = $UserProfile
                    OrgProfilePath = $OrgProfilePath
                }
                Update-OneShellUserProfileSystem @UpdateUserProfileSystemParams
            }
            foreach ($p in $PSBoundParameters.GetEnumerator())
            {
                if ($p.key -in 'ProfileFolder', 'Name', 'MailFromSMTPAddress', 'LogFolder', 'ExportDataFolder', 'InputFilesFolder')
                {
                    if ($p.key -in 'ProfileFolder', 'LogFolder', 'ExportDataFolder', 'InputFilesFolder')
                    {
                        if (-not (Test-Path -PathType Container -Path $p.Value))
                        {
                            Write-Warning -Message "The specified ProfileFolder $($p.key) $ProfileFolder does not exist.  Attempting to Create it."
                            [void](New-Item -Path $p.value -ItemType Directory)
                        }
                    }
                    $UserProfile.$($p.key) = $p.value
                }
            }#end foreach
            Export-OneShellUserProfile -profile $UserProfile -ErrorAction 'Stop'
        }#end foreach
    }#End Process

    }

