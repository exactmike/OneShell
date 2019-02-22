    Function Update-OneShellUserProfileSystem
    {
        
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [Parameter(Mandatory,ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Identity
        ,
        [Parameter(ParameterSetName = 'Object', ValueFromPipeline, Mandatory)]
        [ValidateScript( {$_.ProfileType -eq 'OneShellUserProfile'})]
        [psobject[]]$ProfileObject
        ,
        [parameter(ParameterSetName = 'Identity')]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
    )
    Process
    {
        $IncomingObjects = @(
            switch ($PSCmdlet.ParameterSetName)
            {
                'Object'
                {
                    $ProfileObject
                }
                'Identity'
                {
                    $Identity
                }
            }
        )
        foreach ($io in $IncomingObjects)
        {
            switch ($PSCmdlet.ParameterSetName)
            {
                'Object'
                {
                    #validate the object
                    $UserProfile = $io
                }
                'Identity'
                {
                    $GetUserProfileParams = @{
                        ErrorAction = 'Stop'
                        Identity    = $io
                        Path        = $Path
                    }
                    $UserProfile = $(Get-OneShellUserProfile @GetUserProfileParams)
                }
            }#end switch ParameterSetName
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
                    $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $OrganizationIdentity -Message "No matching Organization Profile was found for identity $OrganizationIdentity"
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
                Default
                {
                    $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $OrganizationIdentity -Message "Multiple matching Organization Profiles were found for identity $OrganizationIdentity"
                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            }
            $OrgProfileSystems = @(GetOrgProfileSystemForUserProfile -OrgProfile $TargetOrgProfile)
            $UserProfileSystems = @($UserProfile.Systems)
            #Remove those that are no longer in the Org Profile
            $UserProfileSystems = @($UserProfileSystems | Where-Object {$_.Identity -in $OrgProfileSystems.Identity})
            #Add those that are new to the Org Profile
            $NewOrgProfileSystems = @($OrgProfileSystems | Where-Object {$_.Identity -notin $UserProfileSystems.Identity})
            $NewUserProfileSystems = @($UserProfileSystems; $NewOrgProfileSystems)
            $UserProfile.Systems = $NewUserProfileSystems
            Export-OneShellUserProfile -profile $UserProfile -ErrorAction 'Stop'
        }#Foreach
    }#Process

    }

