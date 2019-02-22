    Function New-OneShellUserProfile
    {
        
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        [string]$OrgProfileIdentity
        ,
        [Parameter(Mandatory)]
        [string]$ProfileFolder #The folder to use for logs, exports, etc.
        ,
        [Parameter(Mandatory)]
        [string]$MailFromSMTPAddress #email address to use for sending notification emails
        ,
        [Parameter()]
        [pscredential[]]$Credentials = @()
        ,
        [Parameter()]
        [string]$Name #Overrides the default name of Org-Machine-User
        ,
        [Parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        [string]$OrgProfilePath = $Script:OneShellOrgProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string]$Path = $Script:OneShellUserProfilePath
    )
    End
    {
        $GetOrgProfileParams = @{
            ErrorAction = 'Stop'
            Identity    = $OrgProfileIdentity
            Path        = $OrgProfilePath
        }
        $targetOrgProfile = @(Get-OneShellOrgProfile @GetOrgProfileParams)
        switch ($targetOrgProfile.Count)
        {
            1 {}
            0
            {
                $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory ObjectNotFound -TargetObject $OrgIDUsed -Message "No matching Organization Profile was found for identity $OrgIDUsed"
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
            Default
            {
                $errorRecord = New-ErrorRecord -Exception System.Exception -ErrorId 0 -ErrorCategory InvalidData -TargetObject $OrgIDUsed -Message "Multiple matching Organization Profiles were found for identity $OrgIDUsed"
                $PSCmdlet.ThrowTerminatingError($errorRecord)
            }
        }
        $UserProfile = NewGenericUserProfileObject -TargetOrgProfile $targetOrgProfile
        $Systems = @(GetOrgProfileSystemForUserProfile -OrgProfile $TargetOrgProfile)
        $UserProfile.Systems = $Systems
        foreach ($p in $PSBoundParameters.GetEnumerator())
        {
            if ($p.key -in 'ProfileFolder', 'Name', 'MailFromSMTPAddress', 'Credentials', 'Systems')
            {
                if ($p.key -eq 'ProfileFolder')
                {
                    if ($p.value -like '*\' -or $p.value -like '*/')
                    {$ProfileFolder = join-path (split-path -path $p.value -Parent) (split-path -Path $p.value -Leaf)}
                    if (-not (Test-Path -PathType Container -Path $ProfileFolder))
                    {
                        Write-Warning -Message "The specified Profile Folder $ProfileFolder does not exist.  Attempting to Create it."
                        [void](New-Item -Path $ProfileFolder -ItemType Directory)
                    }
                }
                $UserProfile.$($p.key) = $p.value
            }
        }#end foreach
        Export-OneShellUserProfile -profile $UserProfile -path $path -errorAction 'Stop'
    }#end End

    }

