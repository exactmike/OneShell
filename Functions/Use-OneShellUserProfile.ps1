    Function Use-OneShellUserProfile
    {
        
    [cmdletbinding(DefaultParameterSetName = 'Identity')]
    param
    (
        [parameter(ParameterSetName = 'Identity', ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 1, Mandatory)]
        [string]$Identity
        ,
        [parameter(ParameterSetName = 'Object', ValueFromPipeline = $true, Position = 1, Mandatory)]
        $UserProfile
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$Path = $Script:OneShellUserProfilePath
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -Path $_})]
        [string[]]$OrgProfilePath = $Script:OneShellOrgProfilePath
        ,
        [switch]$NoAutoConnect
        ,
        [switch]$NoAutoImport
    )
    begin
    {
        $PotentialUserProfiles = GetPotentialUserProfiles -path $Path
    }
    process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'Object'
            {
                #validate that this is a user profile object . . .
            }
            'Identity'
            {
                if ($null -eq $Identity)
                {
                    $UserProfile = Select-Profile -Profiles $PotentialUserProfiles -Operation Use
                }
                else
                {
                    $GetUserProfileParams = @{
                        Identity    = $Identity
                        ErrorAction = 'Stop'
                        Path        = $path
                    }
                    $UserProfile = $(Get-OneShellUserProfile @GetUserProfileParams)
                }
            }
        }
        #Check User Profile Version
        #$RequiredVersion = 1.3
        #if (! $UserProfile.ProfileTypeVersion -ge $RequiredVersion)
        #{
        #    throw("The selected User Profile $($UserProfile.Name) is an older version. Please Run Set-OneShellUserProfile -Identity $($UserProfile.Identity) or Update-OneShellUserProfileTypeVersion -Identity $($UserProfile.Identity) to update it to version $RequiredVersion.")
        #}
        #Get and use the related Org Profile
        $UseOrgProfileParams = @{
            ErrorAction = 'Stop'
            Path        = $OrgProfilePath
            Identity    = $UserProfile.Organization.Identity
        }
        $OrgProfile = Get-OneShellOrgProfile @UseOrgProfileParams
        Use-OneShellOrgProfile -profile $OrgProfile
        #need to add some clean-up functionality for sessions when there is a change, or make it always optional to reset all sessions with this function
        $script:CurrentUserProfile = $UserProfile
        Write-Verbose -Message "User Profile has been set to $($script:CurrentUserProfile.Identity), $($script:CurrentUserProfile.name)."
        #Build the 'live' systems for use by connect-* functions
        #Retrieve the systems from the current org profile
        $OrgSystems = $OrgProfile.systems
        $UserSystems = $UserProfile.systems
        $JoinedSystems = join-object -Left $OrgSystems -Right $UserSystems -LeftJoinProperty Identity -RightJoinProperty Identity
        #Write-Verbose -Message $("Members of Joined Systems: " + $($JoinedSystems | get-member -MemberType Properties | Select-Object -ExpandProperty Name) -join ',')
        #Write-Verbose -Message $("Members of Joined Systems Credentials: " + $($JoinedSystems.credentials | get-member -MemberType Properties | Select-Object -ExpandProperty Name) -join ',')
        $Script:CurrentSystems =
        @(
            foreach ($js in $JoinedSystems)
            {
                foreach ($p in @('PSSession', 'Service'))
                {
                    $PreCredential = @($UserProfile.credentials | Where-Object -FilterScript {$_.Identity -eq $js.Credentials.$p})
                    switch ($PreCredential.count)
                    {
                        1
                        {
                            $SSPassword = $PreCredential[0].password | ConvertTo-SecureString
                            $Credential = New-Object System.Management.Automation.PSCredential($PreCredential[0].Username, $SSPassword)
                            #Write-Verbose -Message "Service Credential Found for $($js.name)"
                        }
                        0
                        {
                            $Credential = $null
                            #Write-Verbose -Message "Service Credential Not Found for $($js.name)"
                        }
                    }
                    $js.Credentials.$p = $Credential
                }
                $js
            }
        )
        #set folder paths
        $script:OneShellUserProfileFolder = $script:CurrentUserProfile.ProfileFolder
        #Log Folder and Log Paths
        if ([string]::IsNullOrEmpty($script:CurrentUserProfile.LogFolder))
        {
            $Script:LogFolderPath = "$script:OneShellUserProfileFolder\Logs"
        }
        else
        {
            $Script:LogFolderPath = $script:CurrentUserProfile.LogFolder
        }
        if (-not (Test-path -PathType Container -Path $Script:LogFolderPath))
        {
            [void](New-Item -Path $Script:LogFolderPath -ItemType Directory -ErrorAction Stop)
        }
        $Script:LogPath = "$Script:LogFolderPath\$Script:Stamp" + '-Operations.log'
        $Script:ErrorLogPath = "$Script:LogFolderPath\$Script:Stamp" + '-Operations-Errors.log'
        #Input Files Path
        if ([string]::IsNullOrEmpty($script:CurrentUserProfile.InputFilesFolder))
        {
            $Script:InputFilesPath = "$script:OneShellUserProfileFolder\InputFiles\"
        }
        else
        {
            $Script:InputFilesPath = $script:CurrentUserProfile.InputFilesFolder + '\'
        }
        if (-not (Test-path -PathType Container -Path $Script:InputFilesPath))
        {
            [void](New-Item -Path $Script:InputFilesPath -ItemType Directory -ErrorAction Stop)
        }
        #Export Data Path
        if ([string]::IsNullOrEmpty($script:CurrentUserProfile.ExportDataFolder))
        {
            $Script:ExportDataPath = "$script:OneShellUserProfileFolder\Export\"
        }
        else
        {
            $Script:ExportDataPath = $script:CurrentUserProfile.ExportDataFolder + '\'
        }
        if (-not (Test-path -PathType Container -Path $Script:ExportDataPath))
        {
            [void](New-Item -Path $Script:ExportDataPath -ItemType Directory -ErrorAction Stop)
        }
    }#process
    end
    {
        if ($NoAutoConnect -ne $true)
        {
            $AutoConnectSystems = Get-OneShellSystem | Where-Object -FilterScript {$_.AutoConnect -eq $true}

            if ($NoAutoImport -eq $true)
            {
                $ConnectOneShellSystemParams = @{
                    NoAutoImport = $true
                }
            }
            else
            {
                $ConnectOneShellSystemParams = @{}
            }
            $AutoConnectSystems | foreach-object {Connect-OneShellSystem -identity $_.Identity @ConnectOneShellSystemParams}
        }
    }

    }

