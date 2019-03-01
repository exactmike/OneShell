    Function UpdateUserProfileObjectVersion
    {

    [cmdletbinding()]
    param
    (
        [parameter(Mandatory)]
        $UserProfile
        ,
        $DesiredProfileTypeVersion = $Script:UserProfileTypeLatestVersion
    )
    do
    {
        switch ($UserProfile.ProfileTypeVersion)
        {
            {$_ -lt 1}
            {
                #Upgrade ProfileVersion to 1
                #MailFrom
                if (-not (Test-Member -InputObject $UserProfile.General -Name MailFrom))
                {
                    $UserProfile.General | Add-Member -MemberType NoteProperty -Name MailFrom -Value $null
                }
                #UserName
                if (-not (Test-Member -InputObject $UserProfile.General -Name User))
                {
                    $UserProfile.General | Add-Member -MemberType NoteProperty -Name User -Value [Environment]::UserName
                }
                #MailRelayEndpointToUse
                if (-not (Test-Member -InputObject $UserProfile.General -Name MailRelayEndpointToUse))
                {
                    $UserProfile.General | Add-Member -MemberType NoteProperty -Name MailRelayEndpointToUse -Value $null
                }
                #ProfileTypeVersion
                if (-not (Test-Member -InputObject $UserProfile -Name ProfileTypeVersion))
                {
                    $UserProfile | Add-Member -MemberType NoteProperty -Name ProfileTypeVersion -Value 1.0
                }
                #Credentials add Identity
                foreach ($Credential in $UserProfile.Credentials)
                {
                    if (-not (Test-Member -InputObject $Credential -Name Identity))
                    {
                        $Credential | Add-Member -MemberType NoteProperty -Name Identity -Value $(New-OneShellGuid).guid
                    }
                }
                #SystemEntries
                foreach ($se in $UserProfile.Systems)
                {
                    if (-not (Test-Member -InputObject $se -Name Credentials))
                    {
                        $se | Add-Member -MemberType NoteProperty -Name Credentials -Value $null
                    }
                    foreach ($credential in $UserProfile.Credentials)
                    {
                        if (Test-Member -InputObject $credential -Name Systems)
                        {
                            if ($se.Identity -in $credential.systems)
                            {$se.credentials = @($credential.Identity)}
                        }
                    }
                }
                #Credentials Remove Systems
                $UpdatedCredentialObjects = @(
                    foreach ($Credential in $UserProfile.Credentials)
                    {
                        if (Test-Member -InputObject $Credential -Name Systems)
                        {
                            $UpdatedCredential = $Credential | Select-Object -Property Identity, Username, Password
                            $UpdatedCredential
                        }
                        else
                        {
                            $Credential
                        }
                    }
                )
                $UserProfile.Credentials = $UpdatedCredentialObjects
            }#end $_ -lt 1
            {$_ -eq 1}
            {
                $NewMembers = ('ProfileFolder', 'Name', 'MailFromSMTPAddress')
                foreach ($nm in $NewMembers)
                {
                    if (-not (Test-Member -InputObject $UserProfile -Name $nm))
                    {
                        $UserProfile | Add-Member -MemberType NoteProperty -Name $nm -Value $null
                    }
                    switch ($nm)
                    {
                        'MailFromSMTPAddress'
                        {$UserProfile.$nm = $UserProfile.General.MailFrom}
                        Default
                        {$UserProfile.$nm = $UserProfile.General.$nm}
                    }
                }
                $UserProfile | Add-Member -MemberType NoteProperty -Value $([pscustomobject]@{Identity = $null; Name = $null}) -name Organization
                $UserProfile.Organization.Identity = $UserProfile.General.OrganizationIdentity
                $UserProfile | Remove-member -member General
                $UserProfile.ProfileTypeVersion = 1.1
            }
            {$_ -eq 1.1}
            {
                #SystemEntries Update to user possibly separate credentials for PSSession and Service
                foreach ($se in $UserProfile.Systems)
                {
                    if (-not (Test-Member -InputObject $se -Name Credentials))
                    {
                        $se | Add-Member -MemberType NoteProperty -Name Credentials -Value $([pscustomobject]@{PSSession = $se.Credential; Service = $se.Credential})
                        $Se | Remove-Member -Member Credential
                    }
                }
                $UserProfile.ProfileTypeVersion = 1.2
            }
            {$_ -eq 1.2}
            {
                #Add attributes for discrete LogFolder, ExportDataFolder, and InputFilesFolder
                $NewMembers = ('LogFolder', 'ExportDataFolder', 'InputFilesFolder')
                foreach ($nm in $NewMembers)
                {
                    if (-not (Test-Member -InputObject $UserProfile -name $nm))
                    {
                        $UserProfile | Add-Member -MemberType NoteProperty -Name $nm -Value $null
                    }
                }
                $UserProfile.ProfileTypeVersion = 1.3
            }
            {$_ -eq 1.3}
            {
                $NewMembers = GetUserProfileSystemPropertySet
                foreach ($s in $UserProfile.systems)
                {
                    Add-RequiredMember -RequiredMember $NewMembers -InputObject $s
                }
                $UserProfile.ProfileTypeVersion = 1.4
            }
        }#end switch
    }
    Until ($UserProfile.ProfileTypeVersion -eq $DesiredProfileTypeVersion)
    $UserProfile

    }
