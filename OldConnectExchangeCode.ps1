        try
        {
            $ExistingSession = Get-PSSession -Name $ServiceObject.Identity -ErrorAction Stop
            Write-Verbose -Message "Existing session for $($serviceObject.Identity) exists"
            Write-Verbose -Message "Checking $($ServiceObject.Identity) Session State" 
            if ($ExistingSession.State -ne 'Opened')
            {
                Write-Log -Message "Existing session for $($ServiceObject.Identity) exists but is not in state 'Opened'"
                Remove-PSSession -Name $($ServiceObject.Identity) 
                $UseExistingSession = $False
            }#end if
            else
            {
                Write-Verbose -Message "$($ServiceObject.Identity) Session State is 'Opened'. Using existing Session." 
                switch ($ServiceObject.ServiceTypeAttributes.ExchangeOrgType)
                {
                    'OnPremises'
                    {
                        try
                        {
                            $Global:ErrorActionPreference = 'Stop'
                            $InvokeExchangeCommandParams = @{
                                Cmdlet = 'Set-ADServerSettings'
                                ExchangeOrganization = $ServiceObject
                                ErrorAction = 'Stop'
                                WarningAction = 'SilentlyContinue'
                                splat = @{
                                    ViewEntireForest = $true
                                    ErrorAction = 'Stop'
                                    WarningAction = 'SilentlyContinue'
                                }
                            }
                            Invoke-ExchangeCommand @InvokeExchangeCommandParams
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch
                        {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#OnPremises
                    'Online'
                    {
                        try
                        {
                            $splat = @{Identity = $Credential.UserName;ErrorAction = 'Stop'}
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-ExchangeCommand -cmdlet Get-User -ExchangeOrganization $orgName -splat $splat -ErrorAction Stop > $null
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch
                        {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#Online
                    'ComplianceCenter'
                    {
                        try
                        {
                            $splat = @{Identity = $Credential.UserName;ErrorAction = 'Stop'}
                            $Global:ErrorActionPreference = 'Stop'
                            Invoke-ExchangeCommand -cmdlet Get-User -ExchangeOrganization $orgName -splat $splat -ErrorAction Stop > $null
                            $Global:ErrorActionPreference = 'Continue'
                            $UseExistingSession = $true
                        }#try
                        catch
                        {
                            $Global:ErrorActionPreference = 'Continue'
                            Remove-PSSession -Name $SessionName
                            $UseExistingSession = $false
                        }#catch
                    }#ComplianceCenter
                }#switch $orgtype
                }#else
            }#try
            catch {
                Write-Log -Message "No existing session for $SessionName exists" 
                $UseExistingSession = $false
            }#catch
            switch ($UseExistingSession) {
                $true
                {
                    Write-Output -InputObject $true
                }#$true
                $false {
                    $sessionParams = @{
                        ConfigurationName = 'Microsoft.Exchange'
                        Credential = $Credential
                        Name = $SessionName
                    }
                    switch ($orgtype) {
                        'Online' {
                            $sessionParams.ConnectionURI = 'https://outlook.office365.com/powershell-liveid/'
                            $sessionParams.Authentication = 'Basic'
                            $sessionParams.AllowRedirection = $true
                            If ($ProxyEnabled) {
                                $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                                Write-Log -message 'Using Proxy Configuration'
                            }
                        }
                        'ComplianceCenter' {
                            $sessionParams.ConnectionURI = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
                            $sessionParams.Authentication = 'Basic'
                            $sessionParams.AllowRedirection = $true
                            If ($ProxyEnabled) {
                                $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                                Write-Log -message 'Using Proxy Configuration'
                            }
                        }
                        'OnPremises' {
                            #add option for https + Basic Auth    
                            $sessionParams.ConnectionURI = 'http://' + $Server + '/PowerShell/'
                            $sessionParams.Authentication = $AuthMethod
                            if ($ProxyEnabled) {
                                $sessionParams.SessionOption = New-PsSessionOption -ProxyAccessType IEConfig -ProxyAuthentication basic
                                Write-Log -message 'Using Proxy Configuration'
                            }
                        }
                    }
                    try {
                        Write-Log -Message "Attempting: Creation of Remote Session $SessionName to Exchange System $orgName"
                        $Session = New-PSSession @sessionParams -ErrorAction Stop
                        Write-Log -Message "Succeeded: Creation of Remote Session to Exchange System $orgName"
                        Write-Log -Message "Attempting: Import Exchange Session $SessionName and Module" 
                        $ImportPSSessionParams = @{
                            AllowClobber = $true
                            DisableNameChecking = $true
                            ErrorAction = 'Stop'
                            Session = $Session
                        }
                        $ImportModuleParams = @{
                            DisableNameChecking = $true
                            ErrorAction = 'Stop'
                            Global = $true
                        }
                        if (-not [string]::IsNullOrWhiteSpace($CommandPrefix)) {
                            $ImportPSSessionParams.Prefix = $CommandPrefix
                            $ImportModuleParams.Prefix = $CommandPrefix
                        }
                        Import-Module (Import-PSSession @ImportPSSessionParams) @ImportModuleParams
                        Write-Log -Message "Succeeded: Import Exchange Session $SessionName and Module" 
                        if ($orgtype -eq 'OnPremises') {
                            if ($PreferredDomainControllers.Count -ge 1) {
                                $splat=@{ViewEntireForest=$true;SetPreferredDomainControllers=$PreferredDomainControllers;ErrorAction='Stop'}
                            }#if
                            else {
                                $splat=@{ViewEntireForest=$true;ErrorAction='Stop'}
                            }#else    
                            Invoke-ExchangeCommand -cmdlet Set-ADServerSettings -ExchangeOrganization $orgName -splat $splat
                        }#if
                        Write-Output -InputObject $true
                        Write-Log -Message "Succeeded: Connect to Exchange System $orgName"
                    }#try
                    catch {
                        Write-Log -Message "Failed: Connect to Exchange System $orgName" -Verbose -ErrorLog
                        Write-Log -Message $_.tostring() -ErrorLog
                        Write-Output -InputObject $False
                    }#catch
                }#$false
            }#switch
        }