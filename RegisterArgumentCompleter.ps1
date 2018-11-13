Register-ArgumentCompleter -CommandName @(
    'New-OneShellOrgProfileSystem'
    'Get-OneShellServiceTypeDefinition'
    'Set-OneShellOrgProfileSystem'
    'Get-OneShellOrgProfileSystem'
    'Set-OneShellOrgProfileSystemServiceTypeAttribute'
    'New-OneShellOrgProfileSystemEndpoint'
    'Get-OneShellUserProfileSystem'
    'Get-OneShellSystem'
) -ParameterName 'ServiceType' -ScriptBlock {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)
    $ServiceTypes = Get-OneShellServiceTypeName | Where-Object -FilterScript {$_ -like "$wordToComplete*"} | Sort-Object
    if ($commandName -in @('Set-OneShellOrgProfileSystemServiceTypeAttribute') -and ($null -ne $fakeBoundParameter.Identity))
    {
        $Path = if ($null -eq $fakeBoundParameter.Path) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.Path}
        $Systems = Get-OneShellOrgProfileSystem -Path $Path
        $system = $Systems | Where-Object -FilterScript {$_.Identity -like "$($fakeBoundParameter.Identity)*" -or $_.Name -like "$($fakeBoundParameter.Identity)*"}
        $ServiceTypes = @($system.ServiceType)
    }
    if ($commandName -in @('New-OneShellOrgProfileSystemEndpoint') -and ($null -ne $fakeBoundParameter.SystemIdentity))
    {
        $Path = if ($null -eq $fakeBoundParameter.Path) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.Path}
        $Systems = Get-OneShellOrgProfileSystem -Path $Path
        $system = $Systems | Where-Object -FilterScript {$_.Identity -like "$($fakeBoundParameter.SystemIdentity)*" -or $_.Name -like "$($fakeBoundParameter.SystemIdentity)*"}
        $ServiceTypes = @($system.ServiceType)
    }
    #add a filter for Get-OneShellSystem to show only available/existing service types
    ForEach ($st in $ServiceTypes)
    {
        [System.Management.Automation.CompletionResult]::new($st, $st, 'ParameterValue', $st)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Remove-OneShellUserProfile'
    'Get-OneShellUserProfile'
    'Set-OneShellUserProfile'
    'Use-OneShellUserProfile'
) -ParameterName 'Identity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $Path = if ($null -eq $fakeBoundParameter.Path) {$Script:OneShellUserProfilePath} else {$fakeBoundParameter.Path}
    $PotentialUserProfiles = GetPotentialUserProfiles -path $Path
    $UserProfileIdentities = @(
        @($PotentialUserProfiles.name; $PotentialUserProfiles.Identity) |
            Where-Object -FilterScript {$_ -like "$WordToComplete*"}
    )
    foreach ($upi in $UserProfileIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($upi, $upi, 'ParameterValue', $upi)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Get-OneShellUserProfileSystem'
    'Set-OneShellUserProfileSystem'
)  -ParameterName 'ProfileIdentity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $Path = if ($null -eq $fakeBoundParameter.Path) {$Script:OneShellUserProfilePath} else {$fakeBoundParameter.Path}
    $PotentialUserProfiles = GetPotentialUserProfiles -path $Path
    $UserProfileIdentities = @(
        @($PotentialUserProfiles.name; $PotentialUserProfiles.Identity) |
            Where-Object -FilterScript {$_ -like "$WordToComplete*"}
    )
    foreach ($upi in $UserProfileIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($upi, $upi, 'ParameterValue', $upi)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Get-OneShellUserProfile'
    'New-OneShellUserProfile'
) -ParameterName 'OrgProfileIdentity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $OrgProfilePath = if ($null -eq $fakeBoundParameter.OrgProfilePath) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.OrgProfilePath}
    $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $OrgProfilePath )
    $OrgProfileIdentities = @(
        @($PotentialOrgProfiles.Name; $PotentialOrgProfiles.Identity) |
            Where-Object -FilterScript {$_ -like "$WordToComplete*"}
    )
    foreach ($opi in $OrgProfileIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($opi, $opi, 'ParameterValue', $opi)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Get-OneShellOrgProfile'
    'Set-OneShellOrgProfile'
    'Use-OneShellOrgProfile'
) -ParameterName 'Identity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $OrgProfilePath = if ($null -eq $fakeBoundParameter.OrgProfilePath) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.OrgProfilePath}
    $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $OrgProfilePath )
    $OrgProfileIdentities = @(
        @($PotentialOrgProfiles.Name; $PotentialOrgProfiles.Identity) |
            Where-Object -FilterScript {$_ -like "$WordToComplete*"}
    )
    foreach ($opi in $OrgProfileIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($opi, $opi, 'ParameterValue', $opi)
    }
}
Register-ArgumentCompleter -CommandName @(
    'New-OneShellOrgProfileSystem'
    'Set-OneShellOrgProfileSystem'
    'Set-OneShellOrgProfileSystemServiceTypeAttribute'
    'Get-OneShellOrgProfileSystem'
    'Remove-OneShellOrgProfileSystem'
    'New-OneShellOrgProfileSystemEndpoint'
    'Remove-OneShellOrgProfileSystemEndpoint'
    'Get-OneShellOrgProfileSystemEndpoint'
    'Set-OneShellOrgProfileSystemEndpoint'
) -ParameterName 'ProfileIdentity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $Path = if ($null -eq $fakeBoundParameter.Path) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.Path}
    $PotentialOrgProfiles = @(GetPotentialOrgProfiles -path $Path)
    $OrgProfileIdentities = @(
        @($PotentialOrgProfiles.Name; $PotentialOrgProfiles.Identity) |
            Where-Object -FilterScript {$_ -like "$WordToComplete*"}
    )
    foreach ($opi in $OrgProfileIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($opi, $opi, 'ParameterValue', $opi)
    }
}

Register-ArgumentCompleter -CommandName @(
    'Set-OneShellOrgProfileSystemServiceTypeAttribute'
    'Set-OneShellOrgProfileSystem'
    'Get-OneShellOrgProfileSystem'
    'Remove-OneShellOrgProfileSystem'
) -ParameterName 'Identity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $Path = if ($null -eq $fakeBoundParameter.Path) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.Path}
    $GetOneShellOrgProfileSystemParams = @{
        ErrorAction = 'Stop'
        Path        = $Path
    }
    if (Test-IsNotNullOrWhiteSpace -String  $fakeBoundParameter.ProfileIdentity) {$GetOneShellOrgProfileSystemParams.ProfileIdentity = $fakeBoundParameter.ProfileIdentity}
    $PotentialSystemIdentities = @(
        $Systems = Get-OneShellOrgProfileSystem @GetOneShellOrgProfileSystemParams
        $Systems.Name
        $Systems.Identity
    )
    $PotentialSystemIdentities = @($PotentialSystemIdentities | Where-Object -FilterScript {$_ -like "$WordToComplete*"})
    foreach ($psi in $PotentialSystemIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($psi, $psi, 'ParameterValue', $psi)
    }
}
Register-ArgumentCompleter -CommandName @(
    'New-OneShellOrgProfileSystemEndpoint'
    'Remove-OneShellOrgProfileSystemEndpoint'
    'Get-OneShellOrgProfileSystemEndpoint'
    'Set-OneShellOrgProfileSystemEndpoint'
) -ParameterName 'SystemIdentity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $Path = if ($null -eq $fakeBoundParameter.Path) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.Path}
    $GetOneShellOrgProfileSystemParams = @{
        Path        = $Path
        ErrorAction = 'Stop'
    }
    if (Test-IsNotNullOrWhiteSpace -String $fakeBoundParameter.ProfileIdentity) {$GetOneShellOrgProfileSystemParams.ProfileIdentity = $fakeBoundParameter.ProfileIdentity}
    [string]$ServiceType = if ($null -eq $fakeBoundParameter.ServiceType) {$null} else {$fakeBoundParameter.ServiceType}
    $PotentialSystemIdentities = @(
        $Systems = Get-OneShellOrgProfileSystem @GetOneShellOrgProfileSystemParams
        $Systems = $Systems | Where-Object -FilterScript {$_.ServiceType -like "$($ServiceType)*" -or (Test-IsNullorWhiteSpace -string $ServiceType)}
        $Systems.Name
        $Systems.Identity
    )
    $PotentialSystemIdentities = @($PotentialSystemIdentities | Where-Object -FilterScript {$_ -like "$WordToComplete*"})
    foreach ($psi in $PotentialSystemIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($psi, $psi, 'ParameterValue', $psi)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Remove-OneShellOrgProfileSystemEndpoint'
    'Get-OneShellOrgProfileSystemEndpoint'
    'Set-OneShellOrgProfileSystemEndpoint'
) -ParameterName 'Identity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $Path = if ($null -eq $fakeBoundParameter.Path) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.Path}
    $GetOneShellOrgProfileSystemEndpointParams = @{Path = $Path}
    if ($null -ne $fakeBoundParameter.ProfileIdentity -and $null -ne $fakeBoundParameter.SystemIdentity)
    {
        $GetOneShellOrgProfileSystemEndpointParams.ProfileIdentity = $fakeBoundParameter.ProfileIdentity
        $GetOneShellOrgProfileSystemEndpointParams.SystemIdentity = $fakeBoundParameter.SystemIdentity
        $Endpoints = Get-OneShellOrgProfileSystemEndpoint @GetOneShellOrgProfileSystemEndpointParams
        $EndPointIdentities = @(
            $EndPoints | Select-Object -ExpandProperty Address | Sort-Object
            $Endpoints | Select-Object -ExpandProperty Identity
        )
        $EndPointIdentities = @($EndPointIdentities | Where-Object -FilterScript {$_ -like "$WordToComplete*"})
        foreach ($epi in $EndPointIdentities)
        {
            [System.Management.Automation.CompletionResult]::new($epi, $epi, 'ParameterValue', $epi)
        }
    }
}
Register-ArgumentCompleter -CommandName @(
    'Set-OneShellUserProfileSystem'
    'Get-OneShellUserProfileSystem'
) -ParameterName 'Identity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $OrgProfilePath = if ($null -eq $fakeBoundParameter.OrgProfilePath) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.OrgProfilePath}
    $Path = if ($null -eq $fakeBoundParameter.Path) {$Script:OneShellUserProfilePath} else {$fakeBoundParameter.Path}
    $GetOneShellUserProfileSystemParams = @{
        Path           = $Path
        OrgProfilePath = $OrgProfilePath
    }
    if (Test-IsNotNullOrWhiteSpace -String $fakeBoundParameter.ProfileIdentity)
    {
        $GetOneShellUserProfileSystemParams.ProfileIdentity = $fakeBoundParameter.ProfileIdentity
    }
    $PotentialSystemIdentities = @(
        $Systems = Get-OneShellUserProfileSystem @GetOneShellUserProfileSystemParams
        $Systems.Name
        $Systems.Identity
    )
    $PotentialSystemIdentities = @($PotentialSystemIdentities | Where-Object -FilterScript {$_ -like "$WordToComplete*"})
    foreach ($psi in $PotentialSystemIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($psi, $psi, 'ParameterValue', $psi)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Set-OneShellUserProfileSystem'
) -ParameterName 'PreferredEndPoint' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $OrgProfilePath = if ($null -eq $fakeBoundParameter.OrgProfilePath) {$script:OneShellOrgProfilePath} else {$fakeBoundParameter.OrgProfilePath}
    $GetOneShellOrgProfileSystemEndpointParams = @{Path = $OrgProfilePath; ErrorAction = 'Stop'}
    if ($null -ne $fakeBoundParameter.ProfileIdentity -and $null -ne $fakeBoundParameter.Identity)
    {
        $GetOneShellOrgProfileSystemEndpointParams.ProfileIdentity = $fakeBoundParameter.ProfileIdentity
        $GetOneShellOrgProfileSystemEndpointParams.SystemIdentity = $fakeBoundParameter.Identity
        $PotentialEndPointIdentities = @(
            $Endpoints = Get-OneShellOrgProfileSystemEndpoint @GetOneShellOrgProfileSystemEndpointParams
            $EndPoints.Address
            $EndPoints.Identity
        )
        $PotentialEndPointIdentities = @($PotentialEndPointIdentities | Where-Object -FilterScript {$_ -like "$WordToComplete*"})
        foreach ($pei in $PotentialEndPointIdentities)
        {
            [System.Management.Automation.CompletionResult]::new($pei, $pei, 'ParameterValue', $pei)
        }
    }
}
Register-ArgumentCompleter -CommandName @(
    'Get-OneShellSystem'
    'Connect-OneShellSystem'
) -ParameterName 'Identity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    [string]$ServiceType = if ($null -eq $fakeBoundParameter.ServiceType) {$null} else {$fakeBoundParameter.ServiceType}
    $PotentialSystemIdentities = @(
        $Systems = $script:CurrentSystems | Where-Object -FilterScript {$_.ServiceType -like "$($ServiceType)*" -or (Test-IsNullorWhiteSpace -string $ServiceType)}
        $Systems.Name
        $Systems.Identity
    )
    $AvailableOneShellSystemNamesAndIdentities = @($PotentialSystemIdentities | Where-Object -FilterScript {$_ -like "$WordToComplete*"})
    foreach ($psi in $AvailableOneShellSystemNamesAndIdentities)
    {
        [System.Management.Automation.CompletionResult]::new($psi, $psi, 'ParameterValue', $psi)
    }
}
Register-ArgumentCompleter -CommandName @(
    'Get-OneShellSystemPSSession'
) -ParameterName 'Identity' -ScriptBlock {
    param($commandName, $parameterName, $WordToComplete, $commandAst, $fakeBoundParameter)
    $AvailableOneShellSystemPSSessions = @(Get-PSSession | Where-Object -FilterScript {$_.Name.Split('%')[0] -in $script:CurrentSystems.Identity} | Select-Object -ExpandProperty Name | ForEach-Object {$_.split('%')[0]})
    $OneShellSystemsWithPSSessions = @($script:CurrentSystems | Where-Object -FilterScript {$_.Identity -in $AvailableOneShellSystemPSSessions} | ForEach-Object {$_.Name;$_.Identity} | Where-Object -FilterScript {$_ -like "$WordToComplete*"})
    foreach ($psi in $OneShellSystemsWithPSSessions)
    {
        [System.Management.Automation.CompletionResult]::new($psi, $psi, 'ParameterValue', $psi)
    }
}