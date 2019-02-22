Function Export-OneShellUserProfile
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [psobject]$profile
        ,
        [parameter()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        $path = $script:OneShellUserProfilePath
    )
    if ($profile.Identity -is 'GUID')
    {$name = $($profile.Identity.Guid) + '.json'}
    else
    {$name = $($profile.Identity) + '.json'}
    $FilePath = Join-Path -Path $path -ChildPath $name
    Write-Verbose -Message "Profile File Export Path is $FilePath"
    $profile | Remove-Member -Member DirectoryPath
    $ConvertToJsonParams = @{
        InputObject = $profile
        ErrorAction = 'Stop'
        Depth       = 6
    }
    $OutParams = @{
        ErrorAction = 'Stop'
        FilePath    = $FilePath
        Encoding    = 'ascii'
    }
    if ($whatifPreference -eq $false)
    {$OutParams.Force = $true}
    try
    {
        ConvertTo-Json @ConvertToJsonParams | Out-File @OutParams
    }#try
    catch
    {
        $_
        throw "FAILED: Could not write User Profile data to $FilePath"
    }#catch
}
#end function Export-OneShellUserProfile