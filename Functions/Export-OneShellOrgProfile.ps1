Function Export-OneShellOrgProfile
{
    [cmdletbinding(SupportsShouldProcess)]
    param
    (
        [parameter(Mandatory)]
        [psobject]$profile
        ,
        [parameter(Mandatory)]
        [AllowNull()]
        [ValidateScript( {Test-DirectoryPath -path $_})]
        $Path
    )
    $name = [string]$($profile.Identity.tostring()) + '.json'
    if ($null -eq $Path)
    {
        Write-Verbose -Message "Using Default Profile Location"
        $FilePath = Join-Path $script:OneShellOrgProfilePath[0] $name
    }
    else
    {
        $FilePath = Join-Path $Path $name
    }
    Write-Verbose -Message "Profile File Export Path is $FilePath"
    $profile | Remove-Member -Member DirectoryPath
    $JSONparams = @{
        InputObject = $profile
        ErrorAction = 'Stop'
        Depth       = 10
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
        ConvertTo-Json @JSONparams | Out-File @OutParams
    }#end try
    catch
    {
        $_
        throw "FAILED: Could not write Org Profile data to $FilePath"
    }#end catch
}
#end Function Export-OneShellOrgProfile