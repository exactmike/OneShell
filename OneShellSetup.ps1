function Get-UninstallEntry
{
[cmdletbinding(DefaultParameterSetName = 'SpecifiedProperties')]
param(
[parameter(ParameterSetName = 'Raw')]
[switch]$raw
,
[parameter(ParameterSetName = 'SpecifiedProperties')]
[string[]]$property = @('DisplayName','DisplayVersion','InstallDate','Publisher')
)
    # paths: x86 and x64 registry keys are different
    if ([IntPtr]::Size -eq 4) {
        $path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    else {
        $path = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }
    $UninstallEntries = Get-ItemProperty $path 
    # use only with name and unistall information
    #.{process{ if ($_.DisplayName -and $_.UninstallString) { $_ } }} |
    # select more or less common subset of properties
    #Select-Object DisplayName, Publisher, InstallDate, DisplayVersion, HelpLink, UninstallString |
    # and finally sort by name
    #Sort-Object DisplayName
    if ($raw) {$UninstallEntries | Sort-Object -Property DisplayName}
    else {
        $UninstallEntries | Sort-Object -Property DisplayName | Select-Object -Property $property
    }
} 
#region TestPrereqs
$SoftwareInstalled = @(Get-UninstallEntry)

$PreReqsTest = @{
    PSVersion = $PSVersionTable.PSVersion.ToString() -ge 4
    MOSIA = 'Microsoft Online Services Sign-in Assistant' -in $SoftwareInstalled.DisplayName
    AzureAD = 'Windows Azure Active Directory Module for Windows PowerShell' -in $SoftwareInstalled.DisplayName
    Git = Test-CommandExists -command 'git'
}

if ($PreReqsTest.ContainsValue($false)){
    $PreReqsTest
    Throw "Missing a OneShell PreRequisite"
}
#endregion TestPrereqs
if (-not (Test-Path C:\ProgramData\OneShell))
{
    New-Item -Path C:\ProgramData -Name 'OneShell' -ItemType Directory
}
$MyDocsPath = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders').Personal
if (-not (Test-Path "$MyDocsPath\WindowsPowerShell"))
{
    New-Item -Path $MyDocsPath -Name 'WindowsPowerShell' -ItemType Directory 
}
if (Test-Path "$MyDocsPath\WindowsPowerShell")
{
    if (-not (Test-Path "$MyDocsPath\WindowsPowerShell\Modules"))
    {
       New-Item -Path "$MyDocsPath\WindowsPowerShell" -Name 'Modules' -ItemType Directory 
    }
}
$MyWPSPath = "$MyDocsPath\WindowsPowerShell"
$MyPSModulesPath = "$MyWPSPath\Modules"
cd $MyPSModulesPath
git clone https://github.com/exactmike/OneShell.git
git clone https://github.com/exactmike/AdvancedOneShell.git
git clone https://github.com/exactmike/PublicFolderMigration.git
git clone https://github.com/exactmike/MoveRequestManagement.git
git clone https://github.com/exactmike/MigrationDatabase.git

#add more for branches above?
