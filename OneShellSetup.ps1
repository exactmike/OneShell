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
git clone https://github.com/exactmike/PSMenu.git
git clone https://github.com/exactmike/PublicFolderMigration.git
git clone https://github.com/exactmike/MoveRequestManagement.git

#add more for branches above?
