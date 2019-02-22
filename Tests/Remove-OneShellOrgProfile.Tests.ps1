$CommandName = $MyInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
. Join-Path (Join-Path $PSScriptRoot 'Functions') $($CommandName + '.ps1')

Describe "$CommandName Unit Tests" -Tag 'UnitTests' {
    Context "Validate parameters" {
        $paramCount = 2
        $defaultParamCount = 13
        [object[]]$params = (Get-ChildItem Function:\Remove-OneShellOrgProfile).Parameters.Keys
        $knownParameters = @('Identity','Path')
        It "Should contain our specific parameters" {
            ( @(Compare-Object -ReferenceObject $knownParameters -DifferenceObject $params -IncludeEqual | Where-Object SideIndicator -eq "==").Count ) | Should Be $paramCount
        }
        It "Should only contain $paramCount parameters" {
            $params.Count - $defaultParamCount | Should Be $paramCount
        }
    }
}
Describe "$CommandName Integration Tests" -Tags "IntegrationTests" {
    Context "Removes an Org Profile from Disk" {
        New-OneShellOrgProfile -Name 'Test1' -OrganizationSpecificModules 'ATest1OrgModule' -Path 'Testdrive:\'
        It "Should remove the file from disk" {
            {Remove-OneShellOrgProfile -Identity 'Test1' -Path 'testdrive:\'} | Should Not Throw
            {Get-OneShellOrgProfile -Identity 'Test1' -Path 'TestDrive:\'} | Should Throw
        }
    }
}