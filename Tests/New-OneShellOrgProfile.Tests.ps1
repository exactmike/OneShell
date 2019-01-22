$CommandName = $MyInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
. Join-Path (Join-Path $PSScriptRoot 'Functions') $($CommandName + '.ps1')


Describe "$CommandName Unit Tests" -Tag 'UnitTests' {
    Context "Validate parameters" {
        $paramCount = 4
        $defaultParamCount = 11
        [object[]]$params = (Get-ChildItem Function:\New-OneShellOrgProfile).Parameters.Keys
        $knownParameters = @('Name','OrganizationSpecificModules','Path','WriteToPipeline')
        It "Should contain our specific parameters" {
            ( @(Compare-Object -ReferenceObject $knownParameters -DifferenceObject $params -IncludeEqual | Where-Object SideIndicator -eq "==").Count ) | Should Be $paramCount
        }
        It "Should only contain $paramCount parameters" {
            $params.Count - $defaultParamCount | Should Be $paramCount
        }
    }
}
Describe "$CommandName Integration Tests" -Tags "IntegrationTests" {
    Context "Creates an Org Profile with the expected attributes and values" {
        $results = New-OneShellOrgProfile -Name 'Test1' -OrganizationSpecificModules 'ATest1OrgModule' -WriteToPipeline
        It "Should have the right values in each attribute" {
            $results.Name | Should BeExactly 'Test1'
            $results.OrganizationSpecificModules | Should Contain 'ATest1OrgModule'
        }
    }
}