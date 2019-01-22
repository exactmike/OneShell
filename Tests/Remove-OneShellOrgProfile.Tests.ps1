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
