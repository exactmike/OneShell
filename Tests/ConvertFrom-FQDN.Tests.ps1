$CommandName = $MyInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
. Join-Path (Join-Path $PSScriptRoot 'Functions') $($CommandName + '.ps1')


Describe "$CommandName Unit Tests" -Tag 'UnitTests' {
    Context "Validate parameters" {
        $paramCount = 1
        $defaultParamCount = 11
        [object[]]$params = (Get-ChildItem Function:\ConvertFrom-FQDN).Parameters.Keys
        $knownParameters = @('FQDN')
        It "Should contain our specific parameters" {
            ( @(Compare-Object -ReferenceObject $knownParameters -DifferenceObject $params -IncludeEqual | Where-Object SideIndicator -eq "==").Count ) | Should Be $paramCount
        }
        It "Should only contain $paramCount parameters" {
            $params.Count - $defaultParamCount | Should Be $paramCount
        }
    }
}

Describe "$CommandName Integration Tests" -Tags "IntegrationTests" {
    Context "Command actually works with single value specified via parameter" {
        $results = ConvertFrom-FQDN -FQDN 'pester.contoso.com'
        It "Should be the right string" {
            $results | Should Be 'DC=pester,DC=contoso,DC=com'
        }
    }
    Context "Command actually works with multiple values specified via parameter" {
        $results = ConvertFrom-FQDN -FQDN 'pester.contoso.com','tester.contoso.com'
        It "Should be the right strings" {
            $results[0] | Should Be 'DC=pester,DC=contoso,DC=com'
            $results[1] | Should Be 'DC=tester,DC=contoso,DC=com'
        }
    }
    Context "Command actually works with pipeline byValue" {
        $results =  'pester.contoso.com','tester.contoso.com' | ConvertFrom-FQDN
        It "Should be the right strings" {
            $results[0] | Should Be 'DC=pester,DC=contoso,DC=com'
            $results[1] | Should Be 'DC=tester,DC=contoso,DC=com'
        }
    }
    Context "Command actually works with pipeline byPropertyName" {
        $results = [PSCustomObject]@{FQDN = 'pester.contoso.com'},[PSCustomObject]@{FQDN = 'tester.contoso.com'} | ConvertFrom-FQDN
        It "Should be the right strings" {
            $results[0] | Should Be 'DC=pester,DC=contoso,DC=com'
            $results[1] | Should Be 'DC=tester,DC=contoso,DC=com'
        }
    }
}