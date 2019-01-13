    Function Test-TCPConnection
    {
        
    <#
            .SYNOPSIS
            Tests a TCP Connection to each port specified for each ComputerName specified. Useful on systems that don't have Test-NetConnection.

            .DESCRIPTION
            Tests a TCP Connection to each port specified for each ComputerName specified and,
            if specified, can return details for each requested ComputerName and port.

            .INPUTS
            A string or array of strings or any object with a ComputerName property.

            .OUTPUTS
            Boolean, or if ReturnDetail is specified PSCustomObject

            .EXAMPLE
            $ComputerObject = [pscustomobject]@{ComputerName = 'LocalHost'}
            $computerObject | Test-TCPConnection -port 80,5985,25,443

            True
            True
            False
            False

            .EXAMPLE
            'localhost','relayer.contoso.com' | Test-TCPConnection -port 25 -ReturnDetail

            ComputerName        Port Connected
            ------------        ---- ---------
            localhost             25     False
            relayer.contoso.com   25     False

            .EXAMPLE
            Test-TCPConnection -ComputerName 'smtp.office365.com' -port 443,25,80,587,5985 -returnDetail

            ComputerName       Port Connected
            ------------       ---- ---------
            smtp.office365.com  443      True
            smtp.office365.com   25      True
            smtp.office365.com   80      True
            smtp.office365.com  587      True
            smtp.office365.com 5985     False

            .EXAMPLE
            $testobject = [pscustomobject]@{computername = '10.10.101.55';port = 5985,25}
            $testobject | Test-TCPConnection -ReturnDetail

            ComputerName Port Connected
            ------------ ---- ---------
            10.10.101.55 5985      True
            10.10.101.55   25     False
        #>
    [cmdletbinding(DefaultParameterSetName = 'Boolean')]
    [OutputType([bool], ParameterSetName = "Boolean")]
    [OutputType([pscustomobject], ParameterSetName = "ReturnDetail")]
    param
    (
        # Specify one or more ComputerNames, IP Addresses, or FQDNs to test.
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 1)]
        [string[]]$ComputerName
        ,
        # Specify one or more TCP Ports to test.
        [parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 2)]
        [int[]]$Port
        ,
        # Specify the timeout in milliseconds.  500 is the default.
        [parameter(Position = 3)]
        [int]$Timeout = 500
        ,
        # Include if you would like object output including ComputerName, Port, and Connected [bool] properties.
        [parameter(ParameterSetName = 'ReturnDetail', Position = 4)]
        [switch]$ReturnDetail
    )
    process
    {
        foreach ($CN in $ComputerName)
        {
            foreach ($p in $Port)
            {
                $tcpClient = New-Object System.Net.Sockets.TCPClient
                try
                {
                    $ErrorActionPreference = 'Stop'
                    $null = $tcpClient.ConnectAsync($CN, $p)
                    Start-Sleep -Milliseconds $Timeout
                    $ErrorActionPreference = 'Continue'
                }
                catch
                {
                    $ErrorActionPreference = 'Continue'
                    Write-Verbose -message $_.tostring()
                }
                if ($ReturnDetail -eq $true)
                {
                    [pscustomobject]@{
                        ComputerName = $CN
                        Port         = $p
                        Connected    = $tcpClient.Connected
                    }
                }
                else
                {
                    $tcpClient.Connected
                }
                $tcpClient.close()
            }
        }
    }

    }

