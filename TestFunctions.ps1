function Test-Member
{
    <#
            .ForwardHelpTargetName Get-Member
            .ForwardHelpCategory Cmdlet
        #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [psobject]
        $InputObject,

        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name,

        [Alias('Type')]
        [Management.Automation.PSMemberTypes]
        $MemberType,

        [Management.Automation.PSMemberViewTypes]
        $View,

        [Switch]
        $Static,

        [Switch]
        $Force
    )#end param
    begin
    {
        try
        {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Get-Member', [Management.Automation.CommandTypes]::Cmdlet)
            #PSScriptAnalyzer 1.16.1 mistakenly says "The variable 'members' is assigned but never used." about the following line.
            $scriptCmd = {& $wrappedCmd @PSBoundParameters | ForEach-Object -Begin {$members = @()} -Process {$members += $_} -End {$members.Count -ne 0}}
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)
        }
        catch
        {
            throw
        }
    }#end begin
    process
    {
        try
        {
            $steppablePipeline.Process($_)
        }
        catch
        {
            throw
        }
    }#end process
    end
    {
        try
        {
            $steppablePipeline.End()
        }
        catch
        {
            throw
        }
    }#end end
}
#end function Test-Member
function Test-IsNullOrWhiteSpace
{
    [cmdletbinding()]
    Param
    (
        $String
    )
    [string]::IsNullOrWhiteSpace($String)
}
#end function Test-IsNullorWhiteSpace
function Test-IsNotNullOrWhiteSpace
{
    [cmdletbinding()]
    Param(
        $String
    )
    [string]::IsNullOrWhiteSpace($String) -eq $false
}
#end function Test-IsNotNullOrWhiteSpace
function Test-IP
{
    #https://gallery.technet.microsoft.com/scriptcenter/A-short-tip-to-validate-IP-4f039260
    param
    (
        [Parameter(Mandatory)]
        [ValidateScript( {$_ -match [IPAddress]$_})]
        [String]$ip
    )
    $ip
}
#end function Test-IP
Function Test-DirectoryPath
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [string]$path
    )
    if (Test-Path -Path $path -PathType Container)
    {
        $item = Get-Item -Path $path
        if ($item.GetType().fullname -eq 'System.IO.DirectoryInfo')
        {$true}
        else
        {$false}
    }
    else
    {$false}
}
#end function
function Test-IsWriteableDirectory
{
    #Credits to the following:
    #http://poshcode.org/2236
    #http://stackoverflow.com/questions/9735449/how-to-verify-whether-the-share-has-write-access
    [CmdletBinding()]
    param
    (
        [parameter()]
        [ValidateScript(
            {
                $IsContainer = Test-Path -Path ($_) -PathType Container
                if ($IsContainer)
                {
                    $Item = Get-Item -Path $_
                    if ($item.PsProvider.Name -eq 'FileSystem') {$true}
                    else {$false}
                }
                else {$false}
            }
        )]
        [string]$Path
    )
    try
    {
        $testPath = Join-Path -Path $Path -ChildPath ([IO.Path]::GetRandomFileName())
        New-Item -Path $testPath -ItemType File -ErrorAction Stop > $null
        $true
    }
    catch
    {
        $false
    }
    finally
    {
        Remove-Item -Path $testPath -ErrorAction SilentlyContinue
    }
}
#end function Test-IsWriteableDirectory
function Test-CurrentPrincipalIsAdmin
{
    $currentPrincipal = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent())
    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
}
#end function Test-CurrentPrincipalIsAdmin
Function Test-ForInstalledModule
{
    Param
    (
        [parameter(Mandatory = $True)]
        [string]$Name
    )
    If
    (
        (Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue) `
            -or (Get-PSSnapin -Name $Name -ErrorAction SilentlyContinue) `
            -or (Get-PSSnapin -Name $Name -Registered -ErrorAction SilentlyContinue)
    )
    {$True}
    Else
    {$False}
}
#end function Test-ForInstalledModule
Function Test-ForImportedModule
{
    Param(
        [parameter(Mandatory = $True)]
        [string]$Name
    )
    If
    (
        (Get-Module -Name $Name -ErrorAction SilentlyContinue) `
            -or (Get-PSSnapin -Name $Name -Registered -ErrorAction SilentlyContinue)
    )
    {$True}
    Else
    {$False}
}
#end function Test-ForImportedModule
Function Test-CommandIsPresent
{
    Param ([string]$command)
    Try {if (Get-Command -Name $command -ErrorAction Stop) {$true}}
    Catch {$false}
}
#end function Test-CommandIsPresent
Function Test-EmailAddress
{
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory, ValueFromPipeline)]
        [string[]]$EmailAddress
    )
    process
    {
        foreach ($ea in $EmailAddress)
        {
            #Regex borrowed from: http://www.regular-expressions.info/email.html
            $ea -imatch '^(?=[A-Z0-9][A-Z0-9@._%+-]{5,253}$)[A-Z0-9._%+-]{1,64}@(?:(?=[A-Z0-9-]{1,63}\.)[A-Z0-9]+(?:-[A-Z0-9]+)*\.){1,8}[A-Z]{2,63}$'
        }
    }
}
#end function Test-EmailAddress
function Test-TCPConnection
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
#End function Test-TCPConnection