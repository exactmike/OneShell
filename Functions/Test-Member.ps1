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