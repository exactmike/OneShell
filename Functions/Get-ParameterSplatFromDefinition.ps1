    Function Get-ParameterSplatFromDefinition
    {
        
    [cmdletbinding()]
    param(
        [parameter(Mandatory,ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [psobject[]]$ParameterDefinition
        ,
        [parameter()]
        [ValidateSet('Continue','Ignore','Inquire','SilentlyContinue','Stop','Suspend')]
        [string]$ValueForErrorAction
        ,
        [parameter()]
        [ValidateSet('Continue','Ignore','Inquire','SilentlyContinue','Stop','Suspend')]
        [string]$ValueForWarningAction
    )
    Begin
    {
        $ParametersForSplatting = @{}
        if ($PSBoundParameters.ContainsKey('ValueForErrorAction'))
        {
            $ParametersForSplatting.ErrorAction = $ValueForErrorAction
        }
        if ($PSBoundParameters.ContainsKey('ValueForWarningAction'))
        {
            $ParametersForSplatting.WarningAction = $ValueForWarningAction
        }
    }
    Process
    {
        foreach ($pd in $ParameterDefinition)
        {
            $value = $(
                switch ($pd.ValueType)
                {
                    'Static'
                    {$pd.Value}
                    'ScriptBlock'
                    {
                        $ValueGeneratingScriptBlock = [scriptblock]::Create($pd.Value)
                        &$ValueGeneratingScriptBlock
                    }
                }
            )
            $ParametersForSplatting.$($pd.name) = $value
        }
    }
    End
    {
        $ParametersForSplatting
    }

    }

